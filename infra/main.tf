# ============================================================================
# mcp-azure-personal — Azure infrastructure
# ============================================================================
# Provisions the UAMI, federated credential, role assignments, and KV-published
# client ID for the mcp-azure-personal MCP server. The chart in ../chart/
# consumes the KV secret via ExternalSecret.
#
# Historical note: these resources were originally defined in
# nelsong6/tank-operator's infra/mcp.tf alongside other MCP servers. The
# companion tank-operator PR deletes them from that state (Azure destroys
# them); merging this PR's apply afterward creates them fresh here with the
# correct `aks_namespace = "mcp-azure-personal"`. Destroy-recreate rather
# than tofu-state-transfer because the existing FIC subject was stale anyway
# (built when the namespace was still "mcp-azure", never updated after the
# chart rename in #12), so workload identity was already broken — no live
# auth to preserve.
# ============================================================================

module "mcp_azure_personal" {
  source = "./mcp-server"

  name                     = "azure-personal"
  resource_group_name      = data.azurerm_resource_group.main.name
  resource_group_location  = data.azurerm_resource_group.main.location
  aks_oidc_issuer_url      = local.aks_oidc_issuer_url
  aks_namespace            = "mcp-azure-personal"
  aks_service_account_name = "mcp-azure-personal"

  role_assignments = {
    # Broad subscription control plane: the MCP server's ARM tools
    # (arm_list_resources, arm_get_resource, run_aks_command, delete_*,
    # uami_upsert_federated_credential, etc.) all run against ARM. Anyone
    # authenticated to this MCP inherits this — the destructive surface is
    # narrowed by the tools themselves (exact-name confirmations on deletes,
    # dry_run defaults on writes).
    "subscription-operator" = {
      scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
      role_definition_name = "Contributor"
    }
  }
}

# ----------------------------------------------------------------------------
# Key Vault data-plane access for MCP secret tools
# ----------------------------------------------------------------------------
# Subscription Contributor covers Key Vault control-plane reads/writes, but not
# secret values. Grant Secrets Officer at subscription scope so the MCP can read,
# set, and dry-run-delete secrets in app-owned vaults.
resource "azurerm_role_assignment" "uami_workload_sub_keyvault_secrets_officer" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = module.mcp_azure_personal.managed_identity_principal_id
}

resource "azurerm_role_assignment" "uami_cluster_sub_keyvault_secrets_officer" {
  provider             = azurerm.cluster
  scope                = "/subscriptions/${var.cluster_subscription_id}"
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = module.mcp_azure_personal.managed_identity_principal_id
}

# ----------------------------------------------------------------------------
# Cosmos data-plane access (cosmos_query_items et al.)
# ----------------------------------------------------------------------------
# Cosmos SQL API uses its own RBAC system, not ARM RBAC — even Reader at
# subscription scope doesn't grant data-plane reads. Grant account-scope
# Built-in Data Contributor on the Cosmos accounts the MCP needs.
resource "azurerm_cosmosdb_sql_role_assignment" "infra_serverless_contributor" {
  resource_group_name = data.azurerm_resource_group.main.name
  account_name        = data.azurerm_cosmosdb_account.infra_serverless.name
  role_definition_id  = "${data.azurerm_cosmosdb_account.infra_serverless.id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"
  principal_id        = module.mcp_azure_personal.managed_identity_principal_id
  scope               = data.azurerm_cosmosdb_account.infra_serverless.id
}

# ----------------------------------------------------------------------------
# tank-operator AKS runCommand access (run_aks_command tool)
# ----------------------------------------------------------------------------
# Cross-subscription grant. This UAMI lives in the workload subscription
# alongside the rest of the platform; the AKS cluster lives in a separate
# subscription ("romaine-life") and the "subscription-operator" Contributor
# above is scoped to data.azurerm_client_config.current.subscription_id, so
# it never reaches the cluster — hence the explicit scope here.
#
# Azure Kubernetes Service Contributor Role covers the AKS ARM actions
# these tools need:
#   Microsoft.ContainerService/managedClusters/runCommand/action
#   Microsoft.ContainerService/managedClusters/commandResults/read
#   Microsoft.ContainerService/managedClusters/agentPools/deleteMachines/action
#
# infra-aks has disableLocalAccounts=false and aadProfile=null, so
# runCommand falls through to the local admin kubeconfig path — no
# Kubernetes-side AAD role binding required beyond this ARM grant.
resource "azurerm_role_assignment" "tank_aks_runcommand" {
  scope                = var.tank_aks_cluster_id
  role_definition_name = "Azure Kubernetes Service Contributor Role"
  principal_id         = module.mcp_azure_personal.managed_identity_principal_id
}

# ----------------------------------------------------------------------------
# UAMI Cost Management Reader on workload sub; Reader + Cost Management
# Reader on cluster sub
# ----------------------------------------------------------------------------
# Cost Management Reader powers the Cost Analysis tool's
# Microsoft.CostManagement / Microsoft.Consumption actions — not included
# in Contributor (or Reader) at any scope, so it needs an explicit grant
# on both subs.
#
# Cluster sub also needs plain Reader because Contributor is workload-sub-
# scoped (see the role_assignments map above) and doesn't reach
# cluster-sub resources; the MCP's broad troubleshooting tools
# (arm_list_resources, arm_get_resource) would 403 on every cluster-sub
# query otherwise. Workload-sub Reader isn't needed — the existing
# subscription-Contributor grant already covers reads there.
#
# Migrated from nelsong6/infra-bootstrap/tofu/mcp-azure-personal.tf, which
# was deleted in infra-bootstrap#127 because its `data.azuread_service_
# principal` pinned a tombstoned UAMI client_id from a previous destroy-
# recreate cycle. App-specific grants belong here, not in infra-bootstrap;
# this version references the live UAMI via the module output so any
# future destroy-recreate within this stack auto-updates the principal_id.

resource "azurerm_role_assignment" "uami_workload_sub_cost_management_reader" {
  scope                = "/subscriptions/${data.azurerm_client_config.current.subscription_id}"
  role_definition_name = "Cost Management Reader"
  principal_id         = module.mcp_azure_personal.managed_identity_principal_id
}

resource "azurerm_role_assignment" "uami_cluster_sub_reader" {
  provider             = azurerm.cluster
  scope                = "/subscriptions/${var.cluster_subscription_id}"
  role_definition_name = "Reader"
  principal_id         = module.mcp_azure_personal.managed_identity_principal_id
}

resource "azurerm_role_assignment" "uami_cluster_sub_cost_management_reader" {
  provider             = azurerm.cluster
  scope                = "/subscriptions/${var.cluster_subscription_id}"
  role_definition_name = "Cost Management Reader"
  principal_id         = module.mcp_azure_personal.managed_identity_principal_id
}

# ----------------------------------------------------------------------------
# Postgres data-plane access (pg_query / pg_execute)
# ----------------------------------------------------------------------------
# Registers this MCP's UAMI as an Entra AD admin on the tank-operator Postgres
# Flexible Server so the Postgres MCP tools can authenticate with a workload-
# identity token. Mirrors the pattern tank-operator uses for its own
# orchestrator UAMI (infra/postgres.tf in tank-operator).
#
# Admin rather than a narrower SQL role is the deliberately simple choice:
# pg_query remains server-side read-only, and pg_execute is intentionally
# separate, host-allowlisted, dry-run-by-default, single-statement DML with
# affected-row caps and audit logging.
resource "azurerm_postgresql_flexible_server_active_directory_administrator" "tank_operator_db" {
  server_name         = var.tank_operator_postgres_server_name
  resource_group_name = var.tank_operator_postgres_resource_group
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = module.mcp_azure_personal.managed_identity_principal_id
  principal_name      = module.mcp_azure_personal.managed_identity_name
  principal_type      = "ServicePrincipal"
}

# Same shape as tank_operator_db above, against the glimmung-pg server
# provisioned in nelsong6/glimmung#565 (Stage 1 of the Cosmos -> Postgres
# migration documented in nelsong6/glimmung/docs/postgres-migration.md).
# Granted now so the Postgres MCP tools can inspect and, when explicitly
# requested through pg_execute, repair Glimmung control-plane state.
#
# The `cosmos_query_items` tool stays for the four remaining apps
# (ambience, kill-me, my-homepage, investing) still on the shared
# infra-cosmos-serverless account.
resource "azurerm_postgresql_flexible_server_active_directory_administrator" "glimmung_db" {
  server_name         = var.glimmung_postgres_server_name
  resource_group_name = var.glimmung_postgres_resource_group
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = module.mcp_azure_personal.managed_identity_principal_id
  principal_name      = module.mcp_azure_personal.managed_identity_name
  principal_type      = "ServicePrincipal"
}
