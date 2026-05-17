terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

# ============================================================================
# Managed Identity — the MCP server's Azure principal
# ============================================================================
# All upstream Azure calls happen as this UAMI. DefaultAzureCredential picks
# up the federated workload-identity token at runtime via the env vars +
# token file the workload-identity webhook injects. Role assignments below
# are exactly what this MCP server can do — no per-user OBO, no client
# credential dependency.

resource "azurerm_user_assigned_identity" "mcp" {
  name                = "mcp-${var.name}-identity"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
}

resource "azurerm_federated_identity_credential" "pod" {
  name                = "aks-mcp-${var.name}"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.mcp.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.aks_namespace}:${var.aks_service_account_name}"
}

resource "azurerm_role_assignment" "granted" {
  for_each = var.role_assignments

  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = azurerm_user_assigned_identity.mcp.principal_id
}

# Published so the Helm chart can sync it via ExternalSecret into env vars
# on the pod (AZURE_CLIENT_ID). Plain Helm values.yaml can't reference
# tofu state directly, and the workload-identity webhook needs the client
# ID either as a SA annotation or as the env var — KV → ESO → envFrom is
# the existing pattern in this repo.
resource "azurerm_key_vault_secret" "mi_client_id" {
  name         = "mcp-${var.name}-mi-client-id"
  value        = azurerm_user_assigned_identity.mcp.client_id
  key_vault_id = var.key_vault_id
}
