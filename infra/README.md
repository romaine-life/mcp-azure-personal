# mcp-azure-personal infrastructure

Terraform that provisions this MCP server's Azure-side identity and
permissions:

| Resource | Purpose |
| --- | --- |
| `azurerm_user_assigned_identity.mcp` (in `mcp-server/`) | The UAMI everything else binds to. Display name is `mcp-azure-personal-identity` — also used as the Postgres role name for Entra-auth connections. |
| `azurerm_federated_identity_credential.pod` | Binds the K8s SA `mcp-azure-personal/mcp-azure-personal` to the UAMI via the AKS OIDC issuer. |
| `azurerm_role_assignment.granted["subscription-operator"]` | Subscription-scope Contributor. The MCP's ARM tools call against this. |
| `azurerm_role_assignment.uami_workload_sub_keyvault_secrets_officer` | Subscription-scope Key Vault Secrets Officer on the workload subscription. |
| `azurerm_role_assignment.uami_cluster_sub_keyvault_secrets_officer` | Subscription-scope Key Vault Secrets Officer on the AKS cluster subscription. |
| `azurerm_cosmosdb_sql_role_assignment.infra_serverless_contributor` | Cosmos data-plane Built-in Data Contributor on `infra-cosmos-serverless`. |
| `azurerm_key_vault_secret.mi_client_id` (in `mcp-server/`) | Publishes the UAMI's client ID so the chart's ExternalSecret can sync it into `AZURE_CLIENT_ID` on the pod. |
| `azurerm_postgresql_flexible_server_active_directory_administrator.tank_operator_db` | Registers the UAMI as an Entra AD admin on `tank-operator-db` so the `pg_query` tool can read the session registry. New in this PR. |

State is stored in `nelsontofu` blob container `tfstate` under key
`mcp-azure-personal.tfstate` (see `.github/workflows/tofu.yml`).

## Migration from tank-operator/infra

These resources used to be declared in `nelsong6/tank-operator/infra/mcp.tf`
inside the `mcp_azure_personal` module call. The existing FIC subject was
stale anyway (built against the pre-rename namespace `mcp-azure`), so
workload identity was broken — there's no live auth to preserve through
the move. Ownership migrates via destroy-recreate:

1. **Merge [nelsong6/tank-operator#508](https://github.com/nelsong6/tank-operator/pull/508) first.**
   Its CI runs `tofu apply`; tofu destroys the UAMI, FIC, both ARM role
   assignments, the KV secret holding the UAMI client ID, and the Cosmos
   data-plane role assignment in Azure.
2. **Then merge this PR.** Its CI runs `tofu apply` against an empty
   state for this stack. Tofu creates the same resources fresh — but
   this time with `aks_namespace = "mcp-azure-personal"`, so the FIC
   subject matches the renamed chart namespace and workload identity
   works.

Brief window (one CI apply) where the MCP server has no Azure-side
identity — already the case (workload identity has been broken since the
chart namespace rename in #12), so no functional regression.
