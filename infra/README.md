# mcp-azure-personal infrastructure

Terraform that provisions this MCP server's Azure-side identity and
permissions:

| Resource | Purpose |
| --- | --- |
| `azurerm_user_assigned_identity.mcp` (in `mcp-server/`) | The UAMI everything else binds to. Display name is `mcp-azure-personal-identity` — also used as the Postgres role name for Entra-auth connections. |
| `azurerm_federated_identity_credential.pod` | Binds the K8s SA `mcp-azure-personal/mcp-azure` to the UAMI via the AKS OIDC issuer. |
| `azurerm_role_assignment.granted["subscription-operator"]` | Subscription-scope Contributor. The MCP's ARM tools call against this. |
| `azurerm_role_assignment.granted["romaine-kv-secrets-officer"]` | Data-plane Key Vault Secrets Officer on `romaine-kv`. |
| `azurerm_cosmosdb_sql_role_assignment.infra_serverless_contributor` | Cosmos data-plane Built-in Data Contributor on `infra-cosmos-serverless`. |
| `azurerm_key_vault_secret.mi_client_id` (in `mcp-server/`) | Publishes the UAMI's client ID so the chart's ExternalSecret can sync it into `AZURE_CLIENT_ID` on the pod. |
| `azurerm_postgresql_flexible_server_active_directory_administrator.tank_operator_db` | Registers the UAMI as an Entra AD admin on `tank-operator-db` so the `pg_query` tool can read the session registry. New in this PR. |

State is stored in `nelsontofu` blob container `tfstate` under key
`mcp-azure-personal.tfstate` (see `.github/workflows/tofu.yml`).

## Migration from tank-operator/infra

These resources used to be declared in `nelsong6/tank-operator/infra/mcp.tf`
inside the `mcp_azure_personal` module call. The migration moves them here
without disturbing the running Azure resources. Order matters:

1. **Apply this stack first**, importing the existing Azure resources into
   this state. The new `azurerm_postgresql_flexible_server_active_directory_administrator.tank_operator_db` is a genuinely new resource — everything else is an adoption.
2. **Then apply tank-operator's companion PR**, which uses Terraform 1.7+
   `removed { lifecycle.destroy = false }` blocks to forget the resources
   on its side without deleting them.

If you do (2) before (1), the resources are unmanaged. If you apply this
stack without importing first, Terraform tries to *create* the UAMI etc.
and Azure rejects with a name conflict. So the import is required.

### Import commands

The Terraform 1.5+ `import` block syntax is appealing but two of the
resources below have IDs we can't know without an `az` lookup (role-
assignment GUIDs, KV secret version). Easiest to run `terraform import`
explicitly once:

```bash
SUB=606a1ca1-5833-4d21-8937-d0fcd97cd0a0
UAMI_NAME=mcp-azure-personal-identity
RG=infra
UAMI_ID="/subscriptions/${SUB}/resourceGroups/${RG}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${UAMI_NAME}"
UAMI_PRINCIPAL_ID=$(az identity show --name "$UAMI_NAME" --resource-group "$RG" --query principalId -o tsv)
COSMOS_ID=$(az cosmosdb show --name infra-cosmos-serverless --resource-group "$RG" --query id -o tsv)
KV_ID=$(az keyvault show --name romaine-kv --query id -o tsv)

# 1. UAMI
tofu import module.mcp_azure_personal.azurerm_user_assigned_identity.mcp "$UAMI_ID"

# 2. Federated identity credential
tofu import module.mcp_azure_personal.azurerm_federated_identity_credential.pod \
  "${UAMI_ID}/federatedIdentityCredentials/aks-mcp-azure-personal"

# 3. Role assignments — look up the per-scope GUIDs
SUB_ROLE_ID=$(az role assignment list \
  --assignee "$UAMI_PRINCIPAL_ID" \
  --scope "/subscriptions/${SUB}" \
  --role Contributor \
  --query '[0].id' -o tsv)
tofu import 'module.mcp_azure_personal.azurerm_role_assignment.granted["subscription-operator"]' "$SUB_ROLE_ID"

KV_ROLE_ID=$(az role assignment list \
  --assignee "$UAMI_PRINCIPAL_ID" \
  --scope "$KV_ID" \
  --role "Key Vault Secrets Officer" \
  --query '[0].id' -o tsv)
tofu import 'module.mcp_azure_personal.azurerm_role_assignment.granted["romaine-kv-secrets-officer"]' "$KV_ROLE_ID"

# 4. Cosmos SQL role assignment (data-plane RBAC, separate from ARM)
COSMOS_RA_NAME=$(az cosmosdb sql role assignment list \
  --account-name infra-cosmos-serverless \
  --resource-group "$RG" \
  --query "[?principalId=='${UAMI_PRINCIPAL_ID}'] | [0].name" -o tsv)
tofu import azurerm_cosmosdb_sql_role_assignment.infra_serverless_contributor \
  "${COSMOS_ID}/sqlRoleAssignments/${COSMOS_RA_NAME}"

# 5. KV secret holding the UAMI client ID — needs the current version GUID
KV_SECRET_ID=$(az keyvault secret show \
  --vault-name romaine-kv \
  --name mcp-azure-personal-mi-client-id \
  --query id -o tsv)
tofu import module.mcp_azure_personal.azurerm_key_vault_secret.mi_client_id "$KV_SECRET_ID"
```

After importing, `tofu plan` should report **no changes** for those five
resources and **one resource to add** —
`azurerm_postgresql_flexible_server_active_directory_administrator.tank_operator_db`,
the new Postgres admin grant.

### Tank-operator companion PR

In `nelsong6/tank-operator/infra`, add `removed` blocks for everything
above, plus drop the module call from `mcp.tf`:

```hcl
removed {
  from = module.mcp_azure_personal
  lifecycle {
    destroy = false
  }
}

removed {
  from = azurerm_cosmosdb_sql_role_assignment.mcp_azure_personal_infra_serverless_contributor
  lifecycle {
    destroy = false
  }
}
```

Then delete the corresponding resource blocks from `mcp.tf`. The `removed`
blocks themselves stay until they've been applied once; they can be
deleted in a follow-up PR.

The `data.azurerm_cosmosdb_account.infra_serverless` data source in
`mcp.tf` can stay (other things may use it) or move with the resource —
moving it doesn't touch real Azure state.
