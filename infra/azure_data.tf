# Shared Azure data sources. Underlying resources (RG, AKS, the tank-operator
# Postgres server, the infra-cosmos-serverless Cosmos account) live in other
# repos' state — this stack only reads them.

data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

data "azurerm_user_assigned_identity" "external_secrets" {
  name                = "infra-shared-identity"
  resource_group_name = data.azurerm_resource_group.main.name
}

# infra-bootstrap publishes the AKS OIDC issuer URL on its remote state.
# The MCP's federated identity credential needs it to bind the K8s SA token
# to the UAMI.
data "terraform_remote_state" "infra_bootstrap" {
  backend = "azurerm"

  config = {
    resource_group_name  = "infra"
    storage_account_name = "nelsontofu"
    container_name       = "tfstate"
    key                  = "infra-bootstrap.tfstate"
    use_oidc             = true
  }
}

locals {
  aks_oidc_issuer_url = data.terraform_remote_state.infra_bootstrap.outputs.aks_oidc_issuer_url
}

# Cosmos account this MCP server has data-plane access to. Account itself is
# provisioned in infra-bootstrap; we only grant our UAMI a role on it.
data "azurerm_cosmosdb_account" "infra_serverless" {
  name                = "infra-cosmos-serverless"
  resource_group_name = data.azurerm_resource_group.main.name
}
