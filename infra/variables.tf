variable "key_vault_name" {
  description = "MCP Azure Personal-owned Key Vault for runtime configuration."
  type        = string
  default     = "ng6-mcp-azure-personal"
}

variable "resource_group_name" {
  description = "Resource group where the UAMI lives. Matches tank-operator's convention."
  type        = string
  default     = "infra"
}

variable "tank_operator_postgres_server_name" {
  description = "Name of the tank-operator Postgres Flexible Server. The MCP's UAMI is registered as an AAD admin so the Postgres MCP tools can read and explicitly repair tank-operator's session registry."
  type        = string
  default     = "tank-operator-db"
}

variable "tank_operator_postgres_resource_group" {
  description = "Resource group of the tank-operator Postgres server."
  type        = string
  default     = "infra"
}

variable "glimmung_postgres_server_name" {
  description = "Name of the glimmung Postgres Flexible Server. The MCP's UAMI is registered as an AAD admin so the Postgres MCP tools can read and explicitly repair glimmung's durable store."
  type        = string
  default     = "glimmung-pg"
}

variable "glimmung_postgres_resource_group" {
  description = "Resource group of the glimmung Postgres server. Per nelsong6/glimmung/tofu/identity.tf, glimmung-owned resources live in the `glimmung` resource group, not the shared `infra` RG."
  type        = string
  default     = "glimmung"
}

variable "tank_aks_cluster_id" {
  description = "Full ARM ID of the AKS cluster the run_aks_command tool targets. This cluster lives in a different subscription from the rest of this stack, so it can't be derived from data.azurerm_client_config.current — the scope has to be passed in explicitly."
  type        = string
  default     = "/subscriptions/606a1ca1-5833-4d21-8937-d0fcd97cd0a0/resourceGroups/infra/providers/Microsoft.ContainerService/managedClusters/infra-aks"
}

variable "cluster_subscription_id" {
  description = "Azure subscription ID of the AKS cluster. Used to configure the azurerm.cluster provider alias for cross-sub role assignments on cluster-sub resources (Reader, Cost Management Reader for the UAMI). Matches the value infra-bootstrap publishes as CLUSTER_SUBSCRIPTION_ID on this repo and the cluster's sub in tank_aks_cluster_id above."
  type        = string
  default     = "606a1ca1-5833-4d21-8937-d0fcd97cd0a0"
}
