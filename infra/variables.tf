variable "arm_subscription_id" {
  description = "Azure subscription ID. Set via TF_VAR_arm_subscription_id from the workflow."
  type        = string
}

variable "arm_tenant_id" {
  description = "Entra tenant ID. Set via TF_VAR_arm_tenant_id from the workflow."
  type        = string
}

variable "key_vault_name" {
  description = "Key Vault that receives the UAMI client ID secret for ESO sync."
  type        = string
  default     = "romaine-kv"
}

variable "key_vault_resource_group" {
  description = "Resource group containing key_vault_name."
  type        = string
  default     = "infra"
}

variable "resource_group_name" {
  description = "Resource group where the UAMI lives. Matches tank-operator's convention."
  type        = string
  default     = "infra"
}

variable "tank_operator_postgres_server_name" {
  description = "Name of the tank-operator Postgres Flexible Server. The MCP's UAMI is registered as an AAD admin so the pg_query tool can read tank-operator's session registry."
  type        = string
  default     = "tank-operator-db"
}

variable "tank_operator_postgres_resource_group" {
  description = "Resource group of the tank-operator Postgres server."
  type        = string
  default     = "infra"
}
