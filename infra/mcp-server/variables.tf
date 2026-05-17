variable "name" {
  description = "Short name of the MCP server (e.g. 'azure-personal'). Used for resource naming."
  type        = string
}

variable "resource_group_name" {
  type = string
}

variable "resource_group_location" {
  type = string
}

variable "key_vault_id" {
  description = "Key Vault that receives the UAMI client ID secret for ESO sync."
  type        = string
}

variable "aks_oidc_issuer_url" {
  description = "OIDC issuer URL of the AKS cluster — federates the pod SA to this server's UAMI."
  type        = string
}

variable "aks_namespace" {
  type = string
}

variable "aks_service_account_name" {
  type = string
}

variable "role_assignments" {
  description = "Azure RBAC granted to the MCP server's UAMI. Anyone authenticated to this server inherits these permissions — keep narrow."
  type = map(object({
    scope                = string
    role_definition_name = string
  }))
  default = {}
}
