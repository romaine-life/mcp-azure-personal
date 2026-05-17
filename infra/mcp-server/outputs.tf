output "managed_identity_client_id" {
  value       = azurerm_user_assigned_identity.mcp.client_id
  description = "Client ID of the MCP server's UAMI."
}

output "managed_identity_principal_id" {
  value       = azurerm_user_assigned_identity.mcp.principal_id
  description = "Principal ID of the MCP server's UAMI."
}

output "managed_identity_name" {
  value       = azurerm_user_assigned_identity.mcp.name
  description = "Display name of the MCP server's UAMI. Used as the Postgres role name for Entra-authenticated connections."
}
