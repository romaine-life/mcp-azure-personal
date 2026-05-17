provider "azurerm" {
  features {}
  use_oidc                        = true
  subscription_id                 = var.arm_subscription_id
  tenant_id                       = var.arm_tenant_id
  resource_provider_registrations = "none"
}
