variable "prefix" { type = string }
resource "azurerm_resource_group" "rg" { name = "${var.prefix}-rg" location = "eastus" tags = { sandbox = "true" } }
output "resources" { value = { rg = azurerm_resource_group.rg.name } }
