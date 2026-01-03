resource "azurerm_resource_group" "rg" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags = {
    sandbox = "true"
  }
}

variable "prefix" {
  type = string
}

variable "location" {
  type = string
}
