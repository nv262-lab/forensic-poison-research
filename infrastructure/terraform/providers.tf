terraform {
  required_version = ">= 1.5.7, < 2.0.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "4.62.0" }
    azurerm = { source = "hashicorp/azurerm", version = "3.75.0" }
    google = { source = "hashicorp/google", version = "4.81.0" }
    random = { source = "hashicorp/random", version = "3.5.1" }
  }
}
provider "aws" { region = var.aws_region }
provider "azurerm" { features = {} subscription_id = var.azure_subscription_id }
provider "google" { project = var.gcp_project region = var.gcp_region }
