terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = { source = "hashicorp/aws",     version = ">= 4.0" }
    google  = { source = "hashicorp/google",  version = ">= 4.0" }
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

# AWS provider configuration used by backend workspace.
provider "aws" {
  region = var.aws_region
  # credentials from environment (CI or local)
}

# Google provider for backend workspace
provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  # credentials via GOOGLE_CREDENTIALS or ADC
}

# Azure provider for backend workspace
provider "azurerm" {
  features {}
  # authentication via environment or azure/login in CI
}
