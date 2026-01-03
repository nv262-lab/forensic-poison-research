terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = { source = "hashicorp/aws",     version = ">= 4.0" }
    google  = { source = "hashicorp/google",  version = ">= 4.0" }
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
  }
}

# AWS provider: credentials via env AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
provider "aws" {
  region = var.aws_region
  # Optionally set profile = var.aws_profile
}

# Google provider: prefer ADC or GOOGLE_CREDENTIALS env var
provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  # credentials can be supplied via GOOGLE_CREDENTIALS JSON or GOOGLE_APPLICATION_CREDENTIALS env var
}

# Azure provider: prefer service principal via AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID / ARM_SUBSCRIPTION_ID
provider "azurerm" {
  features {}
  # When running in CI, use the azure/login action to authenticate the az CLI, or set the ARM_* env vars.
}
