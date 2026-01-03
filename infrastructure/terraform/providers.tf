terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
    google  = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
    random  = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    null    = {
      source  = "hashicorp/null"
      version = ">= 3.0"
    }
  }
}

# Define the provider blocks outside the terraform block
provider "aws" {
  region = var.aws_region
}

provider "google" {
  project      = var.gcp_project
  region       = var.gcp_region
  access_token = var.gcp_access_token
}

provider "azurerm" {
  features {}
  client_id       = var.azure_client_id
  client_secret   = var.azure_client_secret
  tenant_id       = var.azure_tenant_id
  subscription_id  = var.azure_subscription_id
}
