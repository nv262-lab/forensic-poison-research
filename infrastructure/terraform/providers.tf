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

  provider "azurerm" {
    features {}
    client_id       = var.azure_client_id
    client_secret   = var.azure_client_secret
    tenant_id       = var.azure_tenant_id
    subscription_id  = var.azure_subscription_id
  }

  provider "google" {
    project     = var.gcp_project
    region      = var.gcp_region
    credentials = var.gcp_service_account_key
  }
}
