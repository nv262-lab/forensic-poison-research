terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = { source = "hashicorp/aws",     version = ">= 4.0" }
    google  = { source = "hashicorp/google",  version = ">= 4.0" }
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
    null    = { source = "hashicorp/null",    version = ">= 3.0" }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "gcp_project" {
  type    = string
  default = ""
}

variable "gcp_region" {
  type    = string
  default = "us-central1"
}

variable "azure_subscription_id" {
  type    = string
  default = ""
}

variable "azure_tenant_id" {
  type    = string
  default = ""
}

provider "aws" {
  region = var.aws_region
}

# Ensure gcp_project is provided (workflow should export TF_VAR_gcp_project)
locals {
  gcp_project_provided = length(trimspace(var.gcp_project)) > 0
}

resource "null_resource" "require_gcp_project" {
  count = local.gcp_project_provided ? 0 : 1

  provisioner "local-exec" {
    command = "echo 'ERROR: TF var gcp_project must be provided (set TF_VAR_gcp_project in workflow)'; exit 1"
  }
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  # credentials: set GOOGLE_APPLICATION_CREDENTIALS or GOOGLE_CREDENTIALS in your workflow env
}

provider "azurerm" {
  features {}

  # Prefer explicit ARM_* env vars (ARM_SUBSCRIPTION_ID etc.) or set variables below.
  subscription_id = var.azure_subscription_id != "" ? var.azure_subscription_id : null
  tenant_id       = var.azure_tenant_id != "" ? var.azure_tenant_id : null
}
