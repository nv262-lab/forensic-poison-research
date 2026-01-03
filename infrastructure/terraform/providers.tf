terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = { source = "hashicorp/aws",     version = ">= 4.0" }
    google  = { source = "hashicorp/google",  version = ">= 4.0" }
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
    random  = { source = "hashicorp/random",  version = ">= 3.0" }
    null    = { source = "hashicorp/null",    version = ">= 3.0" }
  }
}

# ----------------
# Shared variables (declare once here)
# ----------------
variable "create_aws"   { type = bool, default = true }
variable "create_gcp"   { type = bool, default = false }
variable "create_azure" { type = bool, default = false }

variable "aws_region"       { type = string, default = "us-east-1" }
variable "tf_state_bucket"  { type = string, default = "" }    # if empty, generated
variable "tf_lock_table"    { type = string, default = "" }    # if empty, generated

variable "gcp_project" { type = string, default = "" }
variable "gcp_region"  { type = string, default = "us-central1" }
variable "gcs_bucket"  { type = string, default = "" }        # if empty, generated

variable "azure_rg_name"         { type = string, default = "" } # if empty, generated
variable "azure_location"        { type = string, default = "eastus" }
variable "azure_storage_account" { type = string, default = "" } # if empty, generated
variable "azure_container_name"  { type = string, default = "tfstate" }

variable "azure_subscription_id" { type = string, default = "" }
variable "azure_tenant_id"       { type = string, default = "" }

# ----------------
# Providers
# ----------------
provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

provider "azurerm" {
  features {}
  subscription_id = var.azure_subscription_id
  tenant_id       = var.azure_tenant_id
}
