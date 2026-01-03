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

# Ensure gcp_project is provided (wor…
[9:48 PM, 1/2/2026] Suji: terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = { source = "hashicorp/aws",     version = ">= 4.0" }
    google  = { source = "hashicorp/google",  version = ">= 4.0" }
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
    random  = { source = "hashicorp/random",  version = ">= 3.0" }
  }
}

variable "aws_region" { type = string, default = "us-east-1" }
variable "gcp_project" { type = string, default = "" }
variable "gcp_region"  { type = string, default = "us-central1" }
variable "azure_subscription_id" { type = string, default = "" }
variable "azure_tenant_id"       { type = string, default = "" }

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
