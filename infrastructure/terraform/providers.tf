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
