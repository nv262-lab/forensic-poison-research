# Toggle cloud provider resource creation
variable "create_aws" {
  type    = bool
  default = true
}

variable "create_gcp" {
  type    = bool
  default = false
}

variable "create_azure" {
  type    = bool
  default = false
}

# AWS Configuration
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "tf_state_bucket" {
  type    = string
  default = ""
  description = "S3 bucket name for Terraform state"
}

variable "tf_lock_table" {
  type    = string
  default = ""
  description = "DynamoDB table name for state locking"
}

# GCP Configuration
variable "gcp_project" {
  type    = string
  default = ""
  description = "GCP project ID"
}

variable "gcp_region" {
  type    = string
  default = "us"
  description = "GCS bucket location"
}

variable "gcs_bucket" {
  type    = string
  default = ""
  description = "GCS bucket name for Terraform state"
}

# Azure Configuration
variable "azure_rg_name" {
  type    = string
  default = ""
  description = "Azure resource group name"
}

variable "azure_location" {
  type    = string
  default = "eastus"
  description = "Azure region"
}

variable "azure_storage_account" {
  type    = string
  default = ""
  description = "Azure storage account name (must be globally unique, 3-24 chars, lowercase alphanumeric)"
}

variable "azure_container_name" {
  type    = string
  default = "tfstate"
  description = "Azure blob container name for Terraform state"
}
