variable "create_aws" { type = bool, default = true }
variable "create_gcp" { type = bool, default = false }
variable "create_azure" { type = bool, default = false }

# AWS
variable "aws_region" { type = string, default = "us-east-1" }
variable "tf_state_bucket" { type = string, default = "" }
variable "tf_lock_table" { type = string, default = "" }

# GCP
variable "gcp_project" { type = string, default = "" }
variable "gcp_region"  { type = string, default = "us" }
variable "gcs_bucket"  { type = string, default = "" }

# Azure
variable "azure_rg_name"        { type = string, default = "" }
variable "azure_location"       { type = string, default = "eastus" }
variable "azure_storage_account" { type = string, default = "" }
variable "azure_container_name"  { type = string, default = "tfstate" }
