# Single place for shared variables to avoid duplicates

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

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "tf_state_bucket" {
  type    = string
  default = ""  # if empty, generated
}

variable "tf_lock_table" {
  type    = string
  default = ""  # if empty, generated
}

variable "gcp_project" {
  type    = string
  default = "indigo-splice-483118-h7"
}

variable "gcp_access_token" {
  type    = string
}

variable "gcp_region" {
  type    = string
  default = "us-central1"
}

variable "gcs_bucket" {
  type    = string
  default = ""  # if empty, generated
}

variable "azure_rg_name" {
  type    = string
  default = ""  # if empty, generated
}

variable "azure_location" {
  type    = string
  default = "eastus"
}

variable "azure_storage_account" {
  type    = string
  default = ""  # if empty, generated
}

variable "azure_container_name" {
  type    = string
  default = "tfstate"
}

variable "azure_subscription_id" {
  type    = string
  default = ""
}

variable "azure_client_id" {
  type    = string
  default = ""
}

variable "azure_client_secret" {
  type    = string
  default = ""
}

variable "azprefix" {
  type    = string
  default = "rag-forensics"
}

variable "azure_tenant_id" {
  type    = string
  default = ""
}
