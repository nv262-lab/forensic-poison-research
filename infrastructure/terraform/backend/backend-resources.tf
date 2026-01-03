terraform {
  required_version = ">= 1.3.0"

  required_providers {
    aws     = { source = "hashicorp/aws",     version = ">= 4.0" }
    google  = { source = "hashicorp/google",  version = ">= 4.0" }
    azurerm = { source = "hashicorp/azurerm", version = ">= 3.0" }
    random  = { source = "hashicorp/random",  version = ">= 3.0" }
  }
}

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

# small random suffix to avoid collisions on repeated CI runs when names not provided
resource "random_id" "suffix" {
  count       = 1
  byte_length = 3
}

locals {
  suffix = length(random_id.suffix) > 0 ? random_id.suffix[0].hex : "manual"

  # final names: prefer provided var, else generate using suffix and region hints
  final_tf_state_bucket = length(trimspace(var.tf_state_bucket)) > 0 ? var.tf_state_bucket : "tf-state-${local.suffix}-${substr(var.aws_region,0,6)}"
  final_tf_lock_table   = length(trimspace(var.tf_lock_table)) > 0 ? var.tf_lock_table : "tf-lock-${local.suffix}"
  final_gcs_bucket      = length(trimspace(var.gcs_bucket)) > 0 ? var.gcs_bucket : "tf-state-${local.suffix}-${substr(var.gcp_region,0,6)}"
  final_azure_rg        = length(trimspace(var.azure_rg_name)) > 0 ? var.azure_rg_name : "tf-backend-rg-${local.suffix}"
  # storage account names must be lowercase and 3-24 chars, letters and numbers only
  generated_azure_storage = lower(replace("tfstate${local.suffix}", "/[^a-z0-9]/", ""))
  final_azure_storage   = length(trimspace(var.azure_storage_account)) > 0 ? var.azure_storage_account : local.generated_azure_storage
}

# --------------------
# AWS: S3 bucket + DynamoDB table for locking
# --------------------
resource "aws_s3_bucket" "tf_state" {
  count  = var.create_aws ? 1 : 0
  bucket = local.final_tf_state_bucket

  versioning {
    enabled = true
  }

  force_destroy = true

  lifecycle_rule {
    id      = "expire-old-versions"
    enabled = true
    noncurrent_version_expiration {
      days = 90
    }
  }

  tags = {
    ManagedBy = "terraform"
    Purpose   = "tf-state"
    Cloud     = "aws"
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  count  = var.create_aws ? 1 : 0
  bucket = aws_s3_bucket.tf_state[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "tf_state_acl" {
  count  = var.create_aws ? 1 : 0
  bucket = aws_s3_bucket.tf_state[0].id
  acl    = "private"
}

resource "aws_dynamodb_table" "tf_lock" {
  count        = var.create_aws ? 1 : 0
  name         = local.final_tf_lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    ManagedBy = "terraform"
    Purpose   = "tf-lock"
    Cloud     = "aws"
  }
}

# --------------------
# GCP: GCS bucket for state
# --------------------
resource "google_storage_bucket" "tf_state" {
  count         = var.create_gcp ? 1 : 0
  name          = local.final_gcs_bucket
  location      = var.gcp_region
  force_destroy = false

  uniform_bucket_level_access = true

  labels = {
    managed_by = "terraform"
    purpose    = "tf-state"
    cloud      = "gcp"
  }
}

# --------------------
# Azure: Storage account + container for state
# --------------------
resource "azurerm_resource_group" "backend" {
  count    = var.create_azure ? 1 : 0
  name     = local.final_azure_rg
  location = var.azure_location
  tags = {
    managed_by = "terraform"
    purpose    = "tf-backend"
    cloud      = "azure"
  }
}

resource "azurerm_storage_account" "tfstate" {
  count               = var.create_azure ? 1 : 0
  name                = local.final_azure_storage
  resource_group_name = azurerm_resource_group.backend[0].name
  location            = azurerm_resource_group.backend[0].location
  account_tier        = "Standard"
  account_replication_type = "LRS"

  enable_https_traffic_only = true

  tags = {
    managed_by = "terraform"
    purpose    = "tf-state"
  }
}

resource "azurerm_storage_container" "tfstate" {
  count                = var.create_azure ? 1 : 0
  name                 = var.azure_container_name
  storage_account_name = azurerm_storage_account.tfstate[0].name
  container_access_type = "private"
}

# --------------------
# Outputs
# --------------------
output "aws_tf_state_bucket" {
  value       = var.create_aws ? aws_s3_bucket.tf_state[0].bucket : ""
  description = "AWS S3 bucket name for Terraform state (empty if not created)"
}

output "aws_tf_lock_table" {
  value       = var.create_aws ? aws_dynamodb_table.tf_lock[0].name : ""
  description = "AWS DynamoDB table name for Terraform locking (empty if not created)"
}

output "gcp_gcs_bucket" {
  value       = var.create_gcp ? google_storage_bucket.tf_state[0].name : ""
  description = "GCS bucket name for Terraform state (empty if not created)"
}

output "azure_storage_account" {
  value       = var.create_azure ? azurerm_storage_account.tfstate[0].name : ""
  description = "Azure storage account name (empty if not created)"
}

output "azure_container_name" {
  value       = var.create_azure ? azurerm_storage_container.tfstate[0].name : ""
  description = "Azure storage container name (empty if not created)"
}
