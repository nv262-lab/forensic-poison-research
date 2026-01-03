# ====================
# AWS S3 + DynamoDB
# ====================
resource "aws_s3_bucket" "tf_state" {
  count  = var.create_aws && length(trimspace(var.tf_state_bucket)) > 0 ? 1 : 0
  bucket = var.tf_state_bucket

  tags = {
    ManagedBy = "terraform"
    Purpose   = "tf-state"
  }
}

resource "aws_s3_bucket_versioning" "tf_state" {
  count  = length(aws_s3_bucket.tf_state) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tf_state[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tf_state" {
  count  = length(aws_s3_bucket.tf_state) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tf_state[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  count  = length(aws_s3_bucket.tf_state) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tf_state[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "tf_state" {
  count  = length(aws_s3_bucket.tf_state) > 0 ? 1 : 0
  bucket = aws_s3_bucket.tf_state[0].id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_dynamodb_table" "tf_lock" {
  count        = var.create_aws && length(trimspace(var.tf_lock_table)) > 0 ? 1 : 0
  name         = var.tf_lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    ManagedBy = "terraform"
    Purpose   = "tf-lock"
  }
}

# ====================
# GCP GCS Bucket
# ====================
resource "google_storage_bucket" "tf_state" {
  count         = var.create_gcp && length(trimspace(var.gcs_bucket)) > 0 ? 1 : 0
  name          = var.gcs_bucket
  location      = var.gcp_region
  force_destroy = false

  versioning {
    enabled = true
  }

  uniform_bucket_level_access = true

  lifecycle_rule {
    condition {
      num_newer_versions = 3
    }
    action {
      type = "Delete"
    }
  }

  labels = {
    managed_by = "terraform"
    purpose    = "tf-state"
  }
}

# ====================
# Azure Storage Account + Container
# ====================
resource "azurerm_resource_group" "tf_state" {
  count    = var.create_azure && length(trimspace(var.azure_rg_name)) > 0 ? 1 : 0
  name     = var.azure_rg_name
  location = var.azure_location

  tags = {
    ManagedBy = "terraform"
    Purpose   = "tf-state"
  }
}

resource "azurerm_storage_account" "tf_state" {
  count                    = var.create_azure && length(trimspace(var.azure_storage_account)) > 0 ? 1 : 0
  name                     = var.azure_storage_account
  resource_group_name      = azurerm_resource_group.tf_state[0].name
  location                 = azurerm_resource_group.tf_state[0].location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  
  blob_properties {
    versioning_enabled = true
  }

  tags = {
    ManagedBy = "terraform"
    Purpose   = "tf-state"
  }
}

resource "azurerm_storage_container" "tf_state" {
  count                 = length(azurerm_storage_account.tf_state) > 0 ? 1 : 0
  name                  = var.azure_container_name
  storage_account_name  = azurerm_storage_account.tf_state[0].name
  container_access_type = "private"
}
