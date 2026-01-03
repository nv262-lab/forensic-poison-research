# ====================
# AWS Outputs
# ====================
output "aws_s3_bucket_name" {
  value       = length(aws_s3_bucket.tf_state) > 0 ? aws_s3_bucket.tf_state[0].id : null
  description = "Name of the S3 bucket for Terraform state"
}

output "aws_s3_bucket_arn" {
  value       = length(aws_s3_bucket.tf_state) > 0 ? aws_s3_bucket.tf_state[0].arn : null
  description = "ARN of the S3 bucket"
}

output "aws_dynamodb_table_name" {
  value       = length(aws_dynamodb_table.tf_lock) > 0 ? aws_dynamodb_table.tf_lock[0].name : null
  description = "Name of the DynamoDB table for state locking"
}

output "aws_backend_config" {
  value = var.create_aws && length(aws_s3_bucket.tf_state) > 0 ? {
    bucket         = aws_s3_bucket.tf_state[0].id
    key            = "terraform.tfstate"
    region         = var.aws_region
    dynamodb_table = length(aws_dynamodb_table.tf_lock) > 0 ? aws_dynamodb_table.tf_lock[0].name : null
    encrypt        = true
  } : null
  description = "AWS backend configuration for other Terraform workspaces"
}

# ====================
# GCP Outputs
# ====================
output "gcs_bucket_name" {
  value       = length(google_storage_bucket.tf_state) > 0 ? google_storage_bucket.tf_state[0].name : null
  description = "Name of the GCS bucket for Terraform state"
}

output "gcs_bucket_url" {
  value       = length(google_storage_bucket.tf_state) > 0 ? google_storage_bucket.tf_state[0].url : null
  description = "URL of the GCS bucket"
}

output "gcp_backend_config" {
  value = var.create_gcp && length(google_storage_bucket.tf_state) > 0 ? {
    bucket = google_storage_bucket.tf_state[0].name
    prefix = "terraform/state"
  } : null
  description = "GCP backend configuration for other Terraform workspaces"
}

# ====================
# Azure Outputs
# ====================
output "azure_resource_group_name" {
  value       = length(azurerm_resource_group.tf_state) > 0 ? azurerm_resource_group.tf_state[0].name : null
  description = "Name of the Azure resource group"
}

output "azure_storage_account_name" {
  value       = length(azurerm_storage_account.tf_state) > 0 ? azurerm_storage_account.tf_state[0].name : null
  description = "Name of the Azure storage account"
}

output "azure_container_name" {
  value       = length(azurerm_storage_container.tf_state) > 0 ? azurerm_storage_container.tf_state[0].name : null
  description = "Name of the Azure blob container"
}

output "azure_backend_config" {
  value = var.create_azure && length(azurerm_storage_account.tf_state) > 0 ? {
    resource_group_name  = azurerm_resource_group.tf_state[0].name
    storage_account_name = azurerm_storage_account.tf_state[0].name
    container_name       = azurerm_storage_container.tf_state[0].name
    key                  = "terraform.tfstate"
  } : null
  description = "Azure backend configuration for other Terraform workspaces"
}
