# infrastructure/terraform/backend/providers.tf

provider "aws" {
  region = var.aws_region
  
  # GitHub Actions will use OIDC or static credentials from environment variables
  # No explicit configuration needed - AWS provider auto-detects credentials
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
  
  # Credentials come from GOOGLE_CREDENTIALS environment variable in CI
  # or from gcloud CLI locally
}

provider "azurerm" {
  features {}
  
  # For GitHub Actions, credentials come from environment variables or OIDC
  # For local development, use 'az login'
  skip_provider_registration = true
}
