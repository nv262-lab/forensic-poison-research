resource "google_storage_bucket" "bucket" {
  name          = "${var.prefix}-gcp-bucket"
  project       = var.project
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true

  # Optional: Set lifecycle rules if needed
  lifecycle {
    prevent_destroy = false  # Adjust as needed, but force_destroy is already set to true
  }
}

variable "prefix" {
  description = "Prefix for bucket name"
  type        = string
}

variable "project" {
  description = "GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region for the bucket"
  type        = string
}
