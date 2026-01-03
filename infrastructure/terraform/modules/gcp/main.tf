resource "google_storage_bucket" "bucket" {
  name          = "${var.prefix}-gcp-bucket"
  project       = var.project
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access {
    enabled = true
  }

  versioning {
    enabled = true
  }
}

variable "prefix" {
  type = string
}

variable "project" {
  type = string
}

variable "region" {
  type = string
}
