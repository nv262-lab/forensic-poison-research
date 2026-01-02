variable "prefix" { type = string }
variable "project" { type = string }
variable "region" { type = string }
resource "google_storage_bucket" "bucket" { name = "${var.prefix}-gcp-bucket" project = var.project location = var.region force_destroy = true }
output "resources" { value = { bucket = google_storage_bucket.bucket.name } }
