resource "random_id" "suffix" {
  byte_length = 2
}

resource "aws_s3_bucket" "bucket" {
  bucket        = "${var.prefix}-aws-bucket-${random_id.suffix.hex}"
  acl           = "private"
  force_destroy = true
}

variable "prefix" {
  type = string
}

variable "region" {
  type = string
}
