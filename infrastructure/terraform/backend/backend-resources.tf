resource "aws_s3_bucket" "tf_state" {
  bucket = var.tf_state_bucket

  # keep private by default
  acl = "private"

  versioning {
    enabled = true
  }

  tags = {
    Name        = var.tf_state_bucket
    ManagedBy   = "terraform"
    Environment = "ci"
  }

  lifecycle_rule {
    id      = "expire-old-versions"
    enabled = true

    noncurrent_version_expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "tf_state_acl" {
  bucket = aws_s3_bucket.tf_state.id
  acl    = "private"
}

resource "aws_dynamodb_table" "tf_lock" {
  name         = var.tf_lock_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name      = var.tf_lock_table
    ManagedBy = "terraform"
  }
}
