resource "aws_s3_bucket" "datalake" {
  bucket = "${lower(var.project_name)}-datalake-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-datalake"
  }
}

resource "aws_s3_bucket_versioning" "datalake" {
  bucket = aws_s3_bucket.datalake.id
  versioning_configuration {
    status = "Enabled"
  }

}

#server side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "datalake" {
  bucket = aws_s3_bucket.datalake.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.datalake.id
    }
    bucket_key_enabled = true
  }
}

#public access block
resource "aws_s3_bucket_public_access_block" "datalake" {
  bucket                  = aws_s3_bucket.datalake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#lifecycle policy
resource "aws_s3_bucket_lifecycle_configuration" "datalake" {
  bucket = aws_s3_bucket.datalake.id
  rule {
    id     = "archive-old-findings"
    status = "Enabled"
    filter {
      prefix = "raw-findings/"
    }
    transition {
      days          = var.s3_lifecycle_glacier_days
      storage_class = "GLACIER"
    }
  }

  rule {
    id     = "delete-old-vpc-logs"
    status = "Enabled"
    filter {
      prefix = "vpc-flow-logs/"
    }
    expiration {
      days = 365
    }
  }
}

#folder structure
resource "aws_s3_object" "folders" {
  for_each = toset([
    "raw-findings/",
    "processed-features/",
    "model-training-data/",
    "vpc-flow-logs/",
    "model-artifacts/"
  ])
  bucket  = aws_s3_bucket.datalake.id
  key     = each.value
  content = ""
}

