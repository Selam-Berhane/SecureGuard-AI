resource "aws_dynamodb_table" "findings" {
  name         = "${var.project_name}-findings"
  billing_mode = "PAY_PER_REQUEST" # On-demand pricing
  hash_key     = "finding_id"
  range_key    = "timestamp"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S" # String (ISO 8601 format)
  }

  # GSI for querying by account
  attribute {
    name = "account_id"
    type = "S"
  }

  # GSI for querying by threat score
  attribute {
    name = "threat_score"
    type = "N" # Number
  }

  # Global Secondary Index - Query by account
  global_secondary_index {
    name            = "AccountIndex"
    hash_key        = "account_id"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  # Global Secondary Index - Query by threat score
  global_secondary_index {
    name            = "ThreatScoreIndex"
    hash_key        = "threat_score"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  # Server-side encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.datalake.arn
  }

  # TTL (optional - delete old records after 90 days)
  ttl {
    attribute_name = "expiration_time"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-findings-table"
  }
}