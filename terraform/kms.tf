resource "aws_kms_key" "datalake" {
  description             = "SecureGuard AI Data Lake Encryption Key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "${var.project_name}-datalake-key"
  }
}


#KEY alias
resource "aws_kms_alias" "datalake" {
  name          = "alias/${var.project_name}-datalake"
  target_key_id = aws_kms_key.datalake.id
}

# KMS key policy
resource "aws_kms_key_policy" "datalake" {
  key_id = aws_kms_key.datalake.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow services to use the key"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "lambda.amazonaws.com",
            "sagemaker.amazonaws.com",
            "logs.amazonaws.com",
            "guardduty.amazonaws.com"
          ]
        }
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

