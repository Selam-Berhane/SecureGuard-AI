resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  # Enable S3 protection
  datasources {
    s3_logs {
      enable = true
    }

    kubernetes {
      audit_logs {
        enable = true
      }
    }

    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name = "${var.project_name}-detector"
  }
}

# GuardDuty publishing destination (optional - to S3)
resource "aws_guardduty_publishing_destination" "main" {
  count = var.enable_guardduty ? 1 : 0

  detector_id     = aws_guardduty_detector.main[0].id
  destination_arn = aws_s3_bucket.datalake.arn
  kms_key_arn     = aws_kms_key.datalake.arn

  depends_on = [
    aws_s3_bucket_policy.guardduty_publishing
  ]
}

# S3 bucket policy for GuardDuty
resource "aws_s3_bucket_policy" "guardduty_publishing" {
  bucket = aws_s3_bucket.datalake.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Allow GuardDuty to write findings"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.datalake.arn}/*"
      },
      {
        Sid    = "Allow GuardDuty to get bucket location"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "s3:GetBucketLocation"
        ]
        Resource = aws_s3_bucket.datalake.arn
      }
    ]
  })
}

