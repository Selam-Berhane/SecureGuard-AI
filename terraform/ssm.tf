# SSM Document for EC2 Instance Isolation
resource "aws_ssm_document" "isolate_instance" {
  name            = "SecureGuard-IsolateEC2Instance"
  document_type   = "Automation"
  document_format = "YAML"

  content = file("${path.module}/../ssm/ssm_custom.yaml")

  tags = {
    Name        = "SecureGuard-IsolateEC2Instance"
    Environment = "Production"
    Purpose     = "Security-Incident-Response"
  }
}

# IAM Role for SSM Automation
resource "aws_iam_role" "ssm_automation" {
  name = "secureguard-ssm-automation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ssm.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "secureguard-ssm-automation-role"
  }
}

# IAM Policy for SSM Automation
resource "aws_iam_role_policy" "ssm_automation" {
  name = "secureguard-ssm-automation-policy"
  role = aws_iam_role.ssm_automation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:ModifyInstanceAttribute",
          "ec2:StopInstances",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = "arn:aws:sns:*:*:secureguard-alerts"
      }
    ]
  })
}

# Output the document name
output "ssm_document_name" {
  description = "Name of the SSM automation document"
  value       = aws_ssm_document.isolate_instance.name
}

output "ssm_automation_role_arn" {
  description = "ARN of the SSM automation role"
  value       = aws_iam_role.ssm_automation.arn
}
