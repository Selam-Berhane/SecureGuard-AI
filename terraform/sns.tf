# SNS Topic for Security Alerts
# Purpose: Send email notifications for high-severity threat detections
# Triggered by: Orchestrator Lambda when threat_score >= 70

resource "aws_sns_topic" "security_alerts" {
  name         = "${var.project_name}-security-alerts"
  display_name = "SecureGuard AI Security Alerts"

  # Enable server-side encryption
  kms_master_key_id = aws_kms_key.datalake.id

  tags = {
    Name        = "${var.project_name}-security-alerts"
    Purpose     = "High-severity threat notifications"
    ManagedBy   = "Terraform"
    Environment = var.environment
  }
}

# Email Subscription
# Note: Subscriber must confirm subscription via email after terraform apply
resource "aws_sns_topic_subscription" "security_email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.receiver_email

  # Email subscriptions require manual confirmation
  # Terraform will create the subscription in "PendingConfirmation" state
  # User must click the confirmation link sent to their email
}

# SNS Topic Policy - Allow Lambda to publish
resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowOrchestratorLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = [
          "SNS:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_lambda_function.orchestrator.arn
          }
        }
      },
      {
        Sid    = "AllowAccountOwnerManagement"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "SNS:GetTopicAttributes",
          "SNS:SetTopicAttributes",
          "SNS:AddPermission",
          "SNS:RemovePermission",
          "SNS:DeleteTopic",
          "SNS:Subscribe",
          "SNS:ListSubscriptionsByTopic",
          "SNS:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# CloudWatch Alarm - Monitor for failed SNS publishes
resource "aws_cloudwatch_metric_alarm" "sns_failed_notifications" {
  alarm_name          = "${var.project_name}-sns-publish-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "NumberOfNotificationsFailed"
  namespace           = "AWS/SNS"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alert if SNS fails to deliver security notifications"
  treat_missing_data  = "notBreaching"

  dimensions = {
    TopicName = aws_sns_topic.security_alerts.name
  }
}

# Output SNS Topic ARN for reference
output "sns_topic_arn" {
  description = "ARN of the security alerts SNS topic"
  value       = aws_sns_topic.security_alerts.arn
}

output "sns_subscription_status" {
  description = "Email subscription confirmation instructions"
  value       = "IMPORTANT: Check ${var.receiver_email} for SNS subscription confirmation email and click the confirmation link"
}
