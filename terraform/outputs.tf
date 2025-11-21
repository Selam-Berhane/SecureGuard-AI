output "aws_account_id" {
  description = "AWS Account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "aws_region" {
  description = "AWS Region"
  value       = data.aws_region.current
}

#s3 Data lake
output "s3_bucket_name" {
  description = "S3 Data Lake bucket name"
  value       = try(aws_s3_bucket.datalake.id, "not created")
}

output "s3_bucket_arn" {
  description = "S3 Data Lake buxket ARN"
  value       = try(aws_s3_bucket.datalake.arn, "not created")

}

output "kms_key_id" {
  description = "KMS Key ID for encryption"
  value       = try(aws_kms_key.datalake.id, "not created")
}

# Lambda Functions
output "lambda_enricher_arn" {
  description = "Enricher Lambda ARN"
  value       = try(aws_lambda_function.enricher.arn, "not created")
}

output "lambda_orchestrator_arn" {
  description = "Orchestrator Lambda ARN"
  value       = try(aws_lambda_function.orchestrator.arn, "not created")
}

#Sagemaker 
#output "sagemaker_endpoint_name" {
#description = "SageMaker endpoint name"
#value       = try(aws_sagemaker_endpoint.classifier[0].name, "not created (demo_mode=false)")
#}

# GuardDuty
output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = try(aws_guardduty_detector.main[0].id, "not created")
}

output "guardduty_detector_arn" {
  description = "GuardDuty detector ARN"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].arn : "not enabled"
}

# DynamoDB
output "dynamodb_table_name" {
  description = "DynamoDB findings table name"
  value       = try(aws_dynamodb_table.findings.name, "not created")
}

output "dynamodb_table_arn" {
  description = "DynamoDB table ARN"
  value       = aws_dynamodb_table.findings.arn
}


# IAM Roles
output "lambda_role_arn" {
  description = "Lambda execution role ARN"
  value       = aws_iam_role.lambda.arn
}

output "sagemaker_role_arn" {
  description = "SageMaker execution role ARN"
  value       = aws_iam_role.sagemaker.arn
}

# GuardDuty
output "guardduty_enabled" {
  description = "Whether GuardDuty is enabled"
  value       = var.enable_guardduty
}

# Security Hub
output "securityhub_enabled" {
  description = "Whether Security Hub is enabled"
  value       = var.enable_securityhub
}

# Complete deployment info
output "deployment_complete" {
  description = "Deployment completion status"
  value = {
    timestamp    = timestamp()
    demo_mode    = var.demo_mode
    region       = data.aws_region.current.name
    account_id   = data.aws_caller_identity.current.account_id
    project_name = var.project_name
  }
}

# Summary
output "deployment_summary" {
  description = "Deployment summary"
  value = {
    project     = var.project_name
    environment = var.environment
    region      = data.aws_region.current.name
    demo_mode   = var.demo_mode
  }
}