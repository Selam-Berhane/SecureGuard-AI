resource "aws_lambda_function" "enricher" {
  filename         = "enricher.zip"
  function_name    = "secureguard-enricher"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = filebase64sha256("enricher.zip")
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 256

  environment {
    variables = {
      BUCKET_NAME = aws_s3_bucket.datalake.id
      KMS_KEY_ID  = aws_kms_key.datalake.id
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_cloudwatch_log_group.enricher
  ]
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "enricher" {
  name              = "/aws/lambda/secureguard-enricher"
  retention_in_days = 7
}

# CloudWatch Log Group for Orchestrator
resource "aws_cloudwatch_log_group" "orchestrator" {
  name              = "/aws/lambda/secureguard-orchestrator"
  retention_in_days = 7
}

# Orchestrator Lambda (similar structure)
resource "aws_lambda_function" "orchestrator" {
  filename         = "orchestrator.zip"
  function_name    = "secureguard-orchestrator"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = filebase64sha256("orchestrator.zip")
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 512

  environment {
    variables = {
      ENDPOINT_NAME  = try(aws_sagemaker_endpoint.classifier[0].name, "UNKNOWN")
      BUCKET_NAME    = aws_s3_bucket.datalake.id
      DYNAMODB_TABLE = aws_dynamodb_table.findings.name
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_cloudwatch_log_group.orchestrator
  ]
}