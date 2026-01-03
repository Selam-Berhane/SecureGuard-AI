
# Trust policy for Lambda

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]

  }
}

# Enricher Lambda execution role
resource "aws_iam_role" "lambda_enricher" {
  name               = "${var.project_name}-lambda-enricher-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Name = "${var.project_name}-lambda-enricher-role"
  }
}

# Orchestrator Lambda execution role
resource "aws_iam_role" "lambda_orchestrator" {
  name               = "${var.project_name}-lambda-orchestrator-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Name = "${var.project_name}-lambda-orchestrator-role"
  }
}

################################################################################
# ENRICHER LAMBDA IAM POLICY
# Purpose: Enrich GuardDuty findings with metadata and store to S3
# Risk Level: LOW (read-only operations + S3 write)
################################################################################

data "aws_iam_policy_document" "lambda_enricher_custom" {
  # S3 Write Access - Store enriched findings to data lake
  # Scoped to: raw-findings prefix only
  statement {
    sid    = "S3WriteEnrichedFindings"
    effect = "Allow"

    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.datalake.arn}/raw-findings/*"
    ]
  }

  # KMS Encryption - Required for S3 ServerSideEncryption
  # Scoped to: Data lake KMS key only
  statement {
    sid    = "KMSEncryptS3Objects"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey"
    ]

    resources = [aws_kms_key.datalake.arn]
  }

  # Lambda Invoke - Call orchestrator Lambda with enriched data
  # Scoped to: Orchestrator Lambda only
  statement {
    sid    = "InvokeOrchestratorLambda"
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction"
    ]

    resources = [
      "arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${var.project_name}-orchestrator"
    ]
  }

  # IAM Read Access - Feature extraction for ML model
  # Reason: Account-level operations, cannot scope to specific resources
  # - GetUser: Get IAM principal age and creation date
  # - ListMFADevices: Check MFA status for security posture
  # - GenerateCredentialReport: Create report for account age calculation
  # - GetCredentialReport: Read root user creation time = account age
  statement {
    sid    = "IAMReadOnlyForFeatures"
    effect = "Allow"

    actions = [
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "lambda_enricher_custom" {
  name        = "${var.project_name}-lambda-enricher-policy"
  description = "Least-privilege policy for Enricher Lambda - data collection and feature extraction"
  policy      = data.aws_iam_policy_document.lambda_enricher_custom.json
}

################################################################################
# ORCHESTRATOR LAMBDA IAM POLICY
# Purpose: ML inference and automated threat remediation
# Risk Level: HIGH (destructive IAM/EC2 operations)
################################################################################

data "aws_iam_policy_document" "lambda_orchestrator_custom" {
  # SageMaker Inference - Invoke ML model for threat scoring
  # Scoped to: SecureGuard endpoint only
  statement {
    sid    = "SageMakerInvokeEndpoint"
    effect = "Allow"

    actions = [
      "sagemaker:InvokeEndpoint"
    ]

    resources = [
      "arn:aws:sagemaker:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:endpoint/${var.project_name}-threat-classifier"
    ]
  }

  # DynamoDB Write - Log ML predictions and actions taken
  # Scoped to: Findings table only
  statement {
    sid    = "DynamoDBWritePredictions"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem"
    ]

    resources = [aws_dynamodb_table.findings.arn]
  }

  # SNS Alerts - Notify security team of high-severity threats
  # Scoped to: SecureGuard SNS topics only
  statement {
    sid    = "SNSPublishAlerts"
    effect = "Allow"

    actions = [
      "sns:Publish"
    ]

    resources = [
      "arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:${var.project_name}-*"
    ]
  }

  # SSM Automation - Execute EC2 isolation automation
  # Scoped to: SecureGuard SSM documents only
  # Reason: Executes automated remediation workflows
  statement {
    sid    = "SSMExecuteRemediation"
    effect = "Allow"

    actions = [
      "ssm:StartAutomationExecution"
    ]

    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:automation-definition/SecureGuard-*"
    ]
  }

  # IAM Remediation - Revoke compromised credentials
  # Reason: Account-level operations for security incident response
  # - ListAccessKeys: Find all access keys for compromised user
  # - DeleteAccessKey: Remove compromised keys
  # - AttachUserPolicy: Attach AWSDenyAll to block further access
  # WARNING: Destructive operations - use with caution
  statement {
    sid    = "IAMRevokeCompromisedCredentials"
    effect = "Allow"

    actions = [
      "iam:ListAccessKeys",
      "iam:DeleteAccessKey",
      "iam:AttachUserPolicy"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "lambda_orchestrator_custom" {
  name        = "${var.project_name}-lambda-orchestrator-policy"
  description = "Least-privilege policy for Orchestrator Lambda - ML inference and threat remediation"
  policy      = data.aws_iam_policy_document.lambda_orchestrator_custom.json
}

################################################################################
# ATTACH POLICIES TO ROLES
################################################################################

# Enricher Lambda - Basic execution + custom permissions
resource "aws_iam_role_policy_attachment" "enricher_basic" {
  role       = aws_iam_role.lambda_enricher.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "enricher_custom" {
  role       = aws_iam_role.lambda_enricher.name
  policy_arn = aws_iam_policy.lambda_enricher_custom.arn
}

# Orchestrator Lambda - Basic execution + custom permissions
resource "aws_iam_role_policy_attachment" "orchestrator_basic" {
  role       = aws_iam_role.lambda_orchestrator.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "orchestrator_custom" {
  role       = aws_iam_role.lambda_orchestrator.name
  policy_arn = aws_iam_policy.lambda_orchestrator_custom.arn
}


# SageMaker Execution Role
# Trust policy for SageMaker
data "aws_iam_policy_document" "sagemaker_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sagemaker.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

# SageMaker execution role
resource "aws_iam_role" "sagemaker" {
  name               = "${var.project_name}-sagemaker-role"
  assume_role_policy = data.aws_iam_policy_document.sagemaker_assume_role.json

  tags = {
    Name = "${var.project_name}-sagemaker-role"
  }
}

# SageMaker custom policy
data "aws_iam_policy_document" "sagemaker_custom" {
  # S3 access
  statement {
    sid    = "S3Access"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.datalake.arn,
      "${aws_s3_bucket.datalake.arn}/*"
    ]
  }

  # KMS access
  statement {
    sid    = "KMSAccess"
    effect = "Allow"

    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey"
    ]

    resources = [aws_kms_key.datalake.arn]
  }

  # CloudWatch Logs
  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]

    resources = ["*"]
  }

  # ECR (for custom containers - optional)
  statement {
    sid    = "ECRAccess"
    effect = "Allow"

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage"
    ]

    resources = ["*"]
  }
}

# Create SageMaker custom policy
resource "aws_iam_policy" "sagemaker_custom" {
  name        = "${var.project_name}-sagemaker-custom-policy"
  description = "Custom policy for SecureGuard AI SageMaker"
  policy      = data.aws_iam_policy_document.sagemaker_custom.json
}

# Attach SageMaker managed policy
resource "aws_iam_role_policy_attachment" "sagemaker_full_access" {
  role       = aws_iam_role.sagemaker.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

# Attach custom policy
resource "aws_iam_role_policy_attachment" "sagemaker_custom" {
  role       = aws_iam_role.sagemaker.name
  policy_arn = aws_iam_policy.sagemaker_custom.arn
}


# EventBridge Role (for invoking Lambda)


data "aws_iam_policy_document" "eventbridge_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "eventbridge" {
  name               = "${var.project_name}-eventbridge-role"
  assume_role_policy = data.aws_iam_policy_document.eventbridge_assume_role.json

  tags = {
    Name = "${var.project_name}-eventbridge-role"
  }
}

data "aws_iam_policy_document" "eventbridge_invoke_lambda" {
  statement {
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction"
    ]

    resources = ["arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${var.project_name}-*"]
  }
}

resource "aws_iam_policy" "eventbridge_invoke_lambda" {
  name   = "${var.project_name}-eventbridge-invoke-lambda"
  policy = data.aws_iam_policy_document.eventbridge_invoke_lambda.json
}

resource "aws_iam_role_policy_attachment" "eventbridge_invoke_lambda" {
  role       = aws_iam_role.eventbridge.name
  policy_arn = aws_iam_policy.eventbridge_invoke_lambda.arn
}
