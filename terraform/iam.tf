
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

# Lambda execution role
resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json

  tags = {
    Name = "${var.project_name}-lambda-role"
  }
}

# Lambda custom policy
data "aws_iam_policy_document" "lambda_custom" {
  # S3 access
  statement {
    sid    = "S3Access"
    effect = "Allow"

    actions = [
      "s3:PutObject",
      "s3:GetObject",
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

  # SageMaker invoke
  statement {
    sid    = "SageMakerInvoke"
    effect = "Allow"

    actions = [
      "sagemaker:InvokeEndpoint"
    ]

    resources = ["*"]
  }

  # DynamoDB access
  statement {
    sid    = "DynamoDBAccess"
    effect = "Allow"

    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan"
    ]

    resources = [aws_dynamodb_table.findings.arn]
  }

  # Lambda invocation (for Enricher -> Orchestrator)
  statement {
    sid    = "LambdaInvoke"
    effect = "Allow"

    actions = [
      "lambda:InvokeFunction"
    ]

    resources = ["arn:aws:lambda:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:function:${var.project_name}-*"]
  }

  # SNS publish
  statement {
    sid    = "SNSPublish"
    effect = "Allow"

    actions = [
      "sns:Publish"
    ]

    resources = ["*"]
  }

  # Systems Manager (for remediation)
  statement {
    sid    = "SSMAccess"
    effect = "Allow"

    actions = [
      "ssm:StartAutomationExecution",
      "ssm:GetAutomationExecution",
      "ssm:DescribeDocument"
    ]

    resources = ["*"]
  }

  # EC2 (for remediation)
  statement {
    sid    = "EC2Remediation"
    effect = "Allow"

    actions = [
      "ec2:ModifyInstanceAttribute",
      "ec2:CreateSnapshot",
      "ec2:DescribeInstances",
      "ec2:CreateNetworkAclEntry",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSnapshots"
    ]

    resources = ["*"]
  }

  # IAM (for credential revocation)
  statement {
    sid    = "IAMRemediation"
    effect = "Allow"

    actions = [
      "iam:DeleteAccessKey",
      "iam:ListAccessKeys",
      "iam:AttachUserPolicy",
      "iam:GetUser"
    ]

    resources = ["*"]
  }
}

# Create custom policy
resource "aws_iam_policy" "lambda_custom" {
  name        = "${var.project_name}-lambda-custom-policy"
  description = "Custom policy for SecureGuard AI Lambda functions"
  policy      = data.aws_iam_policy_document.lambda_custom.json
}

# Attach managed policy (basic execution)
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Attach custom policy
resource "aws_iam_role_policy_attachment" "lambda_custom" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.lambda_custom.arn
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
