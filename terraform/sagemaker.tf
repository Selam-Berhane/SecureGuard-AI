locals {
  # Update this after you train your model
  model_artifacts_uri = "s3://${aws_s3_bucket.datalake.id}/model-artifacts/model.tar.gz"
}


# ECR image for XGBoost inference (matches train_model.py)
data "aws_sagemaker_prebuilt_ecr_image" "xgboost" {
  repository_name = "sagemaker-xgboost"
  image_tag       = "1.7-1"
}

resource "aws_sagemaker_model" "classifier" {
  count = var.demo_mode ? 1 : 0

  name               = "${var.project_name}-threat-classifier-model"
  execution_role_arn = aws_iam_role.sagemaker.arn

  primary_container {
    image          = data.aws_sagemaker_prebuilt_ecr_image.xgboost.registry_path
    model_data_url = local.model_artifacts_uri

    environment = {
      SAGEMAKER_PROGRAM          = "inference.py"
      SAGEMAKER_SUBMIT_DIRECTORY = local.model_artifacts_uri
    }
  }

  tags = {
    Name = "${var.project_name}-model"
  }
}



resource "aws_sagemaker_endpoint_configuration" "classifier_serverless" {
  count = var.demo_mode ? 1 : 0

  name = "${var.project_name}-classifier-serverless-config-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  production_variants {
    variant_name = "AllTraffic"
    model_name   = aws_sagemaker_model.classifier[0].name

    serverless_config {
      memory_size_in_mb       = var.sagemaker_serverless_memory
      max_concurrency         = var.sagemaker_serverless_max_concurrency
      provisioned_concurrency = 0 # Optional: set to 1-5 for lower cold start
    }
  }

  tags = {
    Name = "${var.project_name}-serverless-config"
  }

  lifecycle {
    create_before_destroy = true
  }
}


resource "aws_sagemaker_endpoint" "classifier" {
  count = var.demo_mode ? 1 : 0

  name                 = "${var.project_name}-threat-classifier"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.classifier_serverless[0].name

  tags = {
    Name = "${var.project_name}-endpoint"
  }
}


resource "aws_cloudwatch_metric_alarm" "sagemaker_invocation_errors" {
  count = var.demo_mode ? 1 : 0

  alarm_name          = "${var.project_name}-sagemaker-invocation-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "ModelInvocationErrors"
  namespace           = "AWS/SageMaker"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors SageMaker endpoint errors"

  dimensions = {
    EndpointName = aws_sagemaker_endpoint.classifier[0].name
    VariantName  = "AllTraffic"
  }
}

output "sagemaker_model_arn" {
  description = "SageMaker model ARN"
  value       = var.demo_mode ? aws_sagemaker_model.classifier[0].arn : "not created (demo_mode=false)"
}

output "sagemaker_endpoint_arn" {
  description = "SageMaker endpoint ARN"
  value       = var.demo_mode ? aws_sagemaker_endpoint.classifier[0].arn : "not created (demo_mode=false)"
}