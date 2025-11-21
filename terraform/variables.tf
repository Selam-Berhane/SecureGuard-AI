variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name for resource naming"
  type        = string
  default     = "secureguard-ai"
}

variable "demo_mode" {
  description = "Enable expensive resources for demos (sagemaker endpoint)"
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Enable GuardDuty monitoring"
  type        = bool
  default     = true
}

variable "enable_securityhub" {
  description = "Enable SecurityHub monitoring"
  type        = bool
  default     = true
}

variable "s3_lifecycle_glacier_days" {
  description = "Days before moving findings to Glacier"
  type        = number
  default     = 90
}

variable "lambda_enricher_timeout" {
  description = "Enricher Lambda timeout in seconds"
  type        = number
  default     = 60
}

variable "lambda_orchestrator_timeout" {
  description = "Orchestrator Lambda timeout in seconds"
  type        = number
  default     = 120
}

variable "sagemaker_serverless_memory" {
  description = "SageMaker serverless endpoint memory in MB"
  type        = number
  default     = 2048
}

variable "sagemaker_serverless_max_concurrency" {
  description = "SageMaker serverless max concurrent invocations"
  type        = number
  default     = 5
}
