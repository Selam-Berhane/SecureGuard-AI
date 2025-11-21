# SecureGuard-AI

AI-powered automated threat detection and response system for AWS environments using machine learning to analyze security findings from GuardDuty and Security Hub.

## Overview

SecureGuard-AI is an automated security orchestration platform that ingests security findings from AWS GuardDuty and Security Hub, enriches them with threat intelligence, uses machine learning to assess threat severity, and automatically executes remediation actions based on confidence scores.

## Architecture

The system consists of the following components:

- **Data Ingestion**: EventBridge rules capture GuardDuty and Security Hub findings
- **Enrichment Lambda**: Enriches findings with IP reputation data and contextual information
- **ML Model**: XGBoost classifier deployed on SageMaker to assess threat severity
- **Orchestrator Lambda**: Coordinates ML inference and executes remediation workflows
- **Automated Remediation**: SSM automation documents for incident response
- **Data Lake**: S3 bucket for storing raw findings and model training data
- **Audit Trail**: DynamoDB table for logging all predictions and actions

## Components

### Lambda Functions

- `enricher`: Processes incoming security findings and adds threat intelligence
- `orchestrator`: Invokes ML model and triggers remediation based on threat scores

### Infrastructure

All infrastructure is defined as Terraform code:

- GuardDuty detector configuration
- Security Hub standards enablement
- EventBridge rules for event routing
- S3 data lake with lifecycle policies
- KMS encryption keys
- IAM roles and policies
- Lambda functions
- SageMaker endpoint
- DynamoDB audit table
- SSM automation documents

### Machine Learning

- **Model Type**: XGBoost binary classifier
- **Training**: Automated training pipeline on SageMaker
- **Features**: Severity, finding type, IP reputation, temporal patterns, baseline deviation
- **Deployment**: SageMaker endpoint with configurable instance type

### Remediation Actions

Automated responses triggered based on threat score and confidence:

- **Critical Threats** (score >= 90, confidence >= 0.85):
  - Isolate compromised EC2 instances
  - Revoke IAM credentials
  - Create forensic snapshots
  - Send SNS alerts

- **High Threats** (score >= 70):
  - Alert security team via SNS
  - Log to DynamoDB for investigation

- **Low/Medium Threats**:
  - Log for analysis and model improvement

## Prerequisites

- AWS Account with appropriate permissions
- Terraform >= 1.5.0
- Python 3.8+
- AWS CLI configured

## Deployment

### 1. Clone Repository

```bash
git clone <repository-url>
cd SecureGuard-AI
```

### 2. Configure Variables

Edit `terraform/variables.tf` or create a `terraform.tfvars` file:

```hcl
aws_region           = "us-east-1"
environment          = "dev"
project_name         = "secureguard-ai"
demo_mode            = false
enable_guardduty     = true
enable_securityhub   = true
```

### 3. Deploy Infrastructure

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### 4. Generate Training Data

```bash
cd dataset
python generate_synthetic_training_data.py
```

### 5. Upload Training Data to S3

```bash
export BUCKET_NAME=secureguard-ai-datalake-<ACCOUNT_ID>
aws s3 cp training_data.csv s3://${BUCKET_NAME}/model-training-data/
aws s3 cp validation_data.csv s3://${BUCKET_NAME}/model-training-data/
```

### 6. Train and Deploy Model

```bash
cd sagemaker/deploying
export BUCKET_NAME=secureguard-ai-datalake-<ACCOUNT_ID>
export AWS_REGION=us-east-1
python deploy_model.py
```

## Configuration

### Environment Variables

Lambda functions support the following environment variables:

- `BUCKET_NAME`: S3 bucket for data storage
- `ENDPOINT_NAME`: SageMaker endpoint name
- `SNS_TOPIC_ARN`: SNS topic for alerts
- `ABUSEIPDB_API_KEY`: Optional API key for IP reputation checks

### Terraform Variables

Key configuration options:

- `demo_mode`: Enable/disable expensive resources
- `enable_guardduty`: Toggle GuardDuty integration
- `enable_securityhub`: Toggle Security Hub integration
- `lambda_enricher_timeout`: Enricher function timeout (default: 60s)
- `lambda_orchestrator_timeout`: Orchestrator function timeout (default: 120s)
- `s3_lifecycle_glacier_days`: Days before archiving to Glacier (default: 90)

## Monitoring

- CloudWatch Logs: Lambda execution logs
- DynamoDB: Audit trail of all predictions and actions
- S3: Historical findings data partitioned by date
- CloudWatch Metrics: Lambda invocations, errors, duration

## Cost Optimization

- S3 lifecycle policies move old findings to Glacier after configurable period
- SageMaker endpoint can be configured as serverless or use smaller instance types
- Lambda functions use efficient memory allocation
- KMS keys and GuardDuty can be toggled via variables

## Security

- All S3 data encrypted with KMS
- Lambda functions use least-privilege IAM roles
- VPC endpoints available for private connectivity
- CloudTrail logs all API calls
- SSM automation documents follow AWS security best practices

## Project Structure

```
SecureGuard-AI/
├── dataset/              # Training data generation scripts
├── lambda/
│   ├── enricher/        # Finding enrichment function
│   └── orchestrator/    # ML orchestration function
├── sagemaker/
│   ├── training/        # Model training code
│   └── deploying/       # Deployment scripts
├── ssm_remedations/     # SSM automation documents
└── terraform/           # Infrastructure as code
    ├── dynamodb.tf
    ├── eventbridge.tf
    ├── guardduty.tf
    ├── iam.tf
    ├── kms.tf
    ├── lambda.tf
    ├── outputs.tf
    ├── providers.tf
    ├── s3.tf
    ├── sagemaker.tf
    ├── ssm.tf
    └── variables.tf
```

## Cleanup

To destroy all resources:

```bash
# Delete SageMaker endpoint first
aws sagemaker delete-endpoint --endpoint-name secureguard-ai-threat-classifier

# Destroy Terraform resources
cd terraform
terraform destroy
```

## License

This project is provided as-is for educational and demonstration purposes.