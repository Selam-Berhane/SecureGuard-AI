#!/bin/bash

python3 -m venv venv

pip3 install boto3 pandas scikit-learn sagemaker --break-system-packages

export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
