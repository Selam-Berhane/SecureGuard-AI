import boto3
import sagemaker
from sagemaker.xgboost import XGBoost
from sagemaker.serverless import ServerlessInferenceConfig
import time
import json
import os
import sys

def main():
    print("SecureGuard AI - SageMaker XGBoost Deployment")
    
    # Configuration
    REGION = os.environ.get('AWS_REGION', 'us-east-1')
    BUCKET_NAME = os.environ.get('BUCKET_NAME')
    PROJECT_NAME = 'secureguard-ai'
    
    if not BUCKET_NAME:
        print("\nERROR: BUCKET_NAME environment variable must be set")
        print("\nUsage:")
        print("  export BUCKET_NAME=secureguard-ai-datalake-YOUR-ACCOUNT-ID")
        print("  export AWS_REGION=us-east-1")
        print("  python3 deploy_model.py")
        sys.exit(1)
    
    # Initialize SageMaker
    print("\nInitializing SageMaker session...")
    try:
        boto_session = boto3.Session(region_name=REGION)
        sagemaker_session = sagemaker.Session(boto_session=boto_session)
        
        # Get execution role
        try:
            role = sagemaker.get_execution_role()
        except:
            # If not running in SageMaker notebook, get from environment or use default
            sts = boto3.client('sts', region_name=REGION)
            account_id = sts.get_caller_identity()['Account']
            role = f"arn:aws:iam::{account_id}:role/{PROJECT_NAME}-sagemaker-role"
            print(f"Using role: {role}")
        
    except Exception as e:
        print(f"\n ERROR initializing SageMaker: {e}")
        print("\nMake sure you have:")
        print("  1. AWS credentials configured")
        print("  2. Correct IAM permissions")
        print("  3. SageMaker role created")
        sys.exit(1)
    
    print(f"\n✓ Configuration:")
    print(f"  Region: {REGION}")
    print(f"  Bucket: {BUCKET_NAME}")
    print(f"  Role: {role}")
    
    # Verify data exists
    print("\nVerifying training data...")
    train_data = f's3://{BUCKET_NAME}/model-training-data/training_data.csv'
    val_data = f's3://{BUCKET_NAME}/model-training-data/validation_data.csv'
    
    s3 = boto3.client('s3', region_name=REGION)
    try:
        s3.head_object(Bucket=BUCKET_NAME, Key='model-training-data/training_data.csv')
        s3.head_object(Bucket=BUCKET_NAME, Key='model-training-data/validation_data.csv')
        print(f"✓ Training data found:")
        print(f"    {train_data}")
        print(f"    {val_data}")
    except:
        print(f"\n ERROR: Training data not found in S3")
        print(f"\nPlease upload training data first:")
        print(f"  aws s3 cp training_data.csv s3://{BUCKET_NAME}/model-training-data/")
        print(f"  aws s3 cp validation_data.csv s3://{BUCKET_NAME}/model-training-data/")
        sys.exit(1)
    
    # Create XGBoost estimator
    print("Step 1: Creating XGBoost Estimator")

    xgb_estimator = XGBoost(
        entry_point='train.py',
        source_dir='../training',
        role=role,
        instance_type='ml.m5.xlarge',
        instance_count=1,
        framework_version='1.7-1',
        py_version='py3',

        hyperparameters={
            'max_depth': 6,
            'eta': 0.3,
            'gamma': 0,
            'min_child_weight': 1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'objective': 'binary:logistic',
            'num_round': 100
        },
        output_path=f's3://{BUCKET_NAME}/model-artifacts/',
        base_job_name=f'{PROJECT_NAME}-training'
    )


    print("Step 2: Training Model on SageMaker")

    start_time = time.time()
    try:
        xgb_estimator.fit({
            'train': train_data,
            'validation': val_data},
            wait=True,
            logs='Training'
        )
    except Exception as e:
        print(f" aws logs tail /aws/sagemaker/TrainingJobs --follow")
        sys.exit(1)

    training_time = time.time() - start_time
    print(f" Completed training in  {training_time/60:.1f} minutes")

    #collect some data from the model
    training_job_name = xgb_estimator.latest_training_job
    model_data = xgb_estimator.model_data

    print("Step 3: Deploying to Regular Endpoint")

    # Using regular endpoint instead of serverless to avoid 180s timeout issues
    endpoint_name = f'{PROJECT_NAME}-threat-classifier'

    print("\nDeploying endpoint...")
    print("Note: Using ml.t2.medium instance (~$35/month)")
    try:
        predictor = xgb_estimator.deploy(
            initial_instance_count=1,
            instance_type='ml.t2.medium',
            endpoint_name=endpoint_name,
            serializer=sagemaker.serializers.JSONSerializer(),
            deserializer=sagemaker.deserializers.JSONDeserializer()
        )
    except Exception as e:
        sm = boto3.client('sagemaker', region_name=REGION)
        try:
            response = sm.describe_endpoint(EndpointName=endpoint_name)
            print(f"\nEndpoint already exists with status: {response['EndpointStatus']}")
            print(f"aws sagemaker delete-endpoint --endpoint-name {endpoint_name}")
        except:
            pass
        
        sys.exit(1)
    

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n Deployment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)