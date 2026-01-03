import json
import boto3
import os
from decimal import Decimal

sagemaker_runtime = boto3.client('sagemaker-runtime')
sns = boto3.client('sns')
ssm = boto3.client('ssm')
dynamodb = boto3.resource('dynamodb')

ENDPOINT_NAME = os.environ.get('ENDPOINT_NAME', 'secureguard-ai-threat-classifier')
SNS_TOPIC = os.environ.get('SNS_TOPIC_ARN', '')

# Feature mapping
SEVERITY_MAP = {'LOW': 1, 'MEDIUM': 5, 'HIGH': 8, 'CRITICAL': 10}
FINDING_TYPES = [
    "UnauthorizedAccess:EC2/SSHBruteForce",
    "UnauthorizedAccess:EC2/RDPBruteForce",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "Recon:EC2/PortProbeUnprotectedPort",
    "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "Backdoor:EC2/C&CActivity.B!DNS",
    "Trojan:EC2/DNSDataExfiltration",
    "Impact:EC2/AbusedDomainRequest.Reputation",
    "Policy:IAMUser/RootCredentialUsage"
]

def lambda_handler(event, context):
    """
    Orchestrates ML prediction and remediation
    """
    print("Received enriched finding:", json.dumps(event))
    
    # Prepare features
    features = prepare_features(event)
    
    # Invoke SageMaker
    try:
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=ENDPOINT_NAME,
            ContentType='application/json',
            Body=json.dumps({'features': features})
        )
        
        prediction = json.loads(response['Body'].read())
        threat_score = prediction['threat_score']
        confidence = prediction['confidence']
        
        print(f"ML Prediction - Threat Score: {threat_score:.1f}, Confidence: {confidence:.2f}")
        
    except Exception as e:
        print(f"Error invoking SageMaker: {e}")
        threat_score = 50.0  # Default to medium
        confidence = 0.5
    
    # Log to DynamoDB
    log_prediction(event, threat_score, confidence)
    
    # Decision engine
    action_taken = None
    if threat_score >= 90 and confidence >= 0.85:
        print("Critical threat detected - Remediating")
        action_taken = remediate(event)
    elif threat_score >= 70:
        print("High threat - Alerting security team")
        action_taken = alert_security_team(event, threat_score)
    else:
        print("Low/Medium threat - Logged only")
        action_taken = "logged"
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'threat_score': threat_score,
            'confidence': confidence,
            'action_taken': action_taken
        })
    }

def prepare_features(finding):
    """
    Convert enriched finding to feature vector for ML model.
    All features should now be extracted by the Enricher Lambda.
    """
    severity_numeric = SEVERITY_MAP.get(finding.get('severity', 'MEDIUM'), 5)

    finding_type = finding.get('type', '')
    type_encoded = FINDING_TYPES.index(finding_type) if finding_type in FINDING_TYPES else 0

    # Get IP reputation and calculate derived feature
    ip_reputation = finding.get('ip_reputation', 0)
    is_known_malicious_ip = 1 if ip_reputation > 80 else 0

    # Build feature vector using extracted features from Enricher
    # Order must match training data feature_names.json
    features = [
        severity_numeric,                                    # 0: severity_numeric
        type_encoded,                                        # 1: type_encoded
        ip_reputation,                                       # 2: ip_reputation
        finding.get('hour_of_day', 12),                     # 3: hour_of_day
        finding.get('day_of_week', 0),                      # 4: day_of_week
        finding.get('geo_anomaly', 0),                      # 5: geo_anomaly
        finding.get('baseline_deviation', 0.5),             # 6: baseline_deviation
        finding.get('failed_login_attempts_24h', 0),        # 7: failed_login_attempts_24h
        finding.get('source_port', 0),                      # 8: source_port
        finding.get('destination_port', 0),                 # 9: destination_port
        finding.get('bytes_transferred', 0),                # 10: bytes_transferred
        finding.get('packets_sent', 0),                     # 11: packets_sent
        finding.get('connection_duration_sec', 0),          # 12: connection_duration_sec
        is_known_malicious_ip,                              # 13: is_known_malicious_ip
        finding.get('iam_principal_age_days', 0),           # 14: iam_principal_age_days
        finding.get('account_age_days', 0),                 # 15: account_age_days
        finding.get('previous_incidents_count', 0),         # 16: previous_incidents_count
        finding.get('mfa_enabled', 0)                       # 17: mfa_enabled
    ]

    # Log feature extraction for debugging
    print(f"Prepared feature vector with {len(features)} features")
    print(f"Key features - Severity: {severity_numeric}, IP Rep: {ip_reputation}, "
          f"Ports: {finding.get('source_port', 0)}/{finding.get('destination_port', 0)}, "
          f"MFA: {finding.get('mfa_enabled', 0)}")

    return features

def log_prediction(finding, threat_score, confidence):
    try:
        table_name = os.environ.get('DYNAMODB_TABLE', 'secureguard-ai-findings')
        table = dynamodb.Table(table_name)
        table.put_item(Item={
            'finding_id': finding['finding_id'],
            'timestamp': finding['timestamp'],
            'threat_score': Decimal(str(threat_score)),
            'confidence': Decimal(str(confidence)),
            'severity': finding['severity'],
            'type': finding['type'],
            'account_id': finding['account_id']
        })
    except Exception as e:
        print(f"Error logging to DynamoDB: {e}")


def remediate(finding):
    finding_type = finding['type']
    if 'EC2' in finding_type:
        # Isolate EC2 using custom SSM document
        try:
            instance_id = finding.get('resource', {}).get('instanceId', '')
            if instance_id:
                ssm.start_automation_execution(
                    DocumentName='SecureGuard-IsolateEC2Instance',
                    Parameters={
                        'InstanceId': [instance_id]
                    }
                )
                return "ec2_isolated"
            else:
                print(f"No instance ID found in finding: {finding}")
                return "remediation_failed_no_instance_id"
        except Exception as e:
            print(f"Error isolating EC2 instance: {e}")
            return "remediation_failed_ec2_error"
    elif 'IAM' in finding_type:
        # Revoke IAM Credentials
        try:
            iam = boto3.client('iam')
            username = finding.get('iam_principal', '').split('/')[-1]

            if not username:
                print(f"No IAM username found in finding: {finding}")
                return "remediation_failed_no_username"

            # Delete access keys
            keys = iam.list_access_keys(UserName=username)
            for key in keys['AccessKeyMetadata']:
                iam.delete_access_key(
                    UserName=username,
                    AccessKeyId=key['AccessKeyId']
                )

            # Attach deny policy
            iam.attach_user_policy(
                UserName=username,
                PolicyArn='arn:aws:iam::aws:policy/AWSDenyAll'
            )
            return "iam_credentials_revoked"
        except Exception as e:
            print(f"Error revoking IAM credentials: {e}")
            return "remediation_failed_iam_error"
    else:
        print(f"Remediation required for: {finding_type}")
        return "remediation_not_supported"


def alert_security_team(finding, threat_score):    
    if not SNS_TOPIC:
        print("No SNS topic configured")
        return "alert_skipped"
    
    try:
        message = f""" Security Alert - High Threat Detected

                Threat Score: {threat_score:.1f}/100
                Severity: {finding.get('severity')}
                Type: {finding.get('type')}
                Account: {finding.get('account_id')}
                Source IP: {finding.get('source_ip')}

                Finding ID: {finding.get('finding_id')}
            """
        
        sns.publish(
            TopicArn=SNS_TOPIC,
            Subject='SecureGuard AI - High Threat Alert',
            Message=message
        )
        print("Alert sent via SNS")
        return "alerted"
    except Exception as e:
        print(f"Error sending alert: {e}")
        return "alert_failed"