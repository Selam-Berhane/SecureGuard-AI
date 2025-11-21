import json
import boto3
import os
from datetime import datetime
import requests


s3 = boto3.client('s3')
BUCKET = os.environ.get('BUCKET_NAME', 'secureguard-ai-datalake')

def lambda_handler(event, context=''):
    print("Received event:", json.dumps(event))
    finding = event.get('detail', {})
    finding_id = finding.get('id', 'unknown')
    enriched = {
        'finding_id' : finding_id,
        'severity' : finding.get('severity', "UNKNOWN"),
        'type' : finding.get('type' , 'UNKNOWN'),
        'timestamp' : finding.get('updatedAt', datetime.now().isoformat()),
        'account_id' : finding.get('accountId', ''),
        'region' : finding.get('region' , ''),
        'resource' : finding.get('resource' , '')

    }
    #extract sourcip
    source_ip = extract_source_ip(finding)
    enriched['source_ip']  = source_ip
    enriched['ip_reputation'] = get_ip_reputation(source_ip)
    now = datetime.now()
    enriched['hour_of_day'] = now.hour
    enriched['day_of_week'] = now.weekday()
    #calculate baseline deviation (simpleified)
    enriched['baseline_deviation'] = 0.5  #placeholder

    try:
      key = f"raw-findings/year={now.year}/month={now.month:02d}/day={now.day:02d}/{finding_id}.json"
      s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(enriched),
        ServerSideEncryption='aws:kms'
      )
      print(f"Stored finding to {key}")
    except Exception as e:
      print(f"Error storing to s3: {e}")

      # Invoke orchestrator
    lambda_client = boto3.client('lambda')
    try:
      lambda_client.invoke(
          FunctionName='secureguard-orchestrator',
          InvocationType='Event',
          Payload=json.dumps(enriched)
        )
      print("Invoked orchestrator")
    except Exception as e:
        print(f"Error invoking orchestrator: {e}")

    return {'statusCode': 200, 'body': json.dumps('Success')}


def extract_source_ip(detail):
  """Extract source IP from finding"""
  try:
    service = detail.get('service', {})
    action = service.get('action', {})

    if 'networkConnectionAction' in action:
      remote_ip = action['networkConnectionAction'].get('remoteIpDetails', {})
      return remote_ip.get('ipAddressV4', 'unknown')

    if 'awsApiCallAction' in action:
      remote_ip = action['awsApiCallAction'].get('remoteIpDetails', {})
      return remote_ip.get('ipAddressV4', 'unknown')

  except Exception as e:
    print(f"Error extracting IP: {e}")

  return 'unknown'


def get_ip_reputation(source_ip):
  """
  Check IP reputation using AbuseIPDB API.
  Returns abuse confidence score: 0-100 (0=clean, 100=highly abusive)
  """
  if source_ip == 'unknown':
    return 0

  # Check if IP is in private range
  if source_ip.startswith('10.') or source_ip.startswith('192.168.') or source_ip.startswith('172.'):
      return 10  # Low risk - internal IP

  # Get API key from environment variable
  api_key = os.environ.get('ABUSEIPDB_API_KEY')

  if not api_key:
    # Fallback to demo logic if no API key configured
    print("Warning: ABUSEIPDB_API_KEY not set, using fallback logic")
    hash_value = sum(ord(c) for c in source_ip)
    return (hash_value % 100)

  try:
    response = requests.get(
      f"https://api.abuseipdb.com/api/v2/check",
      headers={
        'Key': api_key,
        'Accept': 'application/json'
      },
      params={
        'ipAddress': source_ip,
        'maxAgeInDays': '90'  # Check reports from last 90 days
      },
      timeout=5  # 5 second timeout
    )

    if response.status_code == 200:
      data = response.json()
      # Return the abuse confidence score (0-100)
      score = data.get('data', {}).get('abuseConfidenceScore', 0)
      print(f"IP {source_ip} reputation score: {score}")
      return score
    else:
      print(f"AbuseIPDB API error: {response.status_code} - {response.text}")
      return 50  # Return neutral score on error

  except requests.exceptions.Timeout:
    print(f"Timeout checking IP reputation for {source_ip}")
    return 50
  except Exception as e:
    print(f"Error checking IP reputation: {e}")
    return 50  # Return neutral score on error
