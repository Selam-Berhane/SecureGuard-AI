import json
import boto3
import os
from datetime import datetime
import requests


s3 = boto3.client('s3')
iam = boto3.client('iam')

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

    # Extract network features
    network_features = extract_network_features(finding)
    enriched.update(network_features)

    # Extract IAM features
    iam_features = extract_iam_features(finding)
    enriched.update(iam_features)

    # Geographic anomaly detection
    enriched['geo_anomaly'] = detect_geo_anomaly(finding, source_ip)

    # Baseline deviation (simplified for now)
    enriched['baseline_deviation'] = calculate_baseline_deviation(finding)

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


def extract_network_features(finding):
  """
  Extract network-related features from GuardDuty finding.
  Returns dictionary with network metrics.
  """
  features = {
    'source_port': 0,
    'destination_port': 0,
    'bytes_transferred': 0,
    'packets_sent': 0,
    'connection_duration_sec': 0,
    'failed_login_attempts_24h': 0
  }

  try:
    service = finding.get('service', {})
    action = service.get('action', {})

    # Extract from NetworkConnectionAction
    if 'networkConnectionAction' in action:
      net_action = action['networkConnectionAction']

      # Port information
      features['source_port'] = net_action.get('localPortDetails', {}).get('port', 0)
      features['destination_port'] = net_action.get('remotePortDetails', {}).get('port', 0)

      # Connection details (if available in finding)
      connection_details = net_action.get('connectionDetails', {})
      features['bytes_transferred'] = connection_details.get('bytesIn', 0) + connection_details.get('bytesOut', 0)
      features['packets_sent'] = connection_details.get('packetsIn', 0) + connection_details.get('packetsOut', 0)

    # Extract from PortProbeAction (for port scan findings)
    elif 'portProbeAction' in action:
      probe_action = action['portProbeAction']
      port_details = probe_action.get('portProbeDetails', [])
      if port_details:
        # Use first probed port as destination
        features['destination_port'] = port_details[0].get('localPortDetails', {}).get('port', 0)

    # Estimate connection duration from timestamps (if available)
    if 'timestamps' in service:
      timestamps = service['timestamps']
      if len(timestamps) >= 2:
        # GuardDuty may include multiple observation timestamps
        first_seen = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
        last_seen = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
        features['connection_duration_sec'] = int((last_seen - first_seen).total_seconds())

    # For SSH/RDP brute force findings, extract failed login attempts
    finding_type = finding.get('type', '')
    if 'BruteForce' in finding_type or 'UnauthorizedAccess' in finding_type:
      # GuardDuty may include this in additionalInfo
      additional_info = service.get('additionalInfo', {})
      features['failed_login_attempts_24h'] = additional_info.get('failedLoginAttempts', 0)

      # If not available, estimate from event count
      if features['failed_login_attempts_24h'] == 0:
        event_count = service.get('count', 1)
        features['failed_login_attempts_24h'] = event_count

  except Exception as e:
    print(f"Error extracting network features: {e}")

  return features


def extract_iam_features(finding):
  """
  Extract IAM-related features from GuardDuty finding.
  Returns dictionary with IAM metrics.
  """
  features = {
    'iam_principal_age_days': 0,
    'account_age_days': 0,
    'mfa_enabled': 0,
    'previous_incidents_count': 0
  }

  try:
    resource = finding.get('resource', {})

    # Extract IAM principal information
    if 'accessKeyDetails' in resource:
      access_key_details = resource['accessKeyDetails']
      principal_id = access_key_details.get('principalId', '')
      user_name = access_key_details.get('userName', '')

      # Get principal age
      if user_name:
        try:
          user_info = iam.get_user(UserName=user_name)
          create_date = user_info['User']['CreateDate']
          age_days = (datetime.now(create_date.tzinfo) - create_date).days
          features['iam_principal_age_days'] = age_days

          # Check MFA status
          mfa_devices = iam.list_mfa_devices(UserName=user_name)
          features['mfa_enabled'] = 1 if mfa_devices['MFADevices'] else 0

        except iam.exceptions.NoSuchEntityException:
          print(f"IAM user {user_name} not found")
        except Exception as e:
          print(f"Error getting IAM user details: {e}")

    # Get account age
    account_id = finding.get('accountId', '')
    if account_id:
      features['account_age_days'] = get_account_age(account_id)

    # For now, previous_incidents_count remains 0
    # This would require querying DynamoDB historical findings
    # which we'll implement later to avoid circular dependency

  except Exception as e:
    print(f"Error extracting IAM features: {e}")

  return features


def get_account_age(account_id):
  """
  Get AWS account age by checking root user creation time from IAM Credential Report.
  The root user creation time = account creation time.
  """
  try:
    import csv
    import io
    import time

    # Generate credential report (may take a few seconds on first call)
    response = iam.generate_credential_report()
    state = response['State']

    # Wait for report to be ready (usually instant if recently generated)
    max_retries = 3
    for attempt in range(max_retries):
      if state == 'COMPLETE':
        break
      print(f"Credential report not ready, waiting... (attempt {attempt + 1}/{max_retries})")
      time.sleep(1)
      response = iam.generate_credential_report()
      state = response['State']

    # Get the credential report
    report_response = iam.get_credential_report()
    report_content = report_response['Content'].decode('utf-8')

    # Parse CSV content
    csv_reader = csv.DictReader(io.StringIO(report_content))

    # Find root user row
    for row in csv_reader:
      if row['user'] == '<root_account>':
        # Root user creation time = account creation time
        creation_time_str = row['user_creation_time']

        # Parse ISO format: 2019-12-15T10:30:00+00:00
        creation_time = datetime.fromisoformat(creation_time_str.replace('Z', '+00:00'))
        now = datetime.now(creation_time.tzinfo)
        age_days = (now - creation_time).days

        print(f"Account {account_id} created on {creation_time_str}, age: {age_days} days")
        return age_days

    # Root user not found in report (shouldn't happen)
    print(f"Root user not found in credential report for {account_id}")
    return get_account_age_heuristic(account_id)

  except Exception as e:
    print(f"Could not get account age from credential report: {e}")
    return get_account_age_heuristic(account_id)


def get_account_age_heuristic(account_id):
  """
  Estimate account age based on account ID pattern.
  AWS assigns account IDs sequentially, so lower IDs = older accounts.
  """
  account_num = int(account_id) if account_id.isdigit() else 999999999999

  # Rough estimate based on account ID ranges
  if account_num < 100000000000:  # Very old account (< 100B)
    estimated_age = 3650  # ~10 years
  elif account_num < 500000000000:  # Older account (100B-500B)
    estimated_age = 1825  # ~5 years
  elif account_num < 800000000000:  # Medium age (500B-800B)
    estimated_age = 730  # ~2 years
  else:  # Newer account (> 800B)
    estimated_age = 365  # ~1 year

  print(f"Account {account_id} estimated age: {estimated_age} days (heuristic based on ID)")
  return estimated_age


def detect_geo_anomaly(finding, source_ip):
  """
  Detect if source IP is from unexpected geographic location.
  Returns 1 if anomalous, 0 if normal.
  """
  try:
    # Skip for internal IPs
    if source_ip == 'unknown' or source_ip.startswith('10.') or source_ip.startswith('192.168.') or source_ip.startswith('172.'):
      return 0

    service = finding.get('service', {})
    action = service.get('action', {})

    # Extract geographic info from GuardDuty
    remote_ip_details = None
    if 'networkConnectionAction' in action:
      remote_ip_details = action['networkConnectionAction'].get('remoteIpDetails', {})
    elif 'awsApiCallAction' in action:
      remote_ip_details = action['awsApiCallAction'].get('remoteIpDetails', {})

    if remote_ip_details:
      country = remote_ip_details.get('country', {}).get('countryName', '')
      organization = remote_ip_details.get('organization', {})

      # Check for known anomalous indicators
      # 1. High-risk countries (this is a simplified example)
      high_risk_countries = ['Unknown', 'Anonymous Proxy', 'Satellite Provider']
      if country in high_risk_countries:
        return 1

      # 2. Tor exit nodes or VPN providers
      org_name = organization.get('orgName', '').lower()
      suspicious_keywords = ['tor', 'vpn', 'proxy', 'anonymous', 'privacy']
      if any(keyword in org_name for keyword in suspicious_keywords):
        return 1

      # 3. Check if IP is from unexpected ASN
      asn = organization.get('asn', '')
      # Could maintain whitelist of expected ASNs for your organization

    return 0

  except Exception as e:
    print(f"Error detecting geo anomaly: {e}")
    return 0


def calculate_baseline_deviation(finding):
  """
  Calculate statistical deviation from normal behavior baseline.
  For now, uses heuristic based on finding metadata.
  Future: Query historical data for true statistical baseline.
  """
  try:
    severity = finding.get('severity', 'MEDIUM')
    service = finding.get('service', {})

    # Higher deviation for:
    # 1. High severity findings
    # 2. First-time occurrences (count = 1)
    # 3. Unusual times (already captured in hour_of_day)

    deviation = 0.0

    # Severity component
    severity_weight = {'LOW': 0.1, 'MEDIUM': 0.3, 'HIGH': 0.6, 'CRITICAL': 0.9}
    deviation += severity_weight.get(severity, 0.3)

    # Event frequency component
    count = service.get('count', 1)
    if count == 1:
      deviation += 0.3  # First occurrence is more anomalous
    elif count > 10:
      deviation -= 0.2  # Recurring pattern might be false positive

    # Event recency
    event_time = finding.get('updatedAt', finding.get('createdAt', ''))
    if event_time:
      event_dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
      now = datetime.now(event_dt.tzinfo)
      hours_since = (now - event_dt).total_seconds() / 3600

      # Very recent events might be more critical
      if hours_since < 1:
        deviation += 0.1

    # Normalize to 0-1 range
    deviation = max(0.0, min(1.0, deviation))

    return round(deviation, 2)

  except Exception as e:
    print(f"Error calculating baseline deviation: {e}")
    return 0.5  # Default to neutral
