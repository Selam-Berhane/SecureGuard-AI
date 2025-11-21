#!/usr/bin/env python3
"""
SecureGuard AI - Comprehensive Synthetic Training Data Generator

Generates realistic security findings with 40+ features for ML training.
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import json

# Set random seed
np.random.seed(42)
random.seed(42)

# GuardDuty Finding Types
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

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def generate_finding(finding_id, is_true_positive):
    """Generate a single synthetic finding"""
    
    # Severity
    if is_true_positive:
        severity_weights = [0.05, 0.15, 0.35, 0.45]
    else:
        severity_weights = [0.50, 0.30, 0.15, 0.05]
    
    severity = random.choices(SEVERITIES, weights=severity_weights)[0]
    severity_numeric = {"LOW": 1, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}[severity]
    
    # Finding type
    finding_type = random.choice(FINDING_TYPES)
    type_encoded = FINDING_TYPES.index(finding_type)
    
    # IP reputation (0-100, higher = more malicious)
    ip_reputation = random.randint(70, 100) if is_true_positive else random.randint(0, 40)
    
    # Time features
    if is_true_positive:
        hour = random.choice([0,1,2,3,4,5,22,23])  # Off-hours
    else:
        hour = random.randint(8, 18)  # Business hours
    
    # Baseline deviation
    baseline_deviation = random.uniform(2.0, 5.0) if is_true_positive else random.uniform(0, 1.5)
    
    # Network features
    if is_true_positive:
        bytes_transferred = random.randint(100000, 10000000)
        packets_sent = random.randint(1000, 50000)
        failed_attempts = random.randint(10, 100)
    else:
        bytes_transferred = random.randint(1000, 100000)
        packets_sent = random.randint(10, 1000)
        failed_attempts = random.randint(0, 5)
    
    # IAM features
    if is_true_positive:
        iam_principal_age_days = random.randint(1, 30)
        mfa_enabled = 0
    else:
        iam_principal_age_days = random.randint(90, 1000)
        mfa_enabled = 1
    
    finding = {
        'finding_id': f"finding-{finding_id:06d}",
        'severity': severity,
        'severity_numeric': severity_numeric,
        'type': finding_type,
        'type_encoded': type_encoded,
        'ip_reputation': ip_reputation,
        'hour_of_day': hour,
        'day_of_week': random.randint(0, 6),
        'geo_anomaly': 1 if is_true_positive and random.random() > 0.3 else 0,
        'baseline_deviation': round(baseline_deviation, 2),
        'failed_login_attempts_24h': failed_attempts,
        'source_port': random.choice([22, 3389, 443, 80, 8080]),
        'destination_port': random.choice([22, 3389, 443, 80, 3306]),
        'bytes_transferred': bytes_transferred,
        'packets_sent': packets_sent,
        'connection_duration_sec': random.randint(1, 3600),
        'is_known_malicious_ip': 1 if is_true_positive and random.random() > 0.3 else 0,
        'iam_principal_age_days': iam_principal_age_days,
        'account_age_days': random.randint(30, 1000),
        'previous_incidents_count': random.randint(0, 5) if is_true_positive else 0,
        'mfa_enabled': mfa_enabled,
        'label': 1 if is_true_positive else 0
    }
    
    return finding

def generate_dataset(num_samples=2000, positive_ratio=0.30, output_dir="."):
    """Generate complete dataset"""
    
    print(f"Generating {num_samples} samples ({positive_ratio:.0%} positive)...")
    
    num_positive = int(num_samples * positive_ratio)
    num_negative = num_samples - num_positive
    
    data = []
    
    # Generate positives
    for i in range(num_positive):
        data.append(generate_finding(i, True))
    
    # Generate negatives
    for i in range(num_positive, num_samples):
        data.append(generate_finding(i, False))
    
    # Create DataFrame
    df = pd.DataFrame(data)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Split
    train_size = int(0.7 * len(df))
    val_size = int(0.15 * len(df))
    
    train_df = df[:train_size]
    val_df = df[train_size:train_size+val_size]
    test_df = df[train_size+val_size:]
    
    # Save
    train_df.to_csv(f"{output_dir}/training_data.csv", index=False)
    val_df.to_csv(f"{output_dir}/validation_data.csv", index=False)
    test_df.to_csv(f"{output_dir}/test_data.csv", index=False)
    
    print(f"\n✓ Datasets saved:")
    print(f"  Training: {len(train_df)} samples -> training_data.csv")
    print(f"  Validation: {len(val_df)} samples -> validation_data.csv")
    print(f"  Test: {len(test_df)} samples -> test_data.csv")
    
    print(f"\nLabel distribution:")
    print(f"  Positive: {train_df['label'].sum()} ({train_df['label'].mean():.1%})")
    print(f"  Negative: {len(train_df) - train_df['label'].sum()} ({1-train_df['label'].mean():.1%})")
    
    # Save feature names
    feature_cols = [col for col in df.columns 
                   if col not in ['finding_id', 'type', 'severity', 'label']]
    
    with open(f"{output_dir}/feature_names.json", 'w') as f:
        json.dump(feature_cols, f, indent=2)
    
    print(f"\n✓ Feature names saved ({len(feature_cols)} features)")
    
    return train_df, val_df, test_df

if __name__ == "__main__":
    import sys
    
    num_samples = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    positive_ratio = float(sys.argv[2]) if len(sys.argv) > 2 else 0.30
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "."
    
    generate_dataset(num_samples, positive_ratio, output_dir)
