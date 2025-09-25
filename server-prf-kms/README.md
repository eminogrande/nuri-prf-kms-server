# Nuri PRF KMS Server

A secure WebAuthn PRF co-signing server using AWS KMS for master key protection.

## Features

- ✅ AWS KMS (HMAC_256) for master key protection
- ✅ PRF alone cannot derive keys (requires KMS access)
- ✅ MuSig2 multi-signature support
- ✅ WebAuthn PRF integration
- ✅ Sealed box encryption for app communication
- ✅ Built-in `/audit` dashboard for live KMS events

## Security Model

1. **HMAC Key**: Materialised only inside AWS KMS (HMAC_256 key)
2. **Key Derivation**: `GenerateMac` with PRF + context + wallet identifier
3. **Access Control**: IAM policies restrict the KMS key to this service
4. **Audit Trail**: KMS usage visible via CloudTrail/CloudWatch metrics
5. **Key Isolation**: Private keys are derived on-demand and immediately wiped

## Quick Start (Local Development)

### 1. Install dependencies
```bash
npm install
```

### 2. Set up environment variables
```bash
cp .env.example .env
# Edit .env with your AWS region, KMS key ID, and credentials (if not using an instance role)
```

### 3. Run locally against AWS KMS
```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... npm run dev
```

The server requires AWS KMS; there is no local fallback.

## AWS Deployment

### Prerequisites

1. AWS Account with appropriate permissions
2. AWS CLI configured
3. Node.js 18+ installed

### Step 1: Create KMS Key

```bash
# Replace ACCOUNT_ID in deployment/aws-kms-policy.json with your AWS account ID
aws kms create-key \
  --description "Nuri PRF Signer Master Key" \
  --key-usage GENERATE_VERIFY_MAC \
  --key-spec HMAC_256 \
  --policy file://deployment/aws-kms-policy.json
```

Save the `KeyId` from the response.

### Step 2: Create IAM Role

```bash
# Create the role
aws iam create-role \
  --role-name NuriPRFSignerRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]},
      "Action": "sts:AssumeRole"
    }]
  }'

# Attach the policy
aws iam put-role-policy \
  --role-name NuriPRFSignerRole \
  --policy-name NuriPRFSignerPolicy \
  --policy-document file://deployment/iam-role-policy.json
```

### Step 3: Configure Environment

Create production `.env`:
```bash
PORT=1337
NODE_ENV=production
AWS_REGION=us-east-1
KMS_KEY_ID=<your-kms-key-id>
```

### Step 4: Deploy to AWS

#### Option A: EC2 Deployment

```bash
# On your EC2 instance:
git clone <your-repo>
cd server-prf-kms
npm install --production
npm start
```

#### Option B: Lambda Deployment

1. Create deployment package:
```bash
zip -r function.zip . -x "*.git*" -x "deployment/*"
```

2. Create Lambda function with the IAM role created above

#### Option C: ECS/Fargate Deployment

1. Build Docker image:
```bash
docker build -t nuri-prf-kms .
```

2. Push to ECR and deploy via ECS

## API Endpoints

### GET /setup
WebAuthn PRF setup page for wallet creation.

### POST /sign-with-prf
Create MuSig2 partial signature.

Required parameters:
- `wallet_id`: Wallet identifier
- `prf`: PRF value from WebAuthn
- `msg32`: 32-byte message to sign (hex)
- `client_pk33`: Client's public key (33 bytes, hex)
- `client_pub_nonce`: Client's public nonces (66 bytes, hex)

Optional:
- `tweak32`: Taproot tweak (32 bytes, hex)
- `pk_app`: App's X25519 public key for response encryption

## Testing

### Security Test
```bash
npm test
```

This verifies that:
- PRF alone cannot derive keys
- Master key is required for key derivation
- Keys are properly isolated

### Manual Testing
```bash
# Start server
npm run dev

# Test setup endpoint
curl http://localhost:1337/setup?wallet_id=test123

# Test signing (requires valid parameters)
curl -X POST http://localhost:1337/sign-with-prf \
  -H "Content-Type: application/json" \
  -d '{...}'
```

## Monitoring

### CloudWatch Logs
All operations are logged to CloudWatch when deployed on AWS.

### Attested Logs
The server produces cryptographically attested logs for audit purposes:
```json
{
  "type": "kms.attestedLog",
  "timestamp": "2024-01-01T00:00:00Z",
  "event": "kms.deriveKeyInKMS",
  "payload": {...},
  "mac": "...",
  "kmsMode": true
}
```

## Security Considerations

1. **Never expose HMAC key**: The HMAC_256 key never leaves AWS KMS
2. **Use IAM roles**: Don't use long-lived AWS credentials
3. **Enable CloudTrail**: Audit all KMS operations
4. **Rotate keys regularly**: Use AWS KMS key rotation features
5. **Restrict network access**: Use VPC endpoints for KMS
6. **Monitor for anomalies**: Set up CloudWatch alarms for unusual activity

## Local Development vs Production

| Feature | Local (Simulation) | Production (KMS) |
|---------|-------------------|------------------|
| Master Key | n/a (simulation removed) | AWS KMS (HMAC_256 key) |
| HMAC Operations | n/a | AWS KMS (`GenerateMac`) |
| Key Protection | n/a | Hardware security |
| Audit Logging | n/a | CloudTrail |
| Cost | n/a | Pay per API call |

## Troubleshooting

### "KMS key not found"
- Verify KMS_KEY_ID is correct
- Check IAM permissions
- Ensure key is in the correct region

### "Cannot derive keys in simulation"
- This build no longer supports simulation. Run against AWS KMS with valid credentials.

### "Access denied to KMS"
- Check IAM role/user grants `kms:GenerateMac`
- Verify the key policy allows this principal

## License

MIT
- Visit `/audit` to view live attested logs. `/audit/logs` returns the same data as JSON for custom tooling.
