# KMS Server Deployment Notes

## EC2 Instance Details
- **Instance ID**: i-0ce2bfbc278566abb
- **Name**: nuri-prf-kms-server
- **IP Address**: 13.51.162.183
- **Region**: eu-north-1 (Stockholm)
- **IAM Role**: NuriPRFSignerProfile (already attached)

## KMS Resources
- **KMS Key ID**: 07daf2a3-aa06-4600-934f-72ec2fcb4ff0
- **KMS Key ARN**: arn:aws:kms:eu-north-1:239339588543:key/07daf2a3-aa06-4600-934f-72ec2fcb4ff0
- **Secret Name**: nuri-master-secret
- **Secret ARN**: arn:aws:secretsmanager:eu-north-1:239339588543:secret:nuri-master-secret-8zV7DF

## Current Status
- ✅ Local KMS server working with real AWS KMS
- ✅ Compatible mode (SHA256) confirmed working
- ✅ Deployment package uploaded to S3
- 🔄 EC2 instance needs SSH access setup
- 📌 Ready for deployment via EC2 user data

## Key Differences
- **Compatible Mode** (for local testing): Uses SHA256, same keys as original
- **Secure Mode** (for production): Uses HMAC with KMS master key, different keys

## URLs
- Local: http://localhost:1337
- Production: https://13.51.162.183 (need SSL)
- Ngrok: https://regular-jointly-cheetah.ngrok-free.app