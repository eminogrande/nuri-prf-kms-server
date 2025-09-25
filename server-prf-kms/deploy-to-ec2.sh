#!/bin/bash
# Deploy script for EC2 instance
# This script should be run on the EC2 instance

set -e

echo "🚀 Deploying Nuri PRF KMS Server to EC2"

# Update system
echo "📦 Updating system packages..."
sudo yum update -y

# Install Node.js 22 (latest LTS)
echo "📦 Installing Node.js 22..."
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo yum install -y nodejs git

# Verify Node version
node_version=$(node --version)
echo "✅ Node.js installed: $node_version"

# Create app directory
echo "📁 Setting up application directory..."
cd /home/ec2-user
mkdir -p nuri-prf-kms

# Copy server files (you'll need to upload these via SCP or S3)
cd nuri-prf-kms

# Create package.json
cat > package.json << 'EOF'
{
  "name": "nuri-prf-kms-server",
  "version": "1.0.0",
  "type": "module",
  "dependencies": {
    "@aws-sdk/client-kms": "^3.0.0",
    "@noble/ciphers": "^2.0.0",
    "@noble/curves": "^2.0.0",
    "@noble/hashes": "^2.0.1",
    "@scure/base": "^2.0.0",
    "@scure/btc-signer": "^2.0.1",
    "base64url": "^3.0.1",
    "cors": "^2.8.5",
    "express": "^5.1.0",
    "uuid": "^13.0.0"
  }
}
EOF

# Install dependencies
echo "📦 Installing dependencies..."
npm install --production

# Create production environment file
cat > .env << EOF
PORT=1337
NODE_ENV=production
AWS_REGION=us-east-1
KMS_KEY_ID=46ae12a8-7002-46ef-b469-d8eefc8942cd
EOF

# Create systemd service
echo "⚙️ Creating systemd service..."
sudo tee /etc/systemd/system/nuri-prf-kms.service > /dev/null << EOF
[Unit]
Description=Nuri PRF KMS Server
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/nuri-prf-kms
Environment="NODE_ENV=production"
Environment="AWS_REGION=us-east-1"
ExecStart=/usr/bin/node server-prf-kms.js
Restart=always
RestartSec=10
StandardOutput=append:/var/log/nuri-prf-kms.log
StandardError=append:/var/log/nuri-prf-kms-error.log

[Install]
WantedBy=multi-user.target
EOF

# Create log files
sudo touch /var/log/nuri-prf-kms.log
sudo touch /var/log/nuri-prf-kms-error.log
sudo chown ec2-user:ec2-user /var/log/nuri-prf-kms*.log

# Enable and start service
echo "🚀 Starting service..."
sudo systemctl daemon-reload
sudo systemctl enable nuri-prf-kms
sudo systemctl start nuri-prf-kms

# Check status
sleep 3
if sudo systemctl is-active --quiet nuri-prf-kms; then
    echo "✅ Nuri PRF KMS Server is running!"
    echo ""
    echo "📍 Server endpoints:"
    echo "   http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):1337"
    echo ""
    echo "📋 Check logs:"
    echo "   sudo journalctl -u nuri-prf-kms -f"
    echo "   tail -f /var/log/nuri-prf-kms.log"
else
    echo "❌ Service failed to start. Check logs:"
    sudo journalctl -u nuri-prf-kms -n 50
fi
