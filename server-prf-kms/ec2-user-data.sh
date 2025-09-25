#!/bin/bash
# EC2 User Data Script for Nuri PRF KMS Server

# Update system
yum update -y

# Install Node.js 18
curl -sL https://rpm.nodesource.com/setup_18.x | sudo bash -
yum install -y nodejs git

# Clone repository (replace with your actual repo)
cd /home/ec2-user
git clone https://github.com/your-repo/nuri-prf-kms.git || {
    # If no repo, create the server files directly
    mkdir -p nuri-prf-kms
    cd nuri-prf-kms

    # Download files from S3 or create inline
    # For now, we'll need to manually deploy
}

cd nuri-prf-kms

# Install dependencies
npm install --production

# Create environment file
cat > .env << EOF
PORT=1337
NODE_ENV=production
AWS_REGION=us-east-1
KMS_KEY_ID=46ae12a8-7002-46ef-b469-d8eefc8942cd
EOF

# Create systemd service
sudo cat > /etc/systemd/system/nuri-prf-kms.service << EOF
[Unit]
Description=Nuri PRF KMS Server
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/nuri-prf-kms
ExecStart=/usr/bin/node server-prf-kms.js
Restart=on-failure
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reload
sudo systemctl enable nuri-prf-kms
sudo systemctl start nuri-prf-kms

echo "Nuri PRF KMS Server deployed!"
