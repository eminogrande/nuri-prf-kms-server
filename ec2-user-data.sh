#!/bin/bash
# EC2 User Data Script for KMS Server Deployment

exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "Starting KMS Server deployment..."

# Install Node.js v22
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo yum install -y nodejs git

# Install PM2
sudo npm install -g pm2

# Download deployment package from S3
cd /home/ec2-user
aws s3 cp s3://nuri-prf-kms-deployment/kms-server-deploy.tar.gz . --region eu-north-1
tar -xzf kms-server-deploy.tar.gz

# Install dependencies
cd /home/ec2-user
npm install

# Create PM2 ecosystem file
cat > ecosystem.config.js << 'EOF'
module.exports = {
  apps: [{
    name: 'kms-server',
    script: 'server-prf-kms/server-prf-kms.js',
    cwd: '/home/ec2-user',
    env: {
      PORT: 1337,
      NODE_ENV: 'production',
      AWS_REGION: 'eu-north-1',
      KMS_KEY_ID: '07daf2a3-aa06-4600-934f-72ec2fcb4ff0'
    }
  }]
};
EOF

# Start server with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup systemd -u ec2-user --hp /home/ec2-user | tail -n1 | bash

# Install and configure nginx
sudo amazon-linux-extras install -y nginx1
sudo tee /etc/nginx/conf.d/kms-server.conf > /dev/null << 'NGINX'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://localhost:1337;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
NGINX

sudo systemctl enable nginx
sudo systemctl start nginx

echo "Deployment complete!"
curl http://localhost:1337/health
