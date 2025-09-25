#!/bin/bash

# EC2 Deployment Script for KMS Server
# This script will set up the KMS server on EC2 with HTTPS

set -e

echo "🚀 Deploying KMS Server to EC2"
echo "================================"

# Configuration
EC2_IP="13.51.162.183"
EC2_USER="ec2-user"
DOMAIN="nuri-kms.regular-jointly-cheetah.ngrok-free.app"

echo "📦 Step 1: Upload deployment package"
echo "Please manually upload kms-server-deploy.tar.gz to the EC2 instance"
echo ""
echo "Since SSH is not working, you can:"
echo "1. Use AWS S3 to transfer the file:"
echo "   aws s3 cp kms-server-deploy.tar.gz s3://your-bucket/"
echo "   Then on EC2: aws s3 cp s3://your-bucket/kms-server-deploy.tar.gz ."
echo ""
echo "2. Or use EC2 user data to run commands on the instance"
echo ""

echo "📝 Step 2: Commands to run on EC2 (manually or via user data):"
cat << 'EOF'

# Install Node.js v22
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo yum install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2

# Extract deployment package
tar -xzf kms-server-deploy.tar.gz
cd server-prf-kms
npm install

# Install and configure nginx for HTTPS
sudo amazon-linux-extras install -y nginx1
sudo systemctl enable nginx
sudo systemctl start nginx

# Install Certbot for Let's Encrypt
sudo yum install -y certbot python3-certbot-nginx

# Configure nginx (create /etc/nginx/conf.d/kms-server.conf)
sudo tee /etc/nginx/conf.d/kms-server.conf > /dev/null << 'NGINX'
server {
    listen 80;
    server_name 13.51.162.183;

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

# Restart nginx
sudo systemctl restart nginx

# Get SSL certificate (for production)
# sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@example.com

# Create PM2 ecosystem file
cat > ecosystem.config.js << 'PM2'
module.exports = {
  apps: [{
    name: 'kms-server',
    script: 'server-prf-kms.js',
    cwd: '/home/ec2-user/server-prf-kms',
    env: {
      PORT: 1337,
      NODE_ENV: 'production',
      AWS_REGION: 'eu-north-1',
      KMS_KEY_ID: '46ae12a8-7002-46ef-b469-d8eefc8942cd'
    }
  }]
};
PM2

# Start server with PM2
pm2 start ecosystem.config.js
pm2 save
pm2 startup systemd -u ec2-user --hp /home/ec2-user

# Test the server
curl http://localhost:1337/health

echo "✅ Server deployed successfully!"
echo "Access at: http://13.51.162.183"

EOF

echo ""
echo "📌 Important Notes:"
echo "1. Ensure the instance role has kms:GenerateMac permission on the target key"
echo "2. Attach the IAM role NuriPRFSignerProfile (or similar least-privileged role)"
echo "3. For HTTPS, point a domain to the EC2 IP and run certbot"
echo "4. The server will run on port 1337 behind nginx on port 80/443"
