# Scale VPN - AWS EC2 Deployment Guide

**Target Environment:** AWS EC2 (`t2.micro`/`t3.micro`), Ubuntu 24.04 LTS, region `ap-south-1` (Mumbai).

This directory contains the deployment files for the Scale VPN control plane and relay on AWS EC2.

## Deployment Steps

**1. AWS Setup**
- Provision a `t2.micro` or `t3.micro` instance with Ubuntu 24.04.
- Allocate an **Elastic IP** and associate it with your instance.
- Configure the **EC2 Security Group** to allow inbound: TCP 22 (SSH), TCP 8080 (API), TCP 8443 (Relay).

**2. SSH & System Prep**
SSH into the instance using your `.pem` key:
```bash
ssh -i /path/to/your-key.pem ubuntu@<elastic-ip>
```

Install dependencies and set up `ufw` (defense-in-depth):
```bash
sudo apt update && sudo apt install -y postgresql redis-server ufw
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 8443/tcp
sudo ufw enable
```

**3. Copy Files to EC2**
From your local machine, build and `scp` the files over:
```bash
GOOS=linux GOARCH=amd64 go build -o control-plane ./main.go
GOOS=linux GOARCH=amd64 go build -o relay ./cmd/relay
scp -i /path/to/your-key.pem control-plane relay deploy/scale.env deploy/setup_db.sql deploy/*.service ubuntu@<elastic-ip>:/home/ubuntu/
```

**4. Generate TLS Certs for Relay**
On the EC2 instance, generate the self-signed certs in the `ubuntu` home directory:
```bash
openssl req -x509 -newkey rsa:4096 -keyout /home/ubuntu/key.pem -out /home/ubuntu/cert.pem -days 365 -nodes -subj '/CN=localhost'
```

**5. Database Setup**
Execute the setup script on the EC2 instance (assuming you already modified the password inside the file):
```bash
sudo -u postgres psql -f /home/ubuntu/setup_db.sql
```

**6. Systemd Services**
Move the service files and start them:
```bash
sudo mv /home/ubuntu/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scale-control scale-relay
sudo systemctl status scale-control scale-relay
```

**7. Verification**
Run the smoke test from your local machine:
```bash
./deploy/smoke_test.sh <elastic-ip>
```
