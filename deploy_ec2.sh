#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "===================================================="
echo "Starting EC2 Deployment Setup for Vuln Web App"
echo "===================================================="

# 1. Update system packages
echo "[1/5] Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# 2. Install prerequisites
echo "[2/5] Installing prerequisite packages..."
sudo apt-get install -y ca-certificates curl gnupg lsb-release git

# 3. Install Docker and Docker Compose
echo "[3/5] Installing Docker and Docker Compose..."
# Check if docker command exists
if ! command -v docker &> /dev/null; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    sudo apt-get update -y
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
    echo "Docker is already installed."
fi

# Add current user to docker group to run docker without sudo next time
if ! groups $USER | grep &>/dev/null '\bdocker\b'; then
    echo "Adding $USER to the docker group..."
    sudo usermod -aG docker $USER
fi

# 4. Check for project files
echo "[4/5] Checking project files..."
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: docker-compose.yml not found in the current directory!"
    echo "Please run this script from the root directory of the cloned repository."
    exit 1
fi

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        echo "Creating .env file from .env.example..."
        cp .env.example .env
        # Generate a random string for SECRET_KEY
        RANDOM_KEY=$(openssl rand -hex 32)
        sed -i "s/SECRET_KEY=.*/SECRET_KEY=$RANDOM_KEY/" .env
        echo "Generated custom SECRET_KEY in .env"
    else
        echo "Warning: .env.example not found. Creating a blank .env..."
        touch .env
    fi
fi

# 5. Build and run containers
echo "[5/5] Launching applications via Docker Compose..."
# Ensure security logs and db exist so they have correct volume permissions
touch security_audit.log
touch vulnerable_app.db

# Run using the new docker compose plugin command
sudo docker compose up -d --build

echo "===================================================="
echo "Deployment Complete!"
echo "The application is running in the background."
echo "Access it at: http://<EC2-PUBLIC-IP>:3001"
echo "Note: If you cannot access it, ensure Port 3001 is open"
echo "in your EC2 instance's Security Group settings."
echo "===================================================="
