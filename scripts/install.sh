#!/bin/bash

# Network Scanner Installation Script
# This script sets up Network Scanner on Ubuntu/Debian systems

set -e

echo "🛡️  Network Scanner Installation Script"
echo "======================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install system dependencies
print_status "Installing system dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    nmap \
    dnsutils \
    whois \
    git \
    curl \
    wget \
    redis-server

# Install Python dependencies
print_status "Setting up Python virtual environment..."
cd /workspaces/Network-Scanner/backend
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Install Node.js dependencies
print_status "Installing Node.js dependencies..."
cd /workspaces/Network-Scanner/frontend
npm install

# Install CLI dependencies
print_status "Setting up CLI..."
cd /workspaces/Network-Scanner/cli
pip3 install -r requirements.txt
chmod +x network_scanner_cli.py
sudo ln -sf $(pwd)/network_scanner_cli.py /usr/local/bin/network-scanner-cli

# Create necessary directories
print_status "Creating directories..."
mkdir -p /workspaces/Network-Scanner/reports
mkdir -p /workspaces/Network-Scanner/logs

# Set up environment file
if [ ! -f /workspaces/Network-Scanner/.env ]; then
    print_status "Creating environment configuration..."
    cp /workspaces/Network-Scanner/.env.example /workspaces/Network-Scanner/.env
    print_warning "Please edit .env file with your configuration"
fi

# Set up systemd services (optional)
setup_services() {
    print_status "Setting up systemd services..."

    # Backend service
    sudo tee /etc/systemd/system/network-scanner-backend.service > /dev/null <<EOF
[Unit]
Description=Network Scanner Backend API
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/workspaces/Network-Scanner/backend
Environment=PATH=/workspaces/Network-Scanner/backend/venv/bin
ExecStart=/workspaces/Network-Scanner/backend/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start services
    sudo systemctl daemon-reload
    sudo systemctl enable network-scanner-backend

    print_success "Systemd services configured"
}

# Start Redis server
print_status "Starting Redis server..."
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Build frontend
print_status "Building frontend..."
cd /workspaces/Network-Scanner/frontend
npm run build

# Make scripts executable
chmod +x /workspaces/Network-Scanner/scripts/*

print_success "Installation completed!"
echo ""
echo "🚀 Quick Start:"
echo "  1. Edit .env file with your configuration"
echo "  2. Start backend: cd backend && source venv/bin/activate && python app.py"
echo "  3. Start frontend: cd frontend && npm start"
echo "  4. CLI usage: network-scanner --help"
echo ""
echo "📚 Documentation: https://github.com/frangelbarrera/Network-Scanner"
echo "🐛 Issues: https://github.com/frangelbarrera/Network-Scanner/issues"
