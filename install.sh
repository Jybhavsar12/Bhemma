#!/bin/bash
# Security Dashboard Installation Script

echo "Installing Security Dashboard..."

# Create directory structure
mkdir -p logs reports threat_feeds backups

# Set permissions
chmod +x security_dashboard.sh
chmod +x start_dashboard.sh

# Install dependencies (Ubuntu/Debian)
if command -v apt &> /dev/null; then
    echo "Installing dependencies for Ubuntu/Debian..."
    sudo apt update
    sudo apt install -y nmap netcat-openbsd curl wget dnsutils whois iptables fail2ban
fi

# Install dependencies (CentOS/RHEL)
if command -v yum &> /dev/null; then
    echo "Installing dependencies for CentOS/RHEL..."
    sudo yum install -y nmap nc curl wget bind-utils whois iptables fail2ban
fi

echo "Installation complete!"
echo "Run with: ./start_dashboard.sh"