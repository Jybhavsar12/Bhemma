#!/bin/bash
# Dashboard startup script

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║                 CYBERSECURITY DASHBOARD                   ║"
echo "║                      Initializing...                     ║"
echo "╚═══════════════════════════════════════════════════════════╝"

# Check if running as root for certain functions
if [[ $EUID -eq 0 ]]; then
    echo "✓ Running with root privileges - full functionality enabled"
else
    echo "⚠ Running as regular user - some features may be limited"
    echo "  (Log monitoring, system hardening, and network tools may require sudo)"
fi

# Check for required tools
echo "Checking dependencies..."
tools=("nmap" "netstat" "ss" "curl" "wget" "dig" "whois")
missing_tools=()

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "✓ $tool found"
    else
        echo "✗ $tool missing"
        missing_tools+=($tool)
    fi
done

if [ ${#missing_tools[@]} -gt 0 ]; then
    echo ""
    echo "Missing tools detected. Install with:"
    echo "Ubuntu/Debian: sudo apt install ${missing_tools[*]}"
    echo "CentOS/RHEL: sudo yum install ${missing_tools[*]}"
    echo "Fedora: sudo dnf install ${missing_tools[*]}"
    echo ""
    read -p "Continue anyway? (y/n): " continue_choice
    if [ "$continue_choice" != "y" ]; then
        exit 1
    fi
fi

# Make dashboard executable
chmod +x security_dashboard.sh

# Create necessary directories
mkdir -p logs reports threat_feeds backups

echo "✓ Initialization complete"
echo ""

# Start the dashboard
./security_dashboard.sh
