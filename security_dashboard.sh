#!/bin/bash

# Colors for better UI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
LOG_DIR="./logs"
REPORT_DIR="./reports"
CONFIG_FILE="./dashboard.conf"
THREAT_FEEDS_DIR="./threat_feeds"
BACKUP_DIR="./backups"

# Create directories
mkdir -p $LOG_DIR $REPORT_DIR $THREAT_FEEDS_DIR $BACKUP_DIR

# Load configuration
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source $CONFIG_FILE
    else
        # Create default config
        cat > $CONFIG_FILE << EOF
DEFAULT_TARGET="192.168.1.0/24"
ALERT_EMAIL="admin@company.com"
REPORT_RETENTION_DAYS=30
SCAN_THREADS=10
LOG_LEVEL="INFO"
AUTO_BLOCK_THRESHOLD=5
SMTP_SERVER="localhost"
SMTP_PORT=587
ENABLE_AUTO_BLOCK=true
ENABLE_EMAIL_ALERTS=false
EOF
        source $CONFIG_FILE
    fi
}

# Logging function
log_event() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> $LOG_DIR/dashboard.log
    if [ "$LOG_LEVEL" = "DEBUG" ] || [ "$level" = "ERROR" ] || [ "$level" = "ALERT" ]; then
        echo -e "${CYAN}[LOG]${NC} $message"
    fi
}

# Email alert function
send_alert() {
    local subject=$1
    local message=$2
    if [ "$ENABLE_EMAIL_ALERTS" = "true" ]; then
        echo "$message" | mail -s "$subject" $ALERT_EMAIL
        log_event "INFO" "Alert sent to $ALERT_EMAIL: $subject"
    fi
}

# Banner
show_banner() {
    clear
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║  ██████  ██   ██ ███████ ███    ███ ███    ███  █████     ║"
    echo "║  ██   ██ ██   ██ ██      ████  ████ ████  ████ ██   ██    ║"
    echo "║  ██████  ███████ █████   ██ ████ ██ ██ ████ ██ ███████    ║"
    echo "║  ██   ██ ██   ██ ██      ██  ██  ██ ██  ██  ██ ██   ██    ║"
    echo "║  ██████  ██   ██ ███████ ██      ██ ██      ██ ██   ██    ║"
    echo "║                                                           ║"
    echo "║              Security Dashboard v2.0                     ║"
    echo "║                  $(date '+%Y-%m-%d %H:%M:%S')                  ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# System status check
system_status() {
    echo -e "${CYAN}[INFO]${NC} Checking system status..."
    
    # Check if tools are installed
    tools=("nmap" "netstat" "ss" "iptables" "fail2ban-client" "curl" "wget" "dig" "whois")
    missing_tools=()
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null; then
            echo -e "${GREEN}✓${NC} $tool installed"
        else
            echo -e "${RED}✗${NC} $tool missing"
            missing_tools+=($tool)
        fi
    done
    
    # System resources
    echo -e "\n${YELLOW}System Resources:${NC}"
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    mem_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
    disk_usage=$(df -h / | awk 'NR==2{printf "%s", $5}' | sed 's/%//')
    
    echo "CPU: ${cpu_usage}% used"
    echo "Memory: ${mem_usage}% used"
    echo "Disk: ${disk_usage}% used"
    
    # Alert on high resource usage
    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        echo -e "${RED}[WARNING]${NC} High CPU usage detected!"
        send_alert "High CPU Usage Alert" "CPU usage is at ${cpu_usage}%"
    fi
    
    if (( $(echo "$mem_usage > 85" | bc -l) )); then
        echo -e "${RED}[WARNING]${NC} High memory usage detected!"
        send_alert "High Memory Usage Alert" "Memory usage is at ${mem_usage}%"
    fi
    
    # Network interfaces
    echo -e "\n${YELLOW}Network Interfaces:${NC}"
    ip addr show | grep -E "^[0-9]|inet " | awk '/^[0-9]/ {iface=$2} /inet / {print iface, $2}'
}

# Main menu
main_menu() {
    load_config
    show_banner
    system_status
    
    echo -e "\n${PURPLE}═══════════════ MAIN MENU ═══════════════${NC}"
    echo -e "${GREEN}1)${NC} Network Security Scanner"
    echo -e "${GREEN}2)${NC} Log Analysis & Monitoring" 
    echo -e "${GREEN}3)${NC} Penetration Testing Suite"
    echo -e "${GREEN}4)${NC} Threat Intelligence"
    echo -e "${GREEN}5)${NC} System Hardening"
    echo -e "${GREEN}6)${NC} Incident Response"
    echo -e "${GREEN}7)${NC} Reports & Analytics"
    echo -e "${GREEN}8)${NC} Configuration"
    echo -e "${RED}9)${NC} Exit"
    echo -e "${PURPLE}═══════════════════════════════════════════${NC}"
    
    read -p "Select option [1-9]: " choice
    
    case $choice in
        1) network_menu ;;
        2) log_menu ;;
        3) pentest_menu ;;
        4) threat_intel_menu ;;
        5) hardening_menu ;;
        6) incident_menu ;;
        7) reports_menu ;;
        8) config_menu ;;
        9) exit_dashboard ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 2; main_menu ;;
    esac
}

# Network Security Menu
network_menu() {
    clear
    echo -e "${BLUE}═══════════ NETWORK SECURITY ═══════════${NC}"
    echo "1) Quick Network Scan"
    echo "2) Deep Port Scan"
    echo "3) Vulnerability Scan"
    echo "4) SSL/TLS Analysis"
    echo "5) Network Monitoring"
    echo "6) Stealth Scan"
    echo "7) Service Detection"
    echo "8) Back to Main Menu"
    
    read -p "Select: " net_choice
    
    case $net_choice in
        1) quick_scan ;;
        2) deep_scan ;;
        3) vuln_scan ;;
        4) ssl_scan ;;
        5) network_monitor ;;
        6) stealth_scan ;;
        7) service_detection ;;
        8) main_menu ;;
        *) echo "Invalid option!"; sleep 2; network_menu ;;
    esac
}

# Quick network scan
quick_scan() {
    read -p "Enter target IP/range [$DEFAULT_TARGET]: " target
    target=${target:-$DEFAULT_TARGET}
    
    echo -e "${YELLOW}[SCANNING]${NC} Quick scan of $target..."
    log_event "INFO" "Starting quick scan of $target"
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/quick_scan_$timestamp.txt"
    
    {
        echo "Quick Network Scan Report"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "Scan Type: Quick Discovery + Fast Port Scan"
        echo "================================"
        echo "Host Discovery:"
        nmap -sn $target
        echo -e "\nFast Port Scan:"
        nmap -F --open $target
        echo "================================"
        echo "Scan completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    log_event "INFO" "Quick scan completed for $target"
    read -p "Press Enter to continue..."
    network_menu
}

# Deep port scan
deep_scan() {
    read -p "Enter target IP: " target
    read -p "Enter port range (1-65535): " ports
    ports=${ports:-1-65535}
    
    echo -e "${YELLOW}[SCANNING]${NC} Deep port scan of $target:$ports..."
    log_event "INFO" "Starting deep scan of $target:$ports"
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/deep_scan_$timestamp.txt"
    
    {
        echo "Deep Port Scan Report"
        echo "Target: $target"
        echo "Ports: $ports"
        echo "Date: $(date)"
        echo "================================"
        nmap -sS -sV -O -p $ports --open $target
        echo "================================"
        echo "Scan completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    log_event "INFO" "Deep scan completed for $target"
    read -p "Press Enter to continue..."
    network_menu
}

# Vulnerability scan
vuln_scan() {
    read -p "Enter target IP: " target
    
    echo -e "${YELLOW}[SCANNING]${NC} Vulnerability scan of $target..."
    log_event "INFO" "Starting vulnerability scan of $target"
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/vuln_scan_$timestamp.txt"
    
    {
        echo "Vulnerability Scan Report"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "================================"
        nmap --script vuln $target
        echo -e "\nAdditional vulnerability checks:"
        nmap --script "auth,default,discovery,external,intrusive,malware,safe,version,vuln" $target
        echo "================================"
        echo "Scan completed at $(date)"
    } | tee $output_file
    
    # Check for critical vulnerabilities
    if grep -q "VULNERABLE" $output_file; then
        echo -e "${RED}[ALERT]${NC} Critical vulnerabilities found!"
        send_alert "Critical Vulnerabilities Detected" "Vulnerabilities found on $target. Check report: $output_file"
    fi
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    log_event "INFO" "Vulnerability scan completed for $target"
    read -p "Press Enter to continue..."
    network_menu
}

# SSL/TLS Analysis
ssl_scan() {
    read -p "Enter target domain/IP: " target
    read -p "Enter port (443): " port
    port=${port:-443}
    
    echo -e "${YELLOW}[ANALYZING]${NC} SSL/TLS configuration of $target:$port..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/ssl_scan_$timestamp.txt"
    
    {
        echo "SSL/TLS Analysis Report"
        echo "Target: $target:$port"
        echo "Date: $(date)"
        echo "================================"
        
        # Certificate information
        echo "Certificate Information:"
        echo | openssl s_client -connect $target:$port -servername $target 2>/dev/null | openssl x509 -noout -text
        
        echo -e "\nSupported Ciphers:"
        nmap --script ssl-enum-ciphers -p $port $target
        
        echo -e "\nSSL Vulnerabilities:"
        nmap --script ssl-* -p $port $target
        
        echo "================================"
        echo "Analysis completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    network_menu
}

# Network monitoring
network_monitor() {
    echo -e "${YELLOW}[MONITORING]${NC} Real-time network monitoring (Ctrl+C to stop)..."
    
    # Monitor network connections
    watch -n 2 'echo "Active Connections:"; netstat -tuln | head -20; echo ""; echo "Top Network Processes:"; ss -tuln | head -10'
}

# Stealth scan
stealth_scan() {
    read -p "Enter target IP: " target
    
    echo -e "${YELLOW}[SCANNING]${NC} Stealth scan of $target..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/stealth_scan_$timestamp.txt"
    
    {
        echo "Stealth Scan Report"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "================================"
        # Stealth SYN scan with timing evasion
        nmap -sS -T2 --randomize-hosts --spoof-mac 0 --data-length 25 $target
        echo "================================"
        echo "Scan completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    network_menu
}

# Service detection
service_detection() {
    read -p "Enter target IP: " target
    
    echo -e "${YELLOW}[DETECTING]${NC} Service detection on $target..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/service_detection_$timestamp.txt"
    
    {
        echo "Service Detection Report"
        echo "Target: $target"
        echo "Date: $(date)"
        echo "================================"
        nmap -sV --version-intensity 9 $target
        echo -e "\nOS Detection:"
        nmap -O $target
        echo "================================"
        echo "Detection completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    network_menu
}

# Log Analysis Menu
log_menu() {
    clear
    echo -e "${BLUE}═══════════ LOG ANALYSIS ═══════════${NC}"
    echo "1) Real-time Auth Log Monitor"
    echo "2) Failed Login Analysis"
    echo "3) Network Connection Monitor"
    echo "4) System Log Analysis"
    echo "5) Generate Log Report"
    echo "6) Suspicious Activity Detection"
    echo "7) Log File Integrity Check"
    echo "8) Back to Main Menu"
    
    read -p "Select: " log_choice
    
    case $log_choice in
        1) realtime_monitor ;;
        2) failed_login_analysis ;;
        3) connection_monitor ;;
        4) system_log_analysis ;;
        5) log_report ;;
        6) suspicious_activity ;;
        7) log_integrity_check ;;
        8) main_menu ;;
        *) echo "Invalid option!"; sleep 2; log_menu ;;
    esac
}

# Real-time monitoring
realtime_monitor() {
    echo -e "${YELLOW}[MONITORING]${NC} Real-time auth log monitoring (Ctrl+C to stop)..."
    log_event "INFO" "Started real-time auth log monitoring"
    
    # Create alert counters
    declare -A fail_counts
    
    tail -f /var/log/auth.log 2>/dev/null | while read line; do
        if echo "$line" | grep -q "Failed password"; then
            ip=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            user=$(echo "$line" | grep -oP "for \K\w+")
            echo -e "${RED}[ALERT]${NC} Failed login from $ip for user $user at $(date)"
            echo "$(date): Failed login from $ip for user $user" >> $LOG_DIR/security_alerts.log
            
            # Auto-blocking logic
            if [ "$ENABLE_AUTO_BLOCK" = "true" ]; then
                fail_count=$(grep "$ip" $LOG_DIR/security_alerts.log | grep "Failed login" | wc -l)
                if [ $fail_count -ge $AUTO_BLOCK_THRESHOLD ]; then
                    iptables -A INPUT -s $ip -j DROP 2>/dev/null
                    echo -e "${RED}[BLOCKED]${NC} IP $ip blocked after $fail_count failed attempts"
                    send_alert "IP Blocked" "IP $ip has been automatically blocked after $fail_count failed login attempts"
                fi
            fi
            
        elif echo "$line" | grep -q "Accepted password"; then
            ip=$(echo "$line" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
            user=$(echo "$line" | grep -oP "for \K\w+")
            echo -e "${GREEN}[INFO]${NC} Successful login from $ip for user $user"
            
        elif echo "$line" | grep -q "sudo"; then
            user=$(echo "$line" | grep -oP "sudo:\s+\K\w+")
            command=$(echo "$line" | grep -oP "COMMAND=\K.*")
            echo -e "${YELLOW}[SUDO]${NC} User $user executed: $command"
        fi
    done
}

# Failed login analysis
failed_login_analysis() {
    echo -e "${YELLOW}[ANALYZING]${NC} Analyzing failed login attempts..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/failed_logins_$timestamp.txt"
    
    {
        echo "Failed Login Analysis Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "Top 10 Failed Login IPs:"
        grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | head -10
        
        echo -e "\nTop 10 Targeted Users:"
        grep "Failed password" /var/log/auth.log | grep -oP "for \K\w+" | sort | uniq -c | sort -nr | head -10
        
        echo -e "\nFailed Login Timeline (Last 24 hours):"
        grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | awk '{print $1, $2, $3}' | uniq -c
        
        echo -e "\nSuspicious Patterns:"
        # Multiple users from same IP
        grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | awk '$1 > 10 {print "High frequency attacks from " $2 " (" $1 " attempts)"}'
        
        echo "================================"
        echo "Analysis completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    log_menu
}

# Connection monitor
connection_monitor() {
    echo -e "${YELLOW}[MONITORING]${NC} Network connection monitoring..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/connections_$timestamp.txt"
    
    {
        echo "Network Connection Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "Current Active Connections:"
        netstat -tuln
        
        echo -e "\nListening Services:"
        ss -tuln
        
        echo -e "\nEstablished Connections:"
        netstat -tun | grep ESTABLISHED
        
        echo -e "\nTop Connection States:"
        netstat -an | awk '{print $6}' | sort | uniq -c | sort -nr
        
        echo "================================"
        echo "Report completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    log_menu
}

# System log analysis
system_log_analysis() {
    echo -e "${YELLOW}[ANALYZING]${NC} System log analysis..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/system_logs_$timestamp.txt"
    
    {
        echo "System Log Analysis Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "Recent System Errors:"
        grep -i error /var/log/syslog | tail -20
        
        echo -e "\nRecent Warnings:"
        grep -i warning /var/log/syslog | tail -20
        
        echo -e "\nKernel Messages:"
        dmesg | tail -20
        
        echo -e "\nDisk Usage Alerts:"
        df -h | awk '$5 > 80 {print "High disk usage: " $0}'
        
        echo -e "\nMemory Usage:"
        free -h
        
        echo "================================"
        echo "Analysis completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    log_menu
}

# Generate comprehensive log report
log_report() {
    echo -e "${YELLOW}[GENERATING]${NC} Comprehensive log report..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/comprehensive_log_report_$timestamp.txt"
    
    {
        echo "COMPREHENSIVE LOG ANALYSIS REPORT"
        echo "Generated: $(date)"
        echo "========================================"
        
        echo -e "\n1. AUTHENTICATION SUMMARY"
        echo "Failed Logins (Last 24h): $(grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)"
        echo "Successful Logins (Last 24h): $(grep "Accepted password" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)"
        echo "Sudo Commands (Last 24h): $(grep "sudo" /var/log/auth.log | grep "$(date '+%b %d')" | wc -l)"
        
        echo -e "\n2. NETWORK ACTIVITY"
        echo "Active Connections: $(netstat -an | grep ESTABLISHED | wc -l)"
        echo "Listening Services: $(ss -tuln | wc -l)"
        
        echo -e "\n3. SYSTEM HEALTH"
        echo "System Errors (Last 24h): $(grep -i error /var/log/syslog | grep "$(date '+%b %d')" | wc -l)"
        echo "System Warnings (Last 24h): $(grep -i warning /var/log/syslog | grep "$(date '+%b %d')" | wc -l)"
        
        echo -e "\n4. SECURITY ALERTS"
        if [ -f "$LOG_DIR/security_alerts.log" ]; then
            echo "Total Security Alerts: $(wc -l < $LOG_DIR/security_alerts.log)"
            echo "Recent Alerts:"
            tail -10 $LOG_DIR/security_alerts.log
        else
            echo "No security alerts logged"
        fi
        
        echo -e "\n5. TOP THREAT SOURCES"
        echo "Top 5 Failed Login IPs:"
        grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr | head -5
        
        echo "========================================"
        echo "Report completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Comprehensive report saved to $output_file"
    read -p "Press Enter to continue..."
    log_menu
}

# Suspicious activity detection
suspicious_activity() {
    echo -e "${YELLOW}[DETECTING]${NC} Scanning for suspicious activities..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/suspicious_activity_$timestamp.txt"
    
    {
        echo "Suspicious Activity Detection Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. Brute Force Attempts:"
        grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | awk '$1 > 10 {print "Potential brute force from " $2 " (" $1 " attempts)"}'
        
        echo -e "\n2. Unusual Login Times:"
        grep "Accepted password" /var/log/auth.log | awk '{print $3}' | awk -F: '$1 < 6 || $1 > 22 {print "Login at unusual hour: " $0}' | head -10
        
        echo -e "\n3. Root Access Attempts:"
        grep "Failed password for root" /var/log/auth.log | tail -10
        
        echo -e "\n4. Privilege Escalation:"
        grep "sudo" /var/log/auth.log | grep -v "session opened" | grep -v "session closed" | tail -10
        
        echo -e "\n5. Network Anomalies:"
        netstat -an | awk '$6 == "ESTABLISHED" {print $5}' | cut -d: -f1 | sort | uniq -c | awk '$1 > 10 {print "High connection count from " $2 " (" $1 " connections)"}'
        
        echo "================================"
        echo "Detection completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    log_menu
}

# Log integrity check
log_integrity_check() {
    echo -e "${YELLOW}[CHECKING]${NC} Log file integrity check..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/log_integrity_$timestamp.txt"
    
    {
        echo "Log File Integrity Check Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "Log File Status:"
        for logfile in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
            if [ -f "$logfile" ]; then
                size=$(stat -c%s "$logfile")
                modified=$(stat -c%y "$logfile")
                echo "$logfile: Size=$size bytes, Modified=$modified"
                
                # Check for gaps in timestamps
                echo "Checking timestamp continuity in $logfile..."
                awk '{print $1, $2, $3}' "$logfile" | tail -100 | sort | uniq -c | awk '$1 == 1 {print "Potential gap: " $0}'
            else
                echo "$logfile: NOT FOUND"
            fi
        done
        
        echo -e "\nLog Rotation Status:"
        ls -la /var/log/*.log* | head -10
        
        echo "================================"
        echo "Check completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    log_menu
}

# Penetration Testing Menu
pentest_menu() {
    clear
    echo -e "${BLUE}═══════════ PENETRATION TESTING ═══════════${NC}"
    echo "1) Web Application Testing"
    echo "2) Network Penetration Test"
    echo "3) Wireless Security Test"
    echo "4) Social Engineering Toolkit"
    echo "5) Password Attack Suite"
    echo "6) Exploit Database Search"
    echo "7) Payload Generator"
    echo "8) Back to Main Menu"
    
    read -p "Select: " pentest_choice
    
    case $pentest_choice in
        1) web_app_test ;;
        2) network_pentest ;;
        3) wireless_test ;;
        4) social_engineering ;;
        5) password_attacks ;;
        6) exploit_search ;;
        7) payload_generator ;;
        8) main_menu ;;
        *) echo "Invalid option!"; sleep 2; pentest_menu ;;
    esac
}

# Web application testing
web_app_test() {
    read -p "Enter target URL: " target_url
    
    echo -e "${YELLOW}[TESTING]${NC} Web application security test of $target_url..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/webapp_test_$timestamp.txt"
    
    {
        echo "Web Application Security Test Report"
        echo "Target: $target_url"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. Directory Enumeration:"
        if command -v gobuster &> /dev/null; then
            gobuster dir -u "$target_url" -w /usr/share/wordlists/dirb/common.txt -q
        else
            echo "gobuster not installed, using curl for basic checks"
            for dir in admin login wp-admin phpmyadmin; do
                if curl -s -o /dev/null -w "%{http_code}" "$target_url/$dir" | grep -q "200\|301\|302"; then
                    echo "Found: $target_url/$dir"
                fi
            done
        fi
        
        echo -e "\n2. HTTP Headers Analysis:"
        curl -I "$target_url" 2>/dev/null
        
        echo -e "\n3. SSL/TLS Check:"
        if echo "$target_url" | grep -q "https"; then
            domain=$(echo "$target_url" | sed 's|https://||' | cut -d'/' -f1)
            echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -dates
        fi
        
        echo -e "\n4. Common Vulnerability Checks:"
        echo "Checking for common files..."
        for file in robots.txt sitemap.xml .htaccess; do
            status=$(curl -s -o /dev/null -w "%{http_code}" "$target_url/$file")
            echo "$file: HTTP $status"
        done
        
        echo "================================"
        echo "Test completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    pentest_menu
}

# Network penetration test
network_pentest() {
    read -p "Enter target network: " target_network
    
    echo -e "${YELLOW}[TESTING]${NC} Network penetration test of $target_network..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/network_pentest_$timestamp.txt"
    
    {
        echo "Network Penetration Test Report"
        echo "Target: $target_network"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. Host Discovery:"
        nmap -sn "$target_network"
        
        echo -e "\n2. Port Scanning:"
        nmap -sS -F --open "$target_network"
        
        echo -e "\n3. Service Enumeration:"
        nmap -sV -sC "$target_network"
        
        echo -e "\n4. Vulnerability Assessment:"
        nmap --script vuln "$target_network"
        
        echo -e "\n5. SMB Enumeration:"
        nmap --script smb-enum-shares,smb-enum-users "$target_network"
        
        echo "================================"
        echo "Test completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    pentest_menu
}

# Password attack suite
password_attacks() {
    clear
    echo -e "${BLUE}═══════════ PASSWORD ATTACKS ═══════════${NC}"
    echo "1) Dictionary Attack"
    echo "2) Brute Force Attack"
    echo "3) Hash Cracking"
    echo "4) Generate Wordlist"
    echo "5) Password Strength Test"
    echo "6) Back to Pentest Menu"
    
    read -p "Select: " pass_choice
    
    case $pass_choice in
        1) dictionary_attack ;;
        2) brute_force_attack ;;
        3) hash_cracking ;;
        4) generate_wordlist ;;
        5) password_strength ;;
        6) pentest_menu ;;
    esac
}

# Dictionary attack
dictionary_attack() {
    read -p "Enter target service (ssh/ftp/http): " service
    read -p "Enter target IP: " target_ip
    read -p "Enter username: " username
    
    echo -e "${YELLOW}[ATTACKING]${NC} Dictionary attack on $service://$target_ip..."
    
    # Create a basic wordlist if none exists
    if [ ! -f "wordlist.txt" ]; then
        echo -e "password\n123456\nadmin\nroot\npassword123\nletmein\nwelcome\n12345678" > wordlist.txt
    fi
    
    case $service in
        ssh)
            if command -v hydra &> /dev/null; then
                hydra -l "$username" -P wordlist.txt "$target_ip" ssh
            else
                echo "Hydra not installed. Manual SSH brute force:"
                while read password; do
                    echo "Trying password: $password"
                    sshpass -p "$password" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$username@$target_ip" exit 2>/dev/null && echo "SUCCESS: $password" && break
                done < wordlist.txt
            fi
            ;;
        *)
            echo "Service $service not implemented yet"
            ;;
    esac
    
    read -p "Press Enter to continue..."
    password_attacks
}

# Threat Intelligence Menu
threat_intel_menu() {
    clear
    echo -e "${BLUE}═══════════ THREAT INTELLIGENCE ═══════════${NC}"
    echo "1) Check IP Reputation"
    echo "2) Download Threat Feeds"
    echo "3) Malware Hash Check"
    echo "4) Domain Analysis"
    echo "5) IOC Correlation"
    echo "6) Threat Feed Management"
    echo "7) Generate Threat Report"
    echo "8) Back to Main Menu"
    
    read -p "Select: " threat_choice
    
    case $threat_choice in
        1) ip_reputation ;;
        2) download_feeds ;;
        3) hash_check ;;
        4) domain_analysis ;;
        5) ioc_correlation ;;
        6) threat_feed_management ;;
        7) generate_threat_report ;;
        8) main_menu ;;
    esac
}

# IP Reputation check
ip_reputation() {
    read -p "Enter IP address: " ip_addr
    echo -e "${YELLOW}[CHECKING]${NC} IP reputation for $ip_addr..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/ip_reputation_${ip_addr}_$timestamp.txt"
    
    {
        echo "IP Reputation Report"
        echo "IP Address: $ip_addr"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. Threat Intelligence Feeds:"
        # Check against multiple threat feeds
        feeds=(
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
        )
        
        for feed in "${feeds[@]}"; do
            feed_name=$(basename "$feed")
            echo "Checking $feed_name..."
            if curl -s "$feed" | grep -q "$ip_addr"; then
                echo "THREAT: IP found in $feed_name"
            else
                echo "CLEAN: IP not found in $feed_name"
            fi
        done
        
        echo -e "\n2. Geolocation Information:"
        if command -v geoiplookup &> /dev/null; then
            geoiplookup "$ip_addr"
        else
            curl -s "http://ip-api.com/line/$ip_addr"
        fi
        
        echo -e "\n3. WHOIS Information:"
        whois "$ip_addr" | head -20
        
        echo -e "\n4. DNS Reverse Lookup:"
        dig -x "$ip_addr" +short
        
        echo -e "\n5. Local Log Analysis:"
        echo "Occurrences in auth.log:"
        grep "$ip_addr" /var/log/auth.log | wc -l
        echo "Recent activities:"
        grep "$ip_addr" /var/log/auth.log | tail -5
        
        echo "================================"
        echo "Check completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    threat_intel_menu
}

# Download threat feeds
download_feeds() {
    echo -e "${YELLOW}[DOWNLOADING]${NC} Updating threat intelligence feeds..."
    
    feeds=(
        "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt:malicious_ips.txt"
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt:emerging_threats.txt"
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset:firehol_level1.txt"
    )
    
    for feed_info in "${feeds[@]}"; do
        url=$(echo "$feed_info" | cut -d':' -f1)
        filename=$(echo "$feed_info" | cut -d':' -f2)
        
        echo "Downloading $(basename "$url")..."
        if curl -s "$url" -o "$THREAT_FEEDS_DIR/$filename"; then
            echo -e "${GREEN}✓${NC} Downloaded $filename"
            log_event "INFO" "Downloaded threat feed: $filename"
        else
            echo -e "${RED}✗${NC} Failed to download $filename"
            log_event "ERROR" "Failed to download threat feed: $filename"
        fi
    done
    
    echo -e "${GREEN}[COMPLETE]${NC} Threat feeds updated"
    read -p "Press Enter to continue..."
    threat_intel_menu
}

# Hash check
hash_check() {
    read -p "Enter file hash (MD5/SHA1/SHA256): " file_hash
    
    echo -e "${YELLOW}[CHECKING]${NC} Malware hash reputation for $file_hash..."
    
    # Check against local malware database (if exists)
    if [ -f "$THREAT_FEEDS_DIR/malware_hashes.txt" ]; then
        if grep -q "$file_hash" "$THREAT_FEEDS_DIR/malware_hashes.txt"; then
            echo -e "${RED}[MALWARE]${NC} Hash found in malware database!"
        else
            echo -e "${GREEN}[CLEAN]${NC} Hash not found in local malware database"
        fi
    else
        echo "Local malware hash database not found"
    fi
    
    # Note: In a real implementation, you would integrate with APIs like VirusTotal
    echo "Note: For comprehensive analysis, integrate with VirusTotal API"
    
    read -p "Press Enter to continue..."
    threat_intel_menu
}

# Domain analysis
domain_analysis() {
    read -p "Enter domain name: " domain
    
    echo -e "${YELLOW}[ANALYZING]${NC} Domain analysis for $domain..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/domain_analysis_${domain}_$timestamp.txt"
    
    {
        echo "Domain Analysis Report"
        echo "Domain: $domain"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. DNS Records:"
        dig "$domain" ANY +short
        
        echo -e "\n2. WHOIS Information:"
        whois "$domain" | head -30
        
        echo -e "\n3. Subdomain Enumeration:"
        for sub in www mail ftp admin login; do
            if dig "$sub.$domain" +short | grep -q .; then
                echo "Found: $sub.$domain"
            fi
        done
        
        echo -e "\n4. SSL Certificate Check:"
        echo | openssl s_client -connect "$domain:443" -servername "$domain" 2>/dev/null | openssl x509 -noout -text | grep -E "(Subject|Issuer|Not Before|Not After)"
        
        echo -e "\n5. HTTP Headers:"
        curl -I "http://$domain" 2>/dev/null | head -10
        
        echo "================================"
        echo "Analysis completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    threat_intel_menu
}

# IOC Correlation
ioc_correlation() {
    echo -e "${YELLOW}[CORRELATING]${NC} Correlating Indicators of Compromise..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/ioc_correlation_$timestamp.txt"
    
    {
        echo "IOC Correlation Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. Correlating IPs from threat feeds with local logs:"
        if [ -f "$THREAT_FEEDS_DIR/malicious_ips.txt" ]; then
            while read malicious_ip; do
                if grep -q "$malicious_ip" /var/log/auth.log; then
                    echo "MATCH: $malicious_ip found in auth.log"
                    grep "$malicious_ip" /var/log/auth.log | tail -3
                fi
            done < "$THREAT_FEEDS_DIR/malicious_ips.txt"
        fi
        
        echo -e "\n2. Suspicious Domain Correlations:"
        # Check DNS queries against known bad domains
        if [ -f "/var/log/syslog" ]; then
            grep "dnsmasq" /var/log/syslog | grep -E "(malware|phishing|suspicious)" | tail -10
        fi
        
        echo -e "\n3. File Hash Correlations:"
        # This would check file hashes against malware databases
        echo "File hash correlation requires integration with malware databases"
        
        echo "================================"
        echo "Correlation completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    threat_intel_menu
}

# System Hardening Menu
hardening_menu() {
    clear
    echo -e "${BLUE}═══════════ SYSTEM HARDENING ═══════════${NC}"
    echo "1) SSH Hardening"
    echo "2) Firewall Configuration"
    echo "3) File Permission Audit"
    echo "4) Service Audit"
    echo "5) Security Updates"
    echo "6) User Account Audit"
    echo "7) Network Security"
    echo "8) Generate Hardening Report"
    echo "9) Back to Main Menu"
    
    read -p "Select: " hard_choice
    
    case $hard_choice in
        1) ssh_hardening ;;
        2) firewall_config ;;
        3) file_audit ;;
        4) service_audit ;;
        5) security_updates ;;
        6) user_audit ;;
        7) network_security ;;
        8) hardening_report ;;
        9) main_menu ;;
    esac
}

# SSH Hardening
ssh_hardening() {
    echo -e "${YELLOW}[HARDENING]${NC} Analyzing SSH configuration..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/ssh_hardening_$timestamp.txt"
    
    {
        echo "SSH Hardening Analysis Report"
        echo "Date: $(date)"
        echo "================================"
        
        ssh_config="/etc/ssh/sshd_config"
        if [ -f "$ssh_config" ]; then
            echo "Current SSH Security Configuration:"
            echo "- Root login: $(grep "^PermitRootLogin" $ssh_config || echo "Not configured (default: yes)")"
            echo "- Password auth: $(grep "^PasswordAuthentication" $ssh_config || echo "Not configured (default: yes)")"
            echo "- Port: $(grep "^Port" $ssh_config || echo "Default (22)")"
            echo "- Protocol: $(grep "^Protocol" $ssh_config || echo "Not configured (default: 2)")"
            echo "- Max auth tries: $(grep "^MaxAuthTries" $ssh_config || echo "Not configured (default: 6)")"
            echo "- Client alive interval: $(grep "^ClientAliveInterval" $ssh_config || echo "Not configured")"
            echo "- X11 forwarding: $(grep "^X11Forwarding" $ssh_config || echo "Not configured (default: yes)")"
            
            echo -e "\nSecurity Recommendations:"
            echo "✓ Disable root login: PermitRootLogin no"
            echo "✓ Use key-based authentication: PasswordAuthentication no"
            echo "✓ Change default port: Port 2222"
            echo "✓ Limit authentication attempts: MaxAuthTries 3"
            echo "✓ Set client timeout: ClientAliveInterval 300"
            echo "✓ Disable X11 forwarding: X11Forwarding no"
            echo "✓ Enable fail2ban for SSH protection"
            
            echo -e "\nCurrent SSH Key Status:"
            if [ -d "/home" ]; then
                for user_home in /home/*; do
                    if [ -d "$user_home/.ssh" ]; then
                        username=$(basename "$user_home")
                        echo "User $username has SSH keys configured"
                    fi
                done
            fi
            
        else
            echo "SSH configuration file not found!"
        fi
        
        echo -e "\nActive SSH Connections:"
        who | grep pts
        
        echo "================================"
        echo "Analysis completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    
    read -p "Apply SSH hardening recommendations? (y/n): " apply_hardening
    if [ "$apply_hardening" = "y" ]; then
        echo "Creating backup of SSH config..."
        cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config_backup_$(date +%Y%m%d_%H%M%S)"
        echo "Backup created. Manual configuration required for security."
    fi
    
    read -p "Press Enter to continue..."
    hardening_menu
}

# Firewall configuration
firewall_config() {
    echo -e "${YELLOW}[CONFIGURING]${NC} Firewall analysis and configuration..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/firewall_config_$timestamp.txt"
    
    {
        echo "Firewall Configuration Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "Current iptables rules:"
        iptables -L -n -v
        
        echo -e "\nCurrent UFW status:"
        if command -v ufw &> /dev/null; then
            ufw status verbose
        else
            echo "UFW not installed"
        fi
        
        echo -e "\nOpen ports:"
        netstat -tuln
        
        echo -e "\nRecommended firewall rules:"
        echo "# Allow SSH (change port as needed)"
        echo "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
        echo "# Allow HTTP/HTTPS"
        echo "iptables -A INPUT -p tcp --dport 80 -j ACCEPT"
        echo "iptables -A INPUT -p tcp --dport 443 -j ACCEPT"
        echo "# Allow established connections"
        echo "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
        echo "# Drop all other incoming"
        echo "iptables -A INPUT -j DROP"
        
        echo "================================"
        echo "Analysis completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    hardening_menu
}

# File permission audit
file_audit() {
    echo -e "${YELLOW}[AUDITING]${NC} File permission audit..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/file_audit_$timestamp.txt"
    
    {
        echo "File Permission Audit Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. World-writable files:"
        find / -type f -perm -002 2>/dev/null | head -20
        
        echo -e "\n2. SUID/SGID files:"
        find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20
        
        echo -e "\n3. Files with no owner:"
        find / -nouser -o -nogroup 2>/dev/null | head -20
        
        echo -e "\n4. Critical system file permissions:"
        ls -la /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
        
        echo -e "\n5. SSH key permissions:"
        find /home -name "*.ssh" -type d -exec ls -la {} \; 2>/dev/null
        
        echo -e "\n6. Log file permissions:"
        ls -la /var/log/ | head -10
        
        echo "================================"
        echo "Audit completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    hardening_menu
}

# Service audit
service_audit() {
    echo -e "${YELLOW}[AUDITING]${NC} Service audit..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/service_audit_$timestamp.txt"
    
    {
        echo "Service Audit Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. Running services:"
        systemctl list-units --type=service --state=running
        
        echo -e "\n2. Enabled services:"
        systemctl list-unit-files --type=service --state=enabled
        
        echo -e "\n3. Network services:"
        netstat -tuln | grep LISTEN
        
        echo -e "\n4. Processes by CPU usage:"
        ps aux --sort=-%cpu | head -10
        
        echo -e "\n5. Processes by memory usage:"
        ps aux --sort=-%mem | head -10
        
        echo -e "\n6. Unnecessary services to consider disabling:"
        echo "- telnet (use SSH instead)"
        echo "- ftp (use SFTP instead)"
        echo "- rsh/rlogin (use SSH instead)"
        echo "- finger"
        echo "- talk"
        
        echo "================================"
        echo "Audit completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    hardening_menu
}

# Security updates
security_updates() {
    echo -e "${YELLOW}[CHECKING]${NC} Security updates..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/security_updates_$timestamp.txt"
    
    {
        echo "Security Updates Report"
        echo "Date: $(date)"
        echo "================================"
        
        if command -v apt &> /dev/null; then
            echo "Debian/Ubuntu system detected"
            echo "Updating package list..."
            apt update &>/dev/null
            
            echo "Available security updates:"
            apt list --upgradable 2>/dev/null | grep -i security
            
            echo -e "\nAll available updates:"
            apt list --upgradable 2>/dev/null
            
        elif command -v yum &> /dev/null; then
            echo "RedHat/CentOS system detected"
            echo "Available security updates:"
            yum check-update --security
            
        elif command -v dnf &> /dev/null; then
            echo "Fedora system detected"
            echo "Available security updates:"
            dnf check-update --security
            
        else
            echo "Package manager not recognized"
        fi
        
        echo -e "\nKernel version:"
        uname -r
        
        echo -e "\nSystem uptime:"
        uptime
        
        echo "================================"
        echo "Check completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    
    read -p "Install security updates now? (y/n): " install_updates
    if [ "$install_updates" = "y" ]; then
        if command -v apt &> /dev/null; then
            echo "Installing security updates..."
            apt upgrade -y
        elif command -v yum &> /dev/null; then
            yum update -y --security
        elif command -v dnf &> /dev/null; then
            dnf update -y --security
        fi
    fi
    
    read -p "Press Enter to continue..."
    hardening_menu
}

# User account audit
user_audit() {
    echo -e "${YELLOW}[AUDITING]${NC} User account audit..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/user_audit_$timestamp.txt"
    
    {
        echo "User Account Audit Report"
        echo "Date: $(date)"
        echo "================================"
        
        echo "1. All user accounts:"
        cat /etc/passwd | cut -d: -f1,3,4,5,6,7
        
        echo -e "\n2. Users with UID 0 (root privileges):"
        awk -F: '$3 == 0 {print $1}' /etc/passwd
        
        echo -e "\n3. Users with empty passwords:"
        awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null || echo "Cannot read /etc/shadow (permission denied)"
        
        echo -e "\n4. Users with shell access:"
        grep -E "/bin/(bash|sh|zsh|fish)" /etc/passwd
        
        echo -e "\n5. Recently logged in users:"
        last | head -10
        
        echo -e "\n6. Failed login attempts:"
        lastb | head -10 2>/dev/null || echo "No failed login records or permission denied"
        
        echo -e "\n7. Sudo users:"
        grep -E "^sudo|^wheel" /etc/group
        
        echo -e "\n8. Password policy:"
        if [ -f "/etc/login.defs" ]; then
            grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE" /etc/login.defs
        fi
        
        echo "================================"
        echo "Audit completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Results saved to $output_file"
    read -p "Press Enter to continue..."
    hardening_menu
}

# Incident Response Menu
incident_menu() {
    clear
    echo -e "${BLUE}═══════════ INCIDENT RESPONSE ═══════════${NC}"
    echo "1) Emergency Response"
    echo "2) Forensic Data Collection"
    echo "3) Network Isolation"
    echo "4) Malware Analysis"
    echo "5) Timeline Analysis"
    echo "6) Evidence Preservation"
    echo "7) Incident Documentation"
    echo "8) Back to Main Menu"
    
    read -p "Select: " incident_choice
    
    case $incident_choice in
        1) emergency_response ;;
        2) forensic_collection ;;
        3) network_isolation ;;
        4) malware_analysis ;;
        5) timeline_analysis ;;
        6) evidence_preservation ;;
        7) incident_documentation ;;
        8) main_menu ;;
    esac
}

# Emergency response
emergency_response() {
    echo -e "${RED}[EMERGENCY]${NC} Emergency Response Protocol"
    echo "================================"
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    incident_dir="$REPORT_DIR/incident_$timestamp"
    mkdir -p "$incident_dir"
    
    echo "1. System Snapshot"
    {
        echo "Emergency Response Report"
        echo "Timestamp: $(date)"
        echo "================================"
        
        echo "Current processes:"
        ps aux
        
        echo -e "\nNetwork connections:"
        netstat -tuln
        
        echo -e "\nLogged in users:"
        who
        
        echo -e "\nRecent commands:"
        history | tail -50
        
        echo -e "\nSystem load:"
        uptime
        
        echo -e "\nDisk usage:"
        df -h
        
        echo -e "\nMemory usage:"
        free -h
        
    } > "$incident_dir/emergency_snapshot.txt"
    
    echo "2. Immediate Actions:"
    echo "   - System snapshot saved to $incident_dir"
    echo "   - Consider network isolation"
    echo "   - Preserve evidence"
    echo "   - Document all actions"
    
    read -p "Isolate network? (y/n): " isolate
    if [ "$isolate" = "y" ]; then
        echo "Network isolation initiated..."
        # In a real scenario, this would disconnect network interfaces
        echo "Network interfaces would be disabled in production"
    fi
    
    log_event "ALERT" "Emergency response protocol activated"
    send_alert "EMERGENCY RESPONSE" "Emergency response protocol has been activated on $(hostname)"
    
    read -p "Press Enter to continue..."
    incident_menu
}

# Forensic data collection
forensic_collection() {
    echo -e "${YELLOW}[COLLECTING]${NC} Forensic data collection..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    forensic_dir="$REPORT_DIR/forensics_$timestamp"
    mkdir -p "$forensic_dir"
    
    {
        echo "Forensic Data Collection Report"
        echo "Collection Time: $(date)"
        echo "Collector: $(whoami)"
        echo "System: $(hostname)"
        echo "================================"
        
        echo "1. System Information:"
        uname -a
        cat /etc/os-release
        
        echo -e "\n2. User Information:"
        who
        last | head -20
        
        echo -e "\n3. Process Information:"
        ps auxf
        
        echo -e "\n4. Network Information:"
        netstat -tuln
        ss -tuln
        
        echo -e "\n5. File System Information:"
        mount
        df -h
        
        echo -e "\n6. Log Files:"
        echo "Auth log entries (last 100):"
        tail -100 /var/log/auth.log
        
        echo -e "\nSyslog entries (last 100):"
        tail -100 /var/log/syslog
        
        echo -e "\n7. Network Configuration:"
        ip addr show
        ip route show
        
        echo -e "\n8. Cron Jobs:"
        crontab -l 2>/dev/null || echo "No crontab for current user"
        ls -la /etc/cron*
        
    } > "$forensic_dir/forensic_collection.txt"
    
    # Copy important log files
    cp /var/log/auth.log "$forensic_dir/" 2>/dev/null
    cp /var/log/syslog "$forensic_dir/" 2>/dev/null
    
    # Create hash of collected data
    find "$forensic_dir" -type f -exec md5sum {} \; > "$forensic_dir/file_hashes.txt"
    
    echo -e "${GREEN}[COMPLETE]${NC} Forensic data collected in $forensic_dir"
    log_event "INFO" "Forensic data collection completed: $forensic_dir"
    
    read -p "Press Enter to continue..."
    incident_menu
}

# Reports Menu
reports_menu() {
    clear
    echo -e "${BLUE}═══════════ REPORTS & ANALYTICS ═══════════${NC}"
    echo "1) Security Summary Report"
    echo "2) Vulnerability Assessment Report"
    echo "3) Network Analysis Report"
    echo "4) Compliance Report"
    echo "5) Executive Summary"
    echo "6) Custom Report Generator"
    echo "7) Report Archive Management"
    echo "8) Back to Main Menu"
    
    read -p "Select: " report_choice
    
    case $report_choice in
        1) security_summary_report ;;
        2) vulnerability_report ;;
        3) network_analysis_report ;;
        4) compliance_report ;;
        5) executive_summary ;;
        6) custom_report ;;
        7) report_archive ;;
        8) main_menu ;;
    esac
}

# Security summary report
security_summary_report() {
    echo -e "${YELLOW}[GENERATING]${NC} Security summary report..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/security_summary_$timestamp.txt"
    
    {
        echo "SECURITY SUMMARY REPORT"
        echo "Generated: $(date)"
        echo "System: $(hostname)"
        echo "========================================"
        
        echo -e "\n1. SYSTEM OVERVIEW"
        echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo "Kernel: $(uname -r)"
        echo "Uptime: $(uptime -p)"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        
        echo -e "\n2. SECURITY STATUS"
        echo "Failed Logins (24h): $(grep "Failed password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l)"
        echo "Successful Logins (24h): $(grep "Accepted password" /var/log/auth.log 2>/dev/null | grep "$(date '+%b %d')" | wc -l)"
        echo "Active Connections: $(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l)"
        echo "Listening Services: $(ss -tuln 2>/dev/null | wc -l)"
        
        echo -e "\n3. RESOURCE USAGE"
        echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
        echo "Memory Usage: $(free | grep Mem | awk '{printf("%.1f%%", $3/$2 * 100.0)}')"
        echo "Disk Usage: $(df -h / | awk 'NR==2{printf "%s", $5}')"
        
        echo -e "\n4. RECOMMENDATIONS"
        echo "- Regular security updates"
        echo "- Monitor failed login attempts"
        echo "- Review open ports and services"
        echo "- Implement proper backup strategy"
        
        echo "========================================"
        echo "Report completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Report saved to $output_file"
    read -p "Press Enter to continue..."
    reports_menu
}

# Vulnerability report
vulnerability_report() {
    echo -e "${YELLOW}[GENERATING]${NC} Vulnerability assessment report..."
    
    timestamp=$(date +"%Y%m%d_%H%M%S")
    output_file="$REPORT_DIR/vulnerability_report_$timestamp.txt"
    
    {
        echo "VULNERABILITY ASSESSMENT REPORT"
        echo "Generated: $(date)"
        echo "========================================"
        
        echo -e "\n1. SYSTEM VULNERABILITIES"
        echo "Outdated packages:"
        if command -v apt &> /dev/null; then
            apt list --upgradable 2>/dev/null | wc -l
        else
            echo "Package manager check not available"
        fi
        
        echo -e "\n2. CONFIGURATION ISSUES"
        echo "SSH root login: $(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null || echo "Not configured")"
        echo "Password authentication: $(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null || echo "Not configured")"
        
        echo -e "\n3. NETWORK EXPOSURE"
        echo "Open ports:"
        netstat -tuln 2>/dev/null | grep LISTEN | head -10
        
        echo -e "\n4. FILE SYSTEM ISSUES"
        echo "World-writable files:"
        find /tmp -type f -perm -002 2>/dev/null | wc -l
        
        echo "========================================"
        echo "Assessment completed at $(date)"
    } | tee $output_file
    
    echo -e "${GREEN}[COMPLETE]${NC} Report saved to $output_file"
    read -p "Press Enter to continue..."
    reports_menu
}

# Configuration menu
config_menu() {
    clear
    echo -e "${BLUE}═══════════ CONFIGURATION ═══════════${NC}"
    echo "1) Set Default Target"
    echo "2) Configure Email Alerts"
    echo "3) Set Report Directory"
    echo "4) Auto-Block Settings"
    echo "5) Log Level Settings"
    echo "6) View Current Config"
    echo "7) Reset to Defaults"
    echo "8) Back to Main Menu"
    
    read -p "Select: " config_choice
    
    case $config_choice in
        1) set_target ;;
        2) config_alerts ;;
        3) set_report_dir ;;
        4) auto_block_config ;;
        5) log_level_config ;;
        6) view_config ;;
        7) reset_config ;;
        8) main_menu ;;
    esac
}

# Set default target
set_target() {
    echo "Current default target: $DEFAULT_TARGET"
    read -p "Enter new default target: " new_target
    
    if [ ! -z "$new_target" ]; then
        sed -i "s/DEFAULT_TARGET=.*/DEFAULT_TARGET=\"$new_target\"/" $CONFIG_FILE
        echo -e "${GREEN}[UPDATED]${NC} Default target set to $new_target"
        load_config
    fi
    
    read -p "Press Enter to continue..."
    config_menu
}

# Configure email alerts
config_alerts() {
    echo "Current alert email: $ALERT_EMAIL"
    echo "Email alerts enabled: $ENABLE_EMAIL_ALERTS"
    
    read -p "Enter new alert email: " new_email
    read -p "Enable email alerts? (true/false): " enable_alerts
    
    if [ ! -z "$new_email" ]; then
        sed -i "s/ALERT_EMAIL=.*/ALERT_EMAIL=\"$new_email\"/" $CONFIG_FILE
    fi
    
    if [ ! -z "$enable_alerts" ]; then
        sed -i "s/ENABLE_EMAIL_ALERTS=.*/ENABLE_EMAIL_ALERTS=$enable_alerts/" $CONFIG_FILE
    fi
    
    echo -e "${GREEN}[UPDATED]${NC} Email configuration updated"
    load_config
    
    read -p "Press Enter to continue..."
    config_menu
}

# View current configuration
view_config() {
    echo -e "${CYAN}Current Configuration:${NC}"
    echo "================================"
    cat $CONFIG_FILE
    echo "================================"
    
    read -p "Press Enter to continue..."
    config_menu
}

# Cleanup function
cleanup_reports() {
    echo -e "${YELLOW}[CLEANING]${NC} Cleaning old reports..."
    
    # Remove reports older than retention period
    find $REPORT_DIR -name "*.txt" -mtime +$REPORT_RETENTION_DAYS -delete 2>/dev/null
    find $LOG_DIR -name "*.log" -mtime +$REPORT_RETENTION_DAYS -delete 2>/dev/null
    
    echo -e "${GREEN}[COMPLETE]${NC} Cleanup completed"
}

# Exit function
exit_dashboard() {
    clear
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                    SESSION COMPLETE                       ║"
    echo "║              Thanks for using SecDashboard!               ║"
    echo "║                                                           ║"
    echo "║  Reports saved in: $REPORT_DIR                    ║"
    echo "║  Logs saved in: $LOG_DIR                          ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Cleanup old reports
    cleanup_reports
    
    log_event "INFO" "Dashboard session ended"
    exit 0
}

# Signal handlers
trap 'echo -e "\n${YELLOW}[INFO]${NC} Dashboard interrupted. Exiting..."; exit_dashboard' INT TERM

# Initialize and start
log_event "INFO" "Dashboard started by $(whoami)"
main_menu
