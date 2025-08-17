# Bhemma - Security Dashboard

A comprehensive cybersecurity monitoring and analysis dashboard built in Bash.

## Features

- **Network Security Scanner**: Port scanning, vulnerability detection, service enumeration
- **Log Analysis & Monitoring**: Real-time log monitoring with auto-blocking capabilities
- **Penetration Testing Suite**: Web app testing, network pentesting, password attacks
- **Threat Intelligence**: IP reputation checks, domain analysis, IOC correlation
- **System Hardening**: SSH hardening, firewall configuration, security audits
- **Incident Response**: Emergency protocols, forensic data collection
- **Reports & Analytics**: Comprehensive security reports and vulnerability assessments

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Jybhavsar12/Bhemma.git
cd Bhemma
```

2. Run the installation script:
```bash
chmod +x install.sh
./install.sh
```

## Usage

Start the dashboard:
```bash
./start_dashboard.sh
```

## Requirements

- Linux/Unix system (Ubuntu, Debian, CentOS, RHEL, Fedora)
- Bash 4.0+
- Root privileges (recommended for full functionality)

### Dependencies
- nmap
- netcat
- curl/wget
- dnsutils
- whois
- iptables
- fail2ban

## Configuration

Edit `dashboard.conf` to customize:
- Default scan targets
- Email alerts
- Auto-blocking settings
- Report retention
- Logging levels

## Directory Structure

```
security-dashboard/
├── security_dashboard.sh    # Main dashboard script
├── start_dashboard.sh       # Startup script
├── install.sh              # Installation script
├── dashboard.conf          # Configuration file
├── logs/                   # Log files
├── reports/               # Generated reports
├── threat_feeds/          # Threat intelligence data
└── backups/              # Backup files
```

## Security Notice

This tool is designed for authorized security testing and monitoring only. Users are responsible for ensuring compliance with applicable laws and regulations.

## License

MIT License - see LICENSE file for details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Support

For issues and questions, please open an issue in the GitHub repository.
