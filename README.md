#  Network Scanner

**AI-Assisted Vulnerability Assessment & Penetration Testing Tool**

Network Scanner is an open-source security scanning platform that combines traditional penetration testing tools with artificial intelligence to provide comprehensive vulnerability assessments. Designed for beginners, researchers, and security professionals, it offers automated reconnaissance, intelligent analysis, and detailed reporting.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)

##  Features

| Category | Features |
|----------|----------|
|  **Reconnaissance** | Subdomain finder, WHOIS lookup, port scanning, DNS enumeration |
|  **AI Assistant** | Interprets scan results, suggests next steps, explains findings |
|  **Automation** | Automated comprehensive scans via CLI or web interface |
|  **Reports** | Generates professional PDF and HTML reports |
|  **Multi-user** | Team collaboration with project management and audit logs |
|  **Learning Mode** | Educational explanations for students and beginners |
|  **API Ready** | RESTful API for integration and automation |
|  **Security** | Rate limiting, authentication, and secure configurations |

##  Quick Start

### Prerequisites

- Python 3.8+ and pip
- Node.js 16+ and npm
- nmap, dnsutils, whois (installed automatically)

### Installation

```bash
# Clone the repository
git clone https://github.com/frangelbarrera/Network-Scanner.git
cd Network-Scanner

# Run the installation script (Ubuntu/Debian)
chmod +x scripts/install.sh
./scripts/install.sh

# Or install manually:
# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend setup
cd ../frontend
npm install

# CLI setup
cd ../cli
pip3 install -r requirements.txt
chmod +x secscanx.py
```

### Configuration

```bash
# Copy and edit environment file
cp .env.example .env
# Edit .env with your settings (API keys, database config, etc.)
```

### Running Network Scanner

**Start the Backend API:**
```bash
cd backend
source venv/bin/activate
python app.py
# API available at http://localhost:5000
```

**Start the Frontend (new terminal):**
```bash
cd frontend
npm start
# Web interface at http://localhost:3000
```

**Use the CLI:**
```bash
# Add to PATH or use directly
./cli/network_scanner_cli.py --help

# Example scans
network-scanner-cli subdomain example.com
network-scanner-cli port 192.168.1.1 --port-range 1-1000
network-scanner-cli vuln https://example.com --scan-type web
```

##  Usage Examples

### Web Interface

1. **Dashboard**: View scan statistics, recent results, and quick actions
2. **Scanner**: Configure and run different types of security scans
3. **Results**: Analyze findings with AI-powered insights
4. **Reports**: Generate professional security assessment reports
5. **AI Assistant**: Chat with AI for security advice and explanations

### Command Line Interface

```bash
# Comprehensive subdomain enumeration
network-scanner-cli subdomain target.com --output results.json

# Port scan with custom range
network-scanner-cli port 10.0.0.1 --port-range 1-65535

# Web application vulnerability assessment
network-scanner-cli vuln https://target.com --scan-type comprehensive

# DNS reconnaissance
network-scanner-cli dns target.com

# Generate professional report
network-scanner-cli report results.json --format pdf
```

### API Usage

```python
import requests

# Start a subdomain scan
response = requests.post('http://localhost:5000/api/scan/subdomain',
                        json={'domain': 'example.com'})
result = response.json()

# Get AI analysis
ai_response = requests.post('http://localhost:5000/api/ai/chat',
                           json={'message': 'Explain this vulnerability',
                                'context': result})
```

##  Architecture

Network Scanner follows a modular architecture:

```
Network-Scanner/
├── backend/          # Python Flask API server
│   ├── app.py       # Main application
│   ├── modules/     # Scanning and AI modules
│   └── models/      # Database models
├── frontend/         # React web interface
│   ├── src/
│   └── components/
├── cli/             # Command-line interface
├── reports/         # Generated reports
├── docs/           # Documentation
└── scripts/        # Installation and utility scripts
```

### Key Components

- **Reconnaissance Module**: Subdomain enumeration, port scanning, DNS/WHOIS lookups
- **AI Assistant**: OpenAI integration for intelligent analysis and recommendations
- **Vulnerability Scanner**: Web app and network service security assessment
- **Report Generator**: Professional PDF/HTML report creation
- **Multi-user System**: Authentication, projects, and audit logging

##  Scan Types

### 1. Subdomain Enumeration
- Brute force common subdomains
- Certificate Transparency log search
- DNS zone transfer attempts
- AI analysis of discovered subdomains

### 2. Port Scanning
- TCP/UDP port discovery
- Service version detection
- Operating system fingerprinting
- Risk assessment of open services

### 3. Vulnerability Assessment
- Web application security testing
- Network service vulnerability detection
- SSL/TLS configuration analysis
- Security header verification

### 4. DNS Enumeration
- A, AAAA, MX, NS, TXT record collection
- DNS zone information gathering
- Email server discovery
- Infrastructure mapping

### 5. WHOIS Lookup
- Domain registration information
- Ownership and contact details
- Name server identification
- Expiration date monitoring

##  AI Features

Network Scanner integrates AI to enhance security assessments:

- **Intelligent Analysis**: Automatically interprets scan results
- **Risk Assessment**: Prioritizes findings by severity and impact
- **Remediation Guidance**: Provides specific fix recommendations
- **Learning Mode**: Explains techniques for educational purposes
- **Contextual Chat**: Interactive AI assistant for security questions

##  Reporting

Generate professional security reports in multiple formats:

- **HTML Reports**: Interactive web-based reports with charts
- **PDF Reports**: Professional documents for stakeholders
- **JSON Exports**: Machine-readable data for integration
- **Executive Summaries**: High-level findings for management

##  Security Considerations

**Important**: Network Scanner is designed for authorized security testing only.

- Only scan systems you own or have explicit permission to test
- Some scans may be detected by security systems
- Follow responsible disclosure practices
- Respect rate limits and target system resources
- Review local laws and regulations before testing

##  Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/frangelbarrera/Network-Scanner.git
cd Network-Scanner

# Install development dependencies
pip install -r backend/requirements-dev.txt
npm install --dev --prefix frontend

# Run tests
pytest backend/tests/
npm test --prefix frontend
```

##  Support

-  **Documentation**: [Wiki](https://github.com/frangelbarrera/Network-Scanner/wiki)
-  **Bug Reports**: [Issues](https://github.com/frangelbarrera/Network-Scanner/issues)
-  **Discussions**: [GitHub Discussions](https://github.com/frangelbarrera/Network-Scanner/discussions)

##  Acknowledgments

- Built with Flask, React, and modern web technologies
- Integrates nmap, dnspython, and other security tools
- UI components from Material-UI
- Charts powered by Recharts
- AI capabilities via OpenAI API

##  Disclaimer

Network Scanner is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any systems. The developers assume no liability for misuse of this tool.

---

**Made with ❤️ for the cybersecurity community**