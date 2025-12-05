# Kali AI Recon Tool - Complete Automated Reconnaissance Platform

## 🚀 Overview

Kali AI Recon Tool is a comprehensive, automated reconnaissance platform that integrates 40+ Kali Linux tools into a single web-based interface. Designed for bug bounty hunters, penetration testers, and security researchers, it streamlines the entire reconnaissance process with AI-powered analysis and real-time progress tracking.

## ✨ Features

### 🛡️ **Core Capabilities**
- **Single-File Implementation**: All tools integrated into one Python file
- **Modern Web Interface**: Beautiful, responsive dashboard with real-time updates
- **Multiple Scan Types**: Quick, Full, and OSINT scanning modes
- **Real-time Progress Tracking**: Live progress updates via WebSockets
- **Automated Reporting**: JSON reports with risk assessment and recommendations

### 🔍 **Reconnaissance Modules**
1. **Passive Recon**
   - WHOIS Lookup
   - DNS Enumeration
   - Subdomain Discovery
   - SSL/TLS Analysis
   - Technology Detection

2. **Active Scanning**
   - Port Scanning (Nmap integration)
   - Service Detection
   - Directory Bruteforce
   - Vulnerability Scanning
   - Web Application Analysis

3. **OSINT Collection**
   - Social Media Intelligence
   - Breach Data Checking
   - Threat Intelligence
   - GeoIP Lookup
   - WAF Detection

4. **AI Analysis**
   - Risk Assessment Scoring
   - Pattern Detection
   - Threat Level Classification
   - Automated Recommendations
   - Visual Analytics

## 📋 Requirements

### System Requirements
- **Operating System**: Kali Linux or any Linux distribution
- **Python**: 3.8 or higher
- **Memory**: 4GB RAM minimum (8GB recommended)
- **Storage**: 2GB free space

### Kali Tools Required
The following Kali Linux tools should be installed for full functionality:

```bash
# DNS & Network Tools
apt-get install nmap dnsutils whois dnsrecon sublist3r amass whatweb wafw00f

# Web Scanning Tools
apt-get install gobuster nikto nuclei

# Additional Utilities
apt-get install ssl-cert curl wget git
```

## 🚦 Installation

### Method: Quick Start (Recommended)

```bash
# 1. Clone or download the tool
git clone https://github.com/ritikshrivas-ai/Kali-AI-Recon-Tool
cd Kali-AI-Recon-Tool

# 2. Install Python dependencies
pip install flask flask-socketio requests beautifulsoup4 python-nmap python-whois dnspython

# 3. Ensure Kali tools are installed
./setup_kali_tools.sh

# 4. Run the tool
python app.py
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file for API keys:

```env
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
SECRET_KEY=your_secret_key_here
```

### File Structure
```
kali-ai-recon-tool/
├── kali.py              # Main application file
├── requirements.txt     # Python dependencies
├── output/             # Scan results directory
├── wordlists/          # Custom wordlists (optional)
└── templates/          # HTML templates (embedded)
```

## 📖 Usage

### Starting the Server

```bash
# Default start
python app.py

# Custom port
python app.py --port 8080

# Production mode (no debug)
python app.py --production

# With specific IP binding
python app.py --host 192.168.1.100 --port 5000
```

### Web Interface Access
1. Start the tool
2. Open browser and navigate to: `http://localhost:5000`
3. Enter target (domain or IP)
4. Select scan type
5. Click "Launch Reconnaissance"

### Scan Types

| Scan Type | Description | Time Required |
|-----------|-------------|---------------|
| **Quick** | Basic DNS, WHOIS, and port scan | 2-5 minutes |
| **Full**  | Comprehensive scan with all modules | 10-20 minutes |
| **OSINT** | Open Source Intelligence gathering | 5-10 minutes |

### API Endpoints

```http
POST /start_scan
Content-Type: application/x-www-form-urlencoded
target=example.com&scan_type=full

GET /scan_status
Returns: JSON with current scan progress

GET /results/<target>
Returns: HTML results page for target

GET /api/v1/quick_scan/<target>
Returns: JSON with quick scan results

GET /dashboard
Returns: Scan history dashboard

GET /download/<filename>
Returns: Download JSON report
```

## 🛠️ Tool Integration

### Integrated Kali Tools
The platform integrates with these Kali Linux tools:

| Category | Tools Integrated |
|----------|------------------|
| **DNS** | nslookup, dig, host, dnsrecon |
| **Subdomains** | sublist3r, amass, crt.sh |
| **Port Scanning** | nmap, masscan (if installed) |
| **Web Scanning** | whatweb, wafw00f, nikto, nuclei, gobuster |
| **OSINT** | whois, shodan (API), virustotal (API) |
| **SSL** | openssl, sslscan |

### Custom Tool Integration
To add custom tools, modify the `ToolRunner` class:

```python
class ToolRunner:
    @staticmethod
    def run_custom_tool(target):
        command = f"your_tool {target} --options"
        return ToolRunner.run_command(command)
```

## 📊 Output & Reports

### Report Structure
```json
{
  "summary": {
    "target": "example.com",
    "scan_duration": "0:05:23",
    "total_findings": 45,
    "risk_level": "Medium",
    "recommendations": ["Close port 22", "Update SSL certificate"]
  },
  "passive": { ... },
  "active": { ... },
  "osint": { ... },
  "vulnerabilities": { ... },
  "ai_analysis": { ... },
  "timeline": [ ... ]
}
```

### Export Options
- **JSON Report**: Full detailed report
- **HTML Report**: Formatted HTML output
- **CSV Summary**: Basic findings export
- **Markdown**: For documentation

## 🤖 AI Analysis Features

### Risk Scoring Algorithm
The AI analyzer evaluates:
1. **Port Exposure** (Weight: 30%)
2. **Vulnerability Count** (Weight: 40%)
3. **SSL/TLS Issues** (Weight: 15%)
4. **OSINT Threats** (Weight: 15%)

### Threat Levels
- **Low (0-39)**: Minimal risks
- **Medium (40-69)**: Moderate risks
- **High (70-100)**: Critical risks requiring immediate attention

### Automated Recommendations
Based on scan results, the AI provides:
- Security hardening suggestions
- Patch management advice
- Configuration improvements
- Compliance recommendations

## 🔒 Security Considerations

### Safe Usage Guidelines
1. **Authorized Testing Only**: Only scan systems you own or have written permission to test
2. **Rate Limiting**: Respect target server resources
3. **Legal Compliance**: Adhere to local and international laws
4. **Data Protection**: Securely store scan results
5. **Disclosure**: Responsibly disclose findings to owners

### Built-in Protections
- Target validation to prevent scanning internal IPs
- Rate limiting for API calls
- Session-based authentication (optional)
- Scan queue management

## 🐛 Troubleshooting

### Common Issues

**Issue**: "Command not found" errors
**Solution**: Install missing Kali tools:
```bash
sudo apt-get update && sudo apt-get install [missing-tool]
```

**Issue**: Flask/SocketIO connection errors
**Solution**: Update dependencies:
```bash
pip install --upgrade flask flask-socketio
```

**Issue**: Slow scans
**Solution**: Adjust timeout settings in config:
```python
# Increase timeout in ToolRunner.run_command
timeout=60  # Increase from 30 seconds
```

**Issue**: API keys not working
**Solution**: Verify environment variables:
```bash
echo $SHODAN_API_KEY
# Should display your API key
```

### Debug Mode
Enable verbose logging:
```bash
python app.py --debug
```

## 📈 Performance Optimization

### Scan Optimization Tips
1. **Quick Scans**: Use for initial reconnaissance
2. **Parallel Scanning**: Enable multi-threading in config
3. **Cached Results**: Reuse DNS lookups when possible
4. **Target Segmentation**: Scan subdomains separately

### Resource Management
- **Memory**: Each scan uses ~200-500MB RAM
- **CPU**: Multi-core support for parallel tasks
- **Network**: Bandwidth usage optimized with connection pooling

## 🤝 Contributing

We welcome contributions! Here's how:

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Submit a pull request**

### Development Setup
```bash
# Set up development environment
git clone https://github.com/yourusername/kali-ai-recon-tool.git
cd kali-ai-recon-tool
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
```

### Code Standards
- Follow PEP 8 style guide
- Add docstrings to new functions
- Include unit tests for new features
- Update documentation accordingly

## 📄 License

MIT License - See LICENSE file for details

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for:
- Educational purposes
- Authorized security testing
- Professional penetration testing
- Bug bounty programs with permission

**DO NOT USE** for:
- Unauthorized testing
- Malicious purposes
- Illegal activities

The developers are not responsible for any misuse or damage caused by this tool.

---

**Made with ❤️ for the security community**

**Version**: 1.0  
**Last Updated**: 2025  
**Maintainer**: Ritik Shrivas
