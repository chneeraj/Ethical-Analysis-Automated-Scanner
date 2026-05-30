# 🔍 Ethical Analysis Automated Scanner

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.0+-green.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

A comprehensive web application vulnerability scanner that automatically detects SQL Injection, XSS, missing security headers, and sensitive data exposure across multiple websites simultaneously.

## ✨ Features

- **Multi-Website Scanning**: Scan multiple websites in a single run
- **Authentication Support**: Handles login forms with CSRF token detection
- **Vulnerability Detection**:
  - SQL Injection (Error-based and Tautology)
  - Reflected XSS (Cross-Site Scripting)
  - Missing Security Headers
  - Sensitive Data Exposure
  - IDOR (Insecure Direct Object References)
- **Report Generation**:
  - 📊 PDF Reports (Password-protected)
  - 📄 JSON Reports for programmatic analysis
- **Secure Output**: Password-protected ZIP archive containing all reports
- **Modern Web Interface**: Clean, responsive UI for easy interaction

## 🚀 Quick Start

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/ethical-analysis-automated-scanner.git
   cd ethical-analysis-automated-scanner
2. **Install required dependencies**
   ```bash
    pip install -r requirements.txt
3. **Run the application**
   ```bash
   python run.py
4. **Open your browser and navigate to:**
   ```bash
   http://localhost:5000

### 📋 Requirements

  Create a ```requirements.txt``` file with:
  ```
  Flask==2.3.3
  requests==2.31.0
  beautifulsoup4==4.12.2
  reportlab==4.0.4
  pyzipper==0.3.6
  ```

### 🎯 Usage

### 1. Basic Usage

Enter website details:

- **Base URL** (e.g., `http://example.com`)
- **Login URL** (if authentication is required)
- **Username and Password**

### 2. Optional Settings

- Set a password to protect reports

### 3. Start Scanning

1. Click the **"Scan Websites"** button
2. Download the password-protected ZIP archive

### Example Targets

**For testing purposes, you can use:**

| Target                | URL                                | Purpose                                  |
|-----------------------|------------------------------------|------------------------------------------|
| OWASP Juice Shop      | `http://localhost:3000`            | Modern vulnerable web app                |
| DVWA                  | `http://localhost/dvwa`            | Classic vulnerability testbed            |
| testphp.vulnweb.com   | `http://testphp.vulnweb.com`       | Public test site                         |

### Sample Test Configuration

```json
[
  {
    "base_url": "http://testphp.vulnweb.com",
    "login_url": "",
    "username": "test",
    "password": "test"
  }
]
```

## 🏗️ Project Structure

```
ethical-analysis-automated-scanner/
├── app/
│ ├── init.py # Flask app initialization
│ ├── routes.py # Web routes and request handling
│ ├── scanner.py # Core vulnerability scanner
│ ├── analyzer.py # Response analysis utilities
│ ├── config.py # Configuration settings
│ ├── report.py # Report generation
│ ├── utils.py # Helper functions
│ └── templates/
│ └── index.html # Web interface
├── reports/ # Generated reports (temporary)
├── scans/ # Scan data storage
├── static/ # Static assets (CSS, JS, images)
├── run.py # Application entry point
└── requirements.txt # Python dependencies
```

### 🔧 How It Works

1. **Authentication:** Automatically detects CSRF tokens and handles login forms

2. **Crawling:** Extracts all internal links from the target website

3. **Scanning:** Tests each discovered URL for vulnerabilities:

  - Injects SQL payloads to detect database errors

  - Injects XSS payloads to check for反射

  - Analyzes response headers for security gaps

  - Scans for exposed sensitive information

4. Reporting: Generates PDF and JSON reports with all findings

### 📊 Sample Report Output

The scanner produces two types of reports:

## PDF Report

- Professional formatted document

- Password protection support

- Tabulated vulnerability details

## JSON Report

```json

{
  "base_url": "http://example.com",
  "login_url": "http://example.com/login",
  "scan_date": "2024-01-15 14:30:00",
  "vulnerabilities": [
    {
      "url": "http://example.com/page?id=1",
      "vulnerability": "SQL Injection",
      "details": "Payload: ' OR '1'='1"
    }
  ]
}

```

### 🛡️ Legal Disclaimer

> ⚠️ Important: This tool is designed for ethical security testing only.

> - Only scan websites you own or have explicit permission to test

> - Unauthorized scanning may violate laws and regulations

> - The author assumes no liability for misuse of this tool

### 🤝 Contributing

  Contributions are welcome! Please follow these steps:

1. Fork the repository

2. Create a feature branch (git checkout -b feature/AmazingFeature)

3. Commit your changes (git commit -m 'Add some AmazingFeature')

4. Push to the branch (git push origin feature/AmazingFeature)

5. Open a Pull Request

### 🐛 Known Issues & Limitations

- SPA (Single Page Applications) have limited crawling support

- Complex JavaScript-rendered content may not be fully scanned

- Some advanced SQL injection techniques (blind, time-based) not implemented

- Rate limiting not implemented (use responsibly)

### 📈 Future Enhancements

- Blind SQL injection detection

- Time-based injection testing

- Command injection detection

- CSRF vulnerability scanning

- Rate limiting to avoid overwhelming targets

- Headless browser support for JavaScript rendering

- API endpoint fuzzing

- Multi-threaded scanning for performance

### 📝 Changelog

## v1.0.0 (Current)

- Initial release

- Basic SQL injection and XSS detection

- PDF and JSON report generation

- Multi-website support

### 📧 Contact

Neeraj Chirravuri - chneeraj97@gmail.com

Project Link: [https://github.com/chneeraj/Ethical-Analysis-Automated-Scanner.git]

### 🙏 Acknowledgments

- OWASP for vulnerability testing guidelines

- ReportLab for PDF generation

- Flask community for the excellent web framework
