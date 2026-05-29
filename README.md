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
