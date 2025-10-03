Automated Web Vulnerability Scanner (AWVS)
Project Overview
Automated Web Vulnerability Scanner (AWVS) is a Python-Flask-based application designed for deep, authenticated web security testing. It automates vulnerability discovery—like SQL Injection, Cross-Site Scripting, and Insecure Direct Object Reference (IDOR)—in modern web applications, with special attention to authenticated user areas that are commonly missed by traditional scanners. This project was developed by Neeraj Chirravuri for the MSc in Cyber Security at the University of Roehampton.

Problem Statement
Modern web applications have dynamic, authenticated attack surfaces where critical vulnerabilities may be hidden. Manual security reviews are time-consuming and often miss post-login flaws, risking privacy breaches, financial loss, and compliance violations. AWVS addresses the urgent need for an agile, reproducible security assessment tool that penetrates authenticated user spaces and delivers actionable results for both developers and stakeholders.

Key Features
Authenticated Scanning: Simulates real user login, including CSRF token handling, to access protected resources.

Targeted Vulnerability Testing: Detects Reflected XSS, Error-Based SQLi, IDOR in API endpoints, and missing critical HTTP security headers.

Single-Page Application (SPA) Awareness: Heuristically discovers routes/API endpoints often hidden from simple crawlers.

Robust Reporting: Outputs both stakeholder-friendly PDFs and machine-readable JSON reports.

Secure by Design: Implements encryption, user authentication, auto-deletion of sensitive reports, and mandatory user compliance warnings for ethical use.

Technical Stack
Backend: Python 3.x

Framework: Flask (local web server for orchestration and UI)

Core Libraries: requests, BeautifulSoup, urllib.parse, reportlab

Frontend: HTML/JavaScript (dynamic forms for input, JSON asset lists)

PDF Generation: reportlab

Data Security: AES-256 encrypted output, access control with Flask.

Project Structure and Main Components
webapp.py — All-in-one script: website scanning logic, web server, report generation.

WebsiteScanner class — Handles login, crawling, vulnerability scans, report formatting.

Modules:

Login/CSRF manager

Spider/crawler (HTML and SPA-aware)

Vulnerability modules (SQLi, XSS, IDOR, header/config check)

PDF/JSON reporting engine

User-facing web UI for entering scan targets and receiving reports.

Example scan reports and demonstration screencast.

Usage
Clone/download the repository and required files (including webapp.py).

Install dependencies (pip install -r requirements.txt).

Run the Flask app:

text
python webapp.py
Navigate to the local web interface as instructed in the terminal.

Enter targets: Provide base URL, login credentials, and (optionally) POST login URL.

Launch scan and receive PDF/JSON report downloads.

Example
json
[
  {
    "baseurl": "https://example.com",
    "loginurl": "https://example.com/login",
    "username": "testuser",
    "password": "password123"
  }
]
Evaluation and Results
Validated against known vulnerable web environments.

AWVS reduced initial vulnerability scan time from ~48 hours to under 5 minutes.

Detected all tested cases of Reflected XSS and error-based SQLi, plus multiple IDOR issues in test APIs.

Integrates seamlessly into development cycles for proactive security assurance.

Limitations
Does not handle advanced CAPTCHAs, MFA, or stored/blind SQLi.

Focuses on URLEncoded flaws, not complex business logic.

No headless browser; limited to what is exposed via HTTP(S) and parsed HTML/SPA logic.

Ethical and Legal Compliance
Ethical Use Only: Scanning is intrusive and must have asset owner’s written consent.

User Authentication: All reports are encrypted and auto-deleted after seven days.

Code of Conduct: Explicit disclaimers warn against misuse; compliance is mandatory.

Acknowledgments
Supervisor: Mastaneh Davis

Faculty and colleagues, University of Roehampton

Open source community (Flask, requests, BeautifulSoup, reportlab)

Reference standards: OWASP Top 10, responsible disclosure guidelines.

References
OWASP Top 10, 2021

Geeks for Geeks, Stack Overflow

Academic literature on web application security, automated scanning, and ethical vulnerability disclosure.

