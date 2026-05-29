import requests
import logging
import json
import os
from urllib.parse import urljoin, unquote
from datetime import datetime
from bs4 import BeautifulSoup

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph,
    Spacer
)
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)
from reportlab.lib.units import inch

class WebsiteScanner:
    def __init__(self, base_url, login_url, username, password, report_password):
        self.session = requests.Session()
        self.base_url = base_url.rstrip('/')
        self.login_url = login_url.rstrip('/') if login_url else None
        self.username = username
        self.password = password
        self.report_password = report_password
        self.vulnerabilities = []
        self.scan_results = {
            'base_url': base_url,
            'login_url': login_url,
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'vulnerabilities': []
        }

    def login(self):
        login_url = self.login_url if self.login_url else urljoin(self.base_url, 'login.php')
        
        try:
            login_page = self.session.get(login_url, timeout=10)
            login_page.raise_for_status()
            
            soup = BeautifulSoup(login_page.text, 'html.parser')
            
            login_data = {
                "username": self.username,
                "password": self.password,
                "Login": "Login"
            }
            
            token_input = soup.find('input', {'name': 'user_token'}) or \
                         soup.find('input', {'name': 'csrf_token'}) or \
                         soup.find('input', {'name': 'token'})
            
            if token_input:
                login_data[token_input['name']] = token_input.get('value', '')
            
            response = self.session.post(
                login_url,
                data=login_data,
                allow_redirects=True,
                timeout=10
            )
            
            success_indicators = [
                "logout" in response.text.lower(),
                "log out" in response.text.lower(),
                "sign out" in response.text.lower(),
                "welcome" in response.text.lower(),
                self.username.lower() in response.text.lower()
            ]
            
            return any(success_indicators)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"[LOGIN] Login failed for {self.base_url}: {str(e)}")
            return False

    def crawl(self):
        try:
            response = self.session.get(self.base_url, timeout=10)
            response.raise_for_status()
            
            if self.is_spa(response.text):
                self.add_vulnerability(
                    self.base_url,
                    "SPA Detected",
                    "JavaScript single-page application detected. Traditional crawling may be limited."
                )
                return self.get_spa_routes(response.text)
                
            soup = BeautifulSoup(response.text, "html.parser")
            links = [urljoin(self.base_url, link.get("href")) for link in soup.find_all("a", href=True)]
            filtered = list(set(link for link in links if not link.startswith(('javascript:', 'mailto:')) and link.startswith(('http://','https://'))))
            return filtered
        except Exception as e:
            logging.error(f"[CRAWL] Crawling failed for {self.base_url}: {str(e)}")
            return []

    def is_spa(self, html):
        spa_indicators = [
            "<div id=\"app\">", "<div id=\"root\">", "react-dom", "angular.module", "Vue.createApp", "window.__NUXT__"
        ]
        return any(indicator in html for indicator in spa_indicators)

    def get_spa_routes(self, html):
        common_routes = [
            '/login', '/register', '/dashboard', '/profile', '/settings', '/api', '/users', '/admin', '/contact'
        ]
        return [urljoin(self.base_url, route) for route in common_routes]

    def scan_url(self, url):
        if '#/' in url:
            self.add_vulnerability(
                url, "Client-Side Routing", "Hash-based routing detected. Server-side scanning may be limited."
            )
            return
            
        try:
            response = self.session.get(url, timeout=10)
            
            if self.is_api_endpoint(url, response):
                self.test_api_endpoints(url)
                return
                
            self.test_sql_injection(url)
            self.test_xss(url)
            self.check_common_vulns(url, response)
            
        except Exception as e:
            logging.error(f"[SCAN] Scan error for {url}: {str(e)}")

    def is_api_endpoint(self, url, response):
        api_indicators = [
            '/api/' in url, url.endswith(('.json', '.xml')),
            'application/json' in response.headers.get('Content-Type', ''),
            'application/xml' in response.headers.get('Content-Type', '')
        ]
        return any(api_indicators)

    def test_api_endpoints(self, url):
        try:
            test_ids = [1, 2, 1000, 'admin', 'test']
            for test_id in test_ids:
                test_url = f"{url.rstrip('/')}/{test_id}"
                try:
                    response = self.session.get(test_url, timeout=10)
                    if response.status_code == 200 and len(response.text) > 0:
                        self.add_vulnerability(url, "Insecure Direct Object Reference (IDOR)", f"Accessible resource at {test_url}")
                        break
                except:
                    continue
                    
            try:
                auth_response = self.session.get(url, timeout=10)
                if auth_response.status_code == 200 and 'auth' not in url.lower():
                    self.add_vulnerability(url, "Missing Authentication", "API endpoint accessible without authentication")
            except:
                pass
                
        except Exception as e:
            logging.error(f"[API TEST] API test failed for {url}: {str(e)}")

    def test_sql_injection(self, url):
        sql_payloads = [
            "' OR '1'='1", "' OR 1=1--",
            "1 AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--",
            "1' UNION SELECT username, password FROM users--"
        ]
        
        for payload in sql_payloads:
            test_url = self.add_payload_to_url(url, payload)
            try:
                response = self.session.get(test_url, timeout=10)
                if any(indicator in response.text.lower() for indicator in ['sql', 'syntax', 'error', 'exception', 'warning']):
                    self.add_vulnerability(url, "SQL Injection (Error/Tautology)", f"Payload: {payload}")
                    break
            except:
                continue

    def test_xss(self, url):
        xss_payloads = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "%3Cscript%3Ealert(1)%3C/script%3E", "\"><script>alert(1)</script>", "javascript:alert(1)"
        ]
        
        for payload in xss_payloads:
            test_url = self.add_payload_to_url(url, payload)
            try:
                response = self.session.get(test_url, timeout=10)
                if payload in response.text or unquote(payload) in response.text:
                    self.add_vulnerability(url, "Reflected XSS", f"Payload: {payload}")
                    break
            except:
                continue

    def add_payload_to_url(self, url, payload):
        if '?' not in url:
            return f"{url}?test={payload}"
        else:
            return f"{url}&test={payload}"

    def check_common_vulns(self, url, response):
        missing = []
        headers = response.headers
        for header in ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection"]:
            if header not in headers:
                missing.append(header)
        if missing:
            self.add_vulnerability(url, "Missing Security Headers", ", ".join(missing))
            
        sensitive_keywords = ['password', 'secret', 'api_key', 'token']
        if any(keyword in response.text.lower() for keyword in sensitive_keywords):
            self.add_vulnerability(url, "Possible Sensitive Data Exposure", "Sensitive keywords found in response body/headers")

    def add_vulnerability(self, url, vuln_type, details):
        vuln = {"url": url, "vulnerability": vuln_type, "details": details}
        self.vulnerabilities.append(vuln)
        self.scan_results['vulnerabilities'].append(vuln)

    def generate_pdf_report(self, filename=None):
        if not self.vulnerabilities:
            return None

        if not filename:
            filename = f"vulnerability_report_{self.base_url.replace('://', '_').replace('/', '_')}.pdf"
        
        # --- PDF Password Protection ---
        # Password protection is set during SimpleDocTemplate initialization
        doc = SimpleDocTemplate(
            filename, 
            pagesize=A4, 
            encrypt=self.report_password.encode('utf-8') if self.report_password else None
        )
        
        styles = getSampleStyleSheet()
        small_style = ParagraphStyle('Small', fontSize=9, leading=11)
        
        title = Paragraph(f"Vulnerability Report for {self.base_url}", styles['Title'])
        scan_date = Paragraph(f"Scan Date: {self.scan_results['scan_date']}", styles['Normal'])
        
        elements = [title, scan_date, Spacer(1, 12)]

        data = [[
            Paragraph("<b>URL</b>", small_style), Paragraph("<b>Vulnerability</b>", small_style), Paragraph("<b>Details</b>", small_style)
        ]]

        for entry in self.vulnerabilities:
            data.append([
                Paragraph(entry["url"], small_style),
                Paragraph(entry["vulnerability"], small_style),
                Paragraph(entry["details"], small_style)
            ])

        table = Table(data, colWidths=[2.5 * inch, 1.5 * inch, 3.0 * inch])
        table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
        ]))

        elements.append(table)
        doc.build(elements)
        return os.path.abspath(filename)

    def generate_json_report(self, filename=None):
        if not filename:
            filename = f"vulnerability_report_{self.base_url.replace('://', '_').replace('/', '_')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        return os.path.abspath(filename)

def scan_repository(site, report_password):

    scanner = WebsiteScanner(
        site['base_url'],
        site['login_url'],
        site['username'],
        site['password'],
        report_password
    )

    logging.info(f"[START] Starting scan for {scanner.base_url}")

    scanner.login()

    urls = scanner.crawl() or []

    if scanner.base_url not in urls:
        urls.append(scanner.base_url)

    urls = list({
        u for u in urls
        if isinstance(u, str)
        and u.startswith(('http://', 'https://'))
    })

    for url in urls:

        if "logout" not in url.lower():
            logging.info(f"[SCAN] Scanning {url}")
            scanner.scan_url(url)

    pdf_path = scanner.generate_pdf_report()
    json_path = scanner.generate_json_report()

    return {
        "base_url": scanner.base_url,
        "pdf_report": pdf_path,
        "json_report": json_path,
        "vulnerabilities": len(scanner.vulnerabilities)
    }