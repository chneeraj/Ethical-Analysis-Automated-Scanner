import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, unquote
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from flask import Flask, render_template_string, request, send_file
import os
import json
from datetime import datetime
import logging
from io import StringIO, BytesIO 
import zipfile
import pyzipper 

# --- Security and Logging Setup ---

# Configure logging to capture console output to a string buffer
log_buffer = StringIO()
log_handler = logging.StreamHandler(log_buffer)
log_handler.setFormatter(logging.Formatter('%(levelname)s:%(message)s'))

# Set the root logger to capture our custom messages
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(log_handler)

# Temporarily remove any handlers from Werkzeug that might cause startup issues
logging.getLogger('werkzeug').handlers = []

# --- Flask App Initialization ---
app = Flask(__name__)

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


@app.route('/', methods=['GET', 'POST'])
def index():
    # Clear log buffer for a new request
    log_buffer.seek(0)
    log_buffer.truncate(0)

    if request.method == 'POST':
        websites = []
        reports = []
        
        # Get the global password from the form
        report_password = request.form.get('report_password', '').strip()
        
        # --- Input Parsing ---
        websites_json = request.form.get('websites', '').strip()
        if websites_json:
            try:
                websites_data = json.loads(websites_json)
                for site in websites_data:
                    websites.append({
                        'base_url': site['base_url'].strip(),
                        'login_url': site.get('login_url', '').strip(),
                        'username': site['username'].strip(),
                        'password': site['password']
                    })
            except json.JSONDecodeError:
                return "Invalid websites JSON data", 400
        else:
            base_urls = request.form.getlist('base_url')
            login_urls = request.form.getlist('login_url')
            usernames = request.form.getlist('username')
            passwords = request.form.getlist('password')

            for i, base in enumerate(base_urls):
                if not base or not base.strip():
                    continue
                login_val = login_urls[i].strip() if i < len(login_urls) and login_urls[i] else ''
                username_val = usernames[i].strip() if i < len(usernames) and usernames[i] else ''
                password_val = passwords[i] if i < len(passwords) else ''
                websites.append({
                    'base_url': base.strip(),
                    'login_url': login_val,
                    'username': username_val,
                    'password': password_val
                })

        if not websites:
            return "No websites provided", 400

        # --- Scanning and Report Generation ---
        
        for site in websites:
            if not site['base_url'].startswith(('http://', 'https://')):
                logging.warning(f"[SKIP] Skipping invalid base_url: {site['base_url']}")
                continue
                
            scanner = WebsiteScanner(
                site['base_url'],
                site['login_url'] if site['login_url'] else None,
                site['username'],
                site['password'],
                report_password
            )
            
            logging.info(f"[START] Starting scan for {scanner.base_url}")
            logged_in = scanner.login()
            
            urls = scanner.crawl() or []
            if scanner.base_url not in urls:
                urls.append(scanner.base_url)
            urls = list({u for u in urls if isinstance(u, str) and u.startswith(('http://','https://'))})
            
            for url in urls:
                if "logout" not in url.lower():
                    logging.info(f"[SCAN] Scanning {url}")
                    scanner.scan_url(url)
            
            pdf_path = scanner.generate_pdf_report()
            json_path = scanner.generate_json_report()
            
            if pdf_path or json_path:
                reports.append({
                    'base_url': scanner.base_url,
                    'pdf_report': pdf_path,
                    'json_report': json_path,
                    'vulnerabilities': len(scanner.vulnerabilities)
                })

            logging.info(f"[DONE] Finished scan for {scanner.base_url}: {len(scanner.vulnerabilities)} vulnerabilities found")

        if not reports:
            return "No valid websites were scanned or no reports were generated."

        # --- Final Report Packaging (Password-Protected ZIP) ---

        log_buffer.seek(0)
        log_content = log_buffer.read() # Read string content from StringIO
        log_filename = "scan_log.txt"
        log_path = os.path.abspath(log_filename)
        
        # Write string log content to a file
        with open(log_path, 'w', encoding='utf-8') as f:
            f.write(log_content)
        
        # Create the final ZIP file using pyzipper for password protection
        zip_buffer = BytesIO() 

        zip_password = report_password.encode('utf-8') if report_password else None

        # Corrected Indentation Block for pyzipper
        with pyzipper.AESZipFile(
            zip_buffer, 
            'w', 
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES
        ) as zf:
            
            # Set the global password on the ZipFile object
            if zip_password:
                zf.setpassword(zip_password)
                # Set encryption only if password exists, using the more compatible ZIP_DEFLATED 
                # (which forces P-KWARE if AES fails)
                 
            for report in reports:
                if report['pdf_report'] and os.path.exists(report['pdf_report']):
                    # When writing, we do not need to specify encryption again; it inherits from setencryption()
                    zf.write(report['pdf_report'], os.path.basename(report['pdf_report']))
                if report['json_report'] and os.path.exists(report['json_report']):
                    zf.write(report['json_report'], os.path.basename(report['json_report']))
            
            # Log file is also written with the same encryption settings
            zf.write(log_path, os.path.basename(log_path))
        
        # 5. Clean up temporary files
        all_files = [report['pdf_report'] for report in reports if report['pdf_report']]
        all_files += [report['json_report'] for report in reports if report['json_report']]
        all_files += [log_path]
        for f in all_files:
            try:
                if os.path.exists(f):
                    os.remove(f)
            except Exception as e:
                logging.error(f"Error cleaning up temporary file {f}: {e}")

        zip_buffer.seek(0)
        
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name='password_protected_reports.zip',
            mimetype='application/zip'
        )

    # --- GET Request (HTML Interface) ---
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Advanced Vulnerability Scanner</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .form-container { max-width: 800px; margin: 0 auto; }
                .website-form { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                .form-group { margin-bottom: 10px; }
                label { display: inline-block; width: 120px; font-weight: bold; }
                input[type="text"], input[type="password"] { 
                    padding: 8px; width: 300px; border: 1px solid #ddd; border-radius: 4px; 
                }
                button { 
                    padding: 8px 15px; margin: 5px; background: #4CAF50; color: white; 
                    border: none; border-radius: 4px; cursor: pointer; 
                }
                button:hover { background: #45a049; }
                #websites-container { margin-bottom: 20px; }
                .remove-btn { background: #f44336; }
                .remove-btn:hover { background: #d32f2f; }
                .json-btn { background: #219; }
            .json-btn:hover { background: #1976d2; }
            textarea { width: 100%; height: 150px; }
            .password-input { background: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 15px; }
        </style>
        <script>
            function addWebsiteBlock() {
                const container = document.getElementById('websites-container');
                const block = document.createElement('div');
                block.className = 'website-form';
                block.innerHTML = `
                    <div class="form-group"><label>Base URL</label><input type="text" name="base_url" placeholder="https://example.com"></div>
                    <div class="form-group"><label>Login URL</label><input type="text" name="login_url" placeholder="https://example.com/login.php"></div>
                    <div class="form-group"><label>Username</label><input type="text" name="username" placeholder="admin"></div>
                    <div class="form-group"><label>Password</label><input type="password" name="password" placeholder="password"></div>
                    <div><button type="button" class="remove-btn" onclick="removeBlock(this)">Remove</button></div>
                `;
                container.appendChild(block);
            }

            function removeBlock(btn) {
                const block = btn.closest('.website-form');
                if (block) block.remove();
            }

            function toggleJsonEditor() {
                const editor = document.getElementById('json-editor');
                editor.style.display = editor.style.display === 'none' ? 'block' : 'none';
            }

            window.onload = function() {
                if (!document.querySelectorAll('.website-form').length) addWebsiteBlock();
            };
        </script>
        </head>
        <body>
            <div class="form-container">
                <h1>Advanced Vulnerability Scanner</h1>
                <p>The scanner will create a ZIP archive containing all reports and logs. Enter a password below to protect the contents.</p>
                <form method="post">
                    
                    <div class="password-input">
                        <div class="form-group">
                            <label>Report Password</label>
                            <input type="password" name="report_password" placeholder="Enter password to protect reports (optional)">
                            <p style="font-size: 0.8em; color: #555; margin-top: 5px;">This password protects the PDF files and the final ZIP file containing the JSON reports and logs.</p>
                        </div>
                    </div>

                    <div id="websites-container"></div>
                    <div>
                        <button type="button" onclick="addWebsiteBlock()">Add Website</button>
                        <button type="button" class="json-btn" onclick="toggleJsonEditor()">Toggle JSON Editor</button>
                    </div>
                    
                    <div id="json-editor" style="display:none;">
                        <p>You can also paste a JSON array:</p>
                        <pre>[
  {
    "base_url": "https://example.com",
    "login_url": "https://example.com/login.php",
    "username": "admin",
    "password": "password"
  }
]</pre>
                        <label for="websites">Websites JSON</label>
                        <textarea name="websites" id="websites" placeholder='Paste JSON here...'></textarea>
                    </div>
                    <div style="margin-top:15px;">
                        <button type="submit">Scan Websites</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
    ''')
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
