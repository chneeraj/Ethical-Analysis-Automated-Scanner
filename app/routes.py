from flask import Blueprint, render_template, request, send_file, jsonify
from .scanner import scan_repository
from .utils import log_buffer, cleanup_files
import json
from io import BytesIO
import pyzipper
import os

main = Blueprint("main", __name__)

@main.route("/", methods=["GET", "POST"])
def index():
    log_buffer.seek(0)
    log_buffer.truncate(0)

    if request.method == "POST":
        websites = []
        report_password = request.form.get("report_password", "").strip()
        
        # Check if JSON input was provided
        json_input = request.form.get("websites", "").strip()
        
        if json_input:
            # Parse JSON input
            try:
                json_websites = json.loads(json_input)
                for site in json_websites:
                    websites.append({
                        "base_url": site.get("base_url", "").strip(),
                        "login_url": site.get("login_url", "").strip(),
                        "username": site.get("username", "").strip(),
                        "password": site.get("password", "")
                    })
            except json.JSONDecodeError as e:
                return f"Invalid JSON format: {str(e)}", 400
        else:
            # Handle regular form input
            base_urls = request.form.getlist("base_url")
            login_urls = request.form.getlist("login_url")
            usernames = request.form.getlist("username")
            passwords = request.form.getlist("password")

            for i, base in enumerate(base_urls):
                if not base.strip():
                    continue
                websites.append({
                    "base_url": base.strip(),
                    "login_url": login_urls[i].strip() if i < len(login_urls) else "",
                    "username": usernames[i].strip() if i < len(usernames) else "",
                    "password": passwords[i] if i < len(passwords) else ""
                })

        if not websites:
            return "No websites to scan", 400

        reports = []
        for site in websites:
            result = scan_repository(site, report_password)
            reports.append(result)

        # Create ZIP file with reports
        zip_buffer = BytesIO()
        zip_password = report_password.encode('utf-8') if report_password else None

        with pyzipper.AESZipFile(zip_buffer, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
            if zip_password:
                zf.setpassword(zip_password)
            for report in reports:
                if report.get('pdf_report') and os.path.exists(report['pdf_report']):
                    zf.write(report['pdf_report'], os.path.basename(report['pdf_report']))
                if report.get('json_report') and os.path.exists(report['json_report']):
                    zf.write(report['json_report'], os.path.basename(report['json_report']))

        # Clean up temporary files
        files_to_cleanup = []
        for report in reports:
            if report.get('pdf_report'):
                files_to_cleanup.append(report['pdf_report'])
            if report.get('json_report'):
                files_to_cleanup.append(report['json_report'])
        cleanup_files(files_to_cleanup)

        zip_buffer.seek(0)
        return send_file(zip_buffer, as_attachment=True, download_name="reports.zip", mimetype="application/zip")

    return render_template("index.html")