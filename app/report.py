import json
import os
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

def generate_pdf_report(scanner, filename=None):

    if not scanner.vulnerabilities:
        return None

    if not filename:
        filename = (
            f"vulnerability_report_"
            f"{scanner.base_url.replace('://', '_').replace('/', '_')}.pdf"
        )

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4,
        encrypt=scanner.report_password.encode('utf-8')
        if scanner.report_password else None
    )

    styles = getSampleStyleSheet()

    small_style = ParagraphStyle(
        'Small',
        fontSize=9,
        leading=11
    )

    title = Paragraph(
        f"Vulnerability Report for {scanner.base_url}",
        styles['Title']
    )

    elements = [title, Spacer(1, 12)]

    data = [[
        Paragraph("<b>URL</b>", small_style),
        Paragraph("<b>Vulnerability</b>", small_style),
        Paragraph("<b>Details</b>", small_style)
    ]]

    for entry in scanner.vulnerabilities:

        data.append([
            Paragraph(entry["url"], small_style),
            Paragraph(entry["vulnerability"], small_style),
            Paragraph(entry["details"], small_style)
        ])

    table = Table(
        data,
        colWidths=[2.5 * inch, 1.5 * inch, 3.0 * inch]
    )

    table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.25, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke)
    ]))

    elements.append(table)

    doc.build(elements)

    return os.path.abspath(filename)

def generate_json_report(scanner, filename=None):

    if not filename:

        filename = (
            f"vulnerability_report_"
            f"{scanner.base_url.replace('://', '_').replace('/', '_')}.json"
        )

    with open(filename, 'w') as f:

        json.dump(scanner.scan_results, f, indent=2)

    return os.path.abspath(filename)