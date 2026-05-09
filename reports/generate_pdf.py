import json
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter

REPORT_JSON = "reports/final_risk_report.json"
OUTPUT_PDF = "reports/final_security_report.pdf"

with open(REPORT_JSON) as f:
    report = json.load(f)

styles = getSampleStyleSheet()

doc = SimpleDocTemplate(
    OUTPUT_PDF,
    pagesize=letter
)

story = []

# Title
story.append(Paragraph("Android APK Security Analysis Report", styles['Title']))
story.append(Spacer(1, 20))

# Overall Risk
story.append(Paragraph(
    f"<b>Overall Risk:</b> {report.get('overall_risk', 'UNKNOWN')}",
    styles['Heading2']
))

story.append(Spacer(1, 12))

# Summary
story.append(Paragraph("Static Findings Summary", styles['Heading2']))

summary = report.get("static_summary", {})

for category, count in summary.items():
    text = f"• {category}: {count}"
    story.append(Paragraph(text, styles['BodyText']))

story.append(Spacer(1, 12))

# Runtime Findings
story.append(Paragraph("Runtime Analysis", styles['Heading2']))

story.append(Paragraph(
    f"Dynamic Log Findings: {report.get('dynamic_logcat_findings_count', 0)}",
    styles['BodyText']
))

story.append(Paragraph(
    f"Dynamic Network Findings: {report.get('dynamic_network_findings_count', 0)}",
    styles['BodyText']
))

story.append(Spacer(1, 12))

# Risk Reasoning
story.append(Paragraph("Risk Reasoning", styles['Heading2']))

for reason in report.get("risk_reasoning", []):
    story.append(Paragraph(f"• {reason}", styles['BodyText']))

story.append(Spacer(1, 12))

# Recommendations
story.append(Paragraph("Recommendations", styles['Heading2']))

recommendations = [
    "Remove hardcoded credentials from source code.",
    "Use Android Keystore for sensitive secrets.",
    "Avoid plaintext HTTP communication.",
    "Avoid storing sensitive information in local databases.",
    "Disable sensitive debug logging in production builds."
]

for rec in recommendations:
    story.append(Paragraph(f"• {rec}", styles['BodyText']))

# Generate PDF

doc.build(story)

print(f"[+] PDF report generated: {OUTPUT_PDF}")
