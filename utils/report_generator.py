import os
import datetime
from typing import Dict, Any, List

# Standard libraries for plotting and PDF creation
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_charts(report_data: Dict[str, Any], output_dir: str) -> Dict[str, str]:
    """
    Generates vulnerability distribution charts using matplotlib.
    Returns a dictionary of generated chart file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    generated_charts = {}
    
    # 1. Severity Distribution Chart (Pie Chart)
    sev_summary = report_data.get("severity_summary", {})
    if sev_summary:
        labels = list(sev_summary.keys())
        sizes = list(sev_summary.values())
        colors_map = {
            "CRITICAL": "#990000",
            "HIGH": "#CC0000",
            "MEDIUM": "#FF8800",
            "LOW": "#33B5E5",
            "INFO": "#99CC00"
        }
        pie_colors = [colors_map.get(l.upper(), "#999999") for l in labels]

        plt.figure(figsize=(6, 5))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, colors=pie_colors,
                textprops={'fontsize': 11, 'weight': 'bold'})
        plt.title("Vulnerability Severity Distribution", fontsize=14, weight='bold', pad=20)
        plt.tight_layout()
        pie_path = os.path.join(output_dir, "severity_pie.png")
        plt.savefig(pie_path, dpi=150)
        plt.close()
        generated_charts["severity_pie"] = pie_path

    # 2. Category Distribution Chart (Bar Chart)
    cat_summary = report_data.get("category_summary", {})
    if cat_summary:
        categories = list(cat_summary.keys())
        counts = list(cat_summary.values())
        
        # Truncate long category names for chart readability
        display_categories = [c[:20] + "..." if len(c) > 20 else c for c in categories]

        plt.figure(figsize=(7, 5))
        bars = plt.barh(display_categories, counts, color="#0099CC")
        plt.xlabel("Finding Count", fontsize=11, weight='bold')
        plt.title("Findings by Security Category", fontsize=14, weight='bold', pad=20)
        
        # Add labels to the ends of the bars
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height()/2, f'{int(width)}',
                     va='center', ha='left', weight='bold')

        plt.tight_layout()
        bar_path = os.path.join(output_dir, "category_bar.png")
        plt.savefig(bar_path, dpi=150)
        plt.close()
        generated_charts["category_bar"] = bar_path

    return generated_charts

def generate_html_report(report_data: Dict[str, Any], apk_name: str, output_path: str):
    """
    Generates a premium, clean, responsive HTML report.
    """
    risk_score = report_data.get("overall_risk_score", 0.0)
    risk_rating = report_data.get("overall_risk", "INFO")
    
    # Determine color for risk score
    color_map = {
        "CRITICAL": "#990000",
        "HIGH": "#CC0000",
        "MEDIUM": "#FF8800",
        "LOW": "#0099CC",
        "INFO": "#99CC00"
    }
    theme_color = color_map.get(risk_rating.upper(), "#999999")

    # Generate charts locally inside output directory
    reports_dir = os.path.dirname(output_path)
    generate_charts(report_data, reports_dir)

    findings_html = ""
    for idx, f in enumerate(report_data.get("findings", [])):
        sev = f.get("severity", "LOW").upper()
        sev_color = color_map.get(sev, "#999999")
        
        findings_html += f"""
        <div class="card finding-card">
            <div class="finding-header">
                <span class="finding-title">#{idx+1} {f.get('category')}</span>
                <span class="badge" style="background-color: {sev_color};">{sev} (Risk: {f.get('finding_risk_score')})</span>
            </div>
            <div class="finding-details">
                <p><strong>OWASP Mapping:</strong> {f.get('owasp', 'N/A')} | <strong>CWE:</strong> {f.get('cwe', 'N/A')} | <strong>Confidence:</strong> {f.get('confidence')}</p>
                <p><strong>Location:</strong> <code>{f.get('location')}</code></p>
                <p><strong>Description:</strong> {f.get('description')}</p>
                <div class="evidence-box">
                    <strong>Evidence:</strong>
                    <pre><code>{f.get('evidence')}</code></pre>
                </div>
                <p><strong>Recommendation:</strong> {f.get('recommendation')}</p>
                {f'<p><strong>Reference:</strong> <a href="{f.get("reference")}" target="_blank">{f.get("reference")}</a></p>' if f.get('reference') else ''}
            </div>
        </div>
        """

    recs_html = ""
    for r in report_data.get("recommendations", []):
        recs_html += f"""
        <tr>
            <td><strong>{r.get('category')}</strong></td>
            <td><span class="badge badge-owasp">OWASP {r.get('owasp', 'N/A')}</span></td>
            <td>{r.get('recommendation')}</td>
        </tr>
        """

    reasoning_html = "".join([f"<li>{r}</li>" for r in report_data.get("risk_reasoning", [])])

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {apk_name}</title>
    <style>
        :root {{
            --primary-color: #2c3e50;
            --secondary-color: #18bc9c;
            --dark-color: #0f172a;
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #334155;
            --border-color: #e2e8f0;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, var(--dark-color) 0%, var(--primary-color) 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            position: relative;
            overflow: hidden;
        }}
        header::after {{
            content: '';
            position: absolute;
            top: -50%;
            right: -20%;
            width: 300px;
            height: 600px;
            background: rgba(24, 188, 156, 0.1);
            transform: rotate(45deg);
            border-radius: 50%;
        }}
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        h1 {{
            font-size: 2.2rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        .apk-name {{
            font-family: monospace;
            background: rgba(255,255,255,0.15);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.95rem;
        }}
        .risk-badge-large {{
            display: inline-block;
            padding: 10px 24px;
            border-radius: 50px;
            font-weight: 800;
            font-size: 1.4rem;
            color: white;
            margin-top: 15px;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.2);
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
        }}
        .grid {{
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
        }}
        @media(max-width: 900px) {{
            .grid {{
                grid-template-columns: 1fr;
            }}
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.03);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
        }}
        .card-title {{
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 20px;
            border-bottom: 2px solid var(--bg-color);
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .metric-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 25px;
        }}
        @media(max-width: 600px) {{
            .metric-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}
        .metric-card {{
            background-color: var(--bg-color);
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 1.8rem;
            font-weight: 800;
            color: var(--primary-color);
        }}
        .metric-label {{
            font-size: 0.85rem;
            color: #64748b;
            font-weight: 600;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            color: white;
            font-size: 0.8rem;
            font-weight: 700;
        }}
        .badge-owasp {{
            background-color: var(--primary-color);
        }}
        .evidence-box {{
            background-color: #0f172a;
            color: #38bdf8;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            font-family: monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            border-left: 4px solid var(--secondary-color);
        }}
        pre {{
            white-space: pre-wrap;
        }}
        .finding-card {{
            border-left: 5px solid #64748b;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .finding-title {{
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--dark-color);
        }}
        .chart-container {{
            text-align: center;
            margin-bottom: 20px;
        }}
        .chart-img {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            text-align: left;
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: var(--bg-color);
            color: var(--primary-color);
            font-weight: 700;
        }}
        ul {{
            padding-left: 20px;
        }}
        li {{
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-content">
                <h1>Android Credential Leakage Detector V2</h1>
                <p>Security Assessment for APK: <span class="apk-name">{apk_name}</span></p>
                <div class="risk-badge-large" style="background-color: {theme_color};">
                    OVERALL RISK: {risk_rating} ({risk_score}/100)
                </div>
            </div>
        </header>

        <div class="grid">
            <div class="main-column">
                <!-- Executive Summary -->
                <div class="card">
                    <div class="card-title">Executive Summary</div>
                    <p style="font-size: 1.1rem; margin-bottom: 15px;">{report_data.get('executive_summary', '')}</p>
                    
                    <div class="metric-grid">
                        <div class="metric-card">
                            <div class="metric-value">{risk_score}</div>
                            <div class="metric-label">Risk Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{report_data.get('static_findings_count', 0)}</div>
                            <div class="metric-label">Static Findings</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{report_data.get('dynamic_logcat_findings_count', 0)}</div>
                            <div class="metric-label">Logcat Leaks</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">{report_data.get('dynamic_network_findings_count', 0)}</div>
                            <div class="metric-label">Network Leaks</div>
                        </div>
                    </div>
                </div>

                <!-- Detailed Findings -->
                <div class="card-section">
                    <h2 style="margin-bottom: 20px; color: var(--primary-color); font-weight:700;">Security Findings Breakdown</h2>
                    {findings_html if findings_html else '<div class="card">No vulnerabilities detected.</div>'}
                </div>
            </div>

            <div class="sidebar-column">
                <!-- Charts -->
                <div class="card">
                    <div class="card-title">Risk Distributions</div>
                    <div class="chart-container">
                        {f'<img class="chart-img" src="severity_pie.png" alt="Severity Distribution">' if os.path.exists(os.path.join(reports_dir, "severity_pie.png")) else ''}
                        {f'<img class="chart-img" src="category_bar.png" alt="Category Distribution">' if os.path.exists(os.path.join(reports_dir, "category_bar.png")) else ''}
                    </div>
                </div>

                <!-- Risk Calculation & Reasoning -->
                <div class="card">
                    <div class="card-title">Risk Assessment Logic</div>
                    <ul style="font-size: 0.95rem;">
                        {reasoning_html}
                    </ul>
                </div>
            </div>
        </div>

        <!-- Recommendations Table -->
        <div class="card" style="width: 100%;">
            <div class="card-title">Automated Action Plan / Recommendations</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 25%;">Vulnerability Class</th>
                        <th style="width: 15%;">OWASP Mapping</th>
                        <th style="width: 60%;">Actionable Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {recs_html if recs_html else '<tr><td colspan="3">No recommendations needed.</td></tr>'}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as out:
        out.write(html_content)

def generate_pdf_report(report_data: Dict[str, Any], apk_name: str, output_path: str):
    """
    Generates a premium PDF report using ReportLab.
    """
    # Force layout generation of charts first
    reports_dir = os.path.dirname(output_path)
    charts = generate_charts(report_data, reports_dir)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=30,
        textColor=colors.HexColor('#0f172a'),
        alignment=1, # Centered
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#64748b'),
        alignment=1,
        spaceAfter=40
    )

    heading1_style = ParagraphStyle(
        'Header1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=colors.HexColor('#2c3e50'),
        spaceBefore=15,
        spaceAfter=10,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceAfter=10
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=body_style,
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#0f172a'),
        backColor=colors.HexColor('#f1f5f9'),
        borderColor=colors.HexColor('#cbd5e1'),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=5,
        spaceAfter=5
    )

    story = []

    # ================= PAGE 1: COVER PAGE =================
    story.append(Spacer(1, 100))
    # Title
    story.append(Paragraph("Android Credential Leakage<br/>Detection System V2", title_style))
    story.append(Paragraph("Intelligent Android Security Analysis Report", subtitle_style))
    story.append(Spacer(1, 50))
    
    # Summary Info Box
    summary_data = [
        [Paragraph("<b>Target APK Path:</b>", body_style), Paragraph(apk_name, body_style)],
        [Paragraph("<b>Overall Risk Score:</b>", body_style), Paragraph(f"<b>{report_data.get('overall_risk_score', 0)}/100</b>", body_style)],
        [Paragraph("<b>Overall Risk Rating:</b>", body_style), Paragraph(f"<b>{report_data.get('overall_risk', 'INFO')}</b>", body_style)],
        [Paragraph("<b>Report Date:</b>", body_style), Paragraph(datetime.date.today().strftime('%B %d, %Y'), body_style)],
        [Paragraph("<b>Static Findings:</b>", body_style), Paragraph(str(report_data.get('static_findings_count', 0)), body_style)],
        [Paragraph("<b>Dynamic Leaks:</b>", body_style), Paragraph(str(report_data.get('dynamic_logcat_findings_count', 0) + report_data.get('dynamic_network_findings_count', 0)), body_style)]
    ]
    t_summary = Table(summary_data, colWidths=[150, 300])
    t_summary.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('PADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_summary)
    
    story.append(PageBreak())

    # ================= PAGE 2: EXECUTIVE SUMMARY =================
    story.append(Paragraph("Executive Summary", heading1_style))
    story.append(Paragraph(report_data.get("executive_summary", ""), body_style))
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("Risk Reasoning", heading1_style))
    for reason in report_data.get("risk_reasoning", []):
        story.append(Paragraph(f"• {reason}", body_style))
    story.append(Spacer(1, 20))

    # Add Charts
    chart_flowables = []
    if "severity_pie" in charts and os.path.exists(charts["severity_pie"]):
        chart_flowables.append(Image(charts["severity_pie"], width=230, height=190))
    if "category_bar" in charts and os.path.exists(charts["category_bar"]):
        chart_flowables.append(Image(charts["category_bar"], width=270, height=190))
        
    if chart_flowables:
        t_charts = Table([chart_flowables], colWidths=[250, 280])
        t_charts.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t_charts)

    story.append(PageBreak())

    # ================= PAGE 3: DETAILED FINDINGS =================
    story.append(Paragraph("Detailed Findings Breakdown", heading1_style))
    
    findings = report_data.get("findings", [])
    if not findings:
        story.append(Paragraph("No vulnerability findings detected during analysis.", body_style))
    else:
        for idx, f in enumerate(findings):
            finding_detail = []
            finding_detail.append(Paragraph(f"<b>Finding #{idx+1}: {f.get('category')}</b>", ParagraphStyle('fhead', parent=heading1_style, fontSize=12, leading=14, spaceBefore=0)))
            
            meta_table_data = [
                [
                    Paragraph(f"<b>Severity:</b> {f.get('severity')}", body_style),
                    Paragraph(f"<b>OWASP:</b> {f.get('owasp', 'N/A')}", body_style),
                    Paragraph(f"<b>Risk Score:</b> {f.get('finding_risk_score')}", body_style)
                ],
                [
                    Paragraph(f"<b>CWE:</b> {f.get('cwe', 'N/A')}", body_style),
                    Paragraph(f"<b>Confidence:</b> {f.get('confidence')}", body_style),
                    Paragraph(f"<b>Type:</b> {'Dynamic' if f.get('is_dynamic') else 'Static'}", body_style)
                ]
            ]
            t_meta = Table(meta_table_data, colWidths=[160, 160, 160])
            t_meta.setStyle(TableStyle([
                ('LINEBELOW', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            finding_detail.append(t_meta)
            finding_detail.append(Spacer(1, 6))

            finding_detail.append(Paragraph(f"<b>Location:</b> <code>{f.get('location')}</code>", body_style))
            finding_detail.append(Paragraph(f"<b>Description:</b> {f.get('description')}", body_style))
            
            # Evidence codeblock
            finding_detail.append(Paragraph("<b>Evidence:</b>", body_style))
            finding_detail.append(Paragraph(f.get('evidence', '').replace('\n', '<br/>'), code_style))
            
            finding_detail.append(Paragraph(f"<b>Recommendation:</b> {f.get('recommendation')}", body_style))
            if f.get('reference'):
                finding_detail.append(Paragraph(f"<b>Reference:</b> <font color='blue'>{f.get('reference')}</font>", body_style))
            
            finding_detail.append(Spacer(1, 15))
            
            # Use KeepTogether to keep each finding on the same page where possible
            story.append(KeepTogether(finding_detail))

    story.append(PageBreak())

    # ================= PAGE 4: RECOMMENDATIONS ACTION PLAN =================
    story.append(Paragraph("Vulnerability Remediation & Recommendations", heading1_style))
    
    recs = report_data.get("recommendations", [])
    if not recs:
        story.append(Paragraph("No remediation actions are required.", body_style))
    else:
        table_rows = [["Security Category", "OWASP Mapping", "Recommended Remediation Action"]]
        for r in recs:
            table_rows.append([
                Paragraph(f"<b>{r.get('category')}</b>", body_style),
                Paragraph(f"OWASP {r.get('owasp')}", body_style),
                Paragraph(r.get('recommendation'), body_style)
            ])
            
        t_recs = Table(table_rows, colWidths=[130, 90, 310])
        t_recs.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#94a3b8')),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(t_recs)

    doc.build(story)
