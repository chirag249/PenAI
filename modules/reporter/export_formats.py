#!/usr/bin/env python3
"""
Export Formats Module for PenAI
Supports exporting reports in PDF, HTML, and JSON formats.
"""

import json
import os
from typing import List, Dict, Any
import datetime

# Check if export libraries are available
WEASYPRINT_AVAILABLE = False
HTML = None
CSS = None
try:
    from weasyprint import HTML as WeasyHTML, CSS
    WEASYPRINT_AVAILABLE = True
    HTML = WeasyHTML
except ImportError:
    pass

def generate_html_report(report_data: Dict[str, Any], outdir: str) -> str:
    """Generate an HTML report."""
    try:
        # Create HTML content
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>PenAI Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header {{ background-color: #3498db; color: white; padding: 20px; border-radius: 5px; }}
        .summary-box {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .finding {{ border: 1px solid #bdc3c7; margin: 15px 0; padding: 15px; border-radius: 5px; }}
        .severity-5 {{ border-left: 5px solid #e74c3c; }}
        .severity-4 {{ border-left: 5px solid #e67e22; }}
        .severity-3 {{ border-left: 5px solid #f1c40f; }}
        .severity-2 {{ border-left: 5px solid #3498db; }}
        .severity-1 {{ border-left: 5px solid #95a5a6; }}
        .chart-container {{ text-align: center; margin: 30px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PenAI Security Assessment Report</h1>
        <p>Generated on: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="summary-box">
        <h2>Executive Summary</h2>
        """

        # Add executive summary if available
        exec_summary = report_data.get("executive_summary", {})
        if exec_summary:
            html_content += f"""
        <p><strong>Risk Level:</strong> {exec_summary.get('risk_level', 'N/A')}</p>
        <p><strong>Total Vulnerabilities:</strong> {exec_summary.get('total_vulnerabilities', 0)}</p>
        """
            
            business_impact = exec_summary.get('potential_business_impact', {})
            if business_impact:
                html_content += f"""
        <p><strong>Estimated Downtime:</strong> {business_impact.get('estimated_downtime_hours', 0)} hours</p>
        <p><strong>Potential Data Exposure:</strong> {business_impact.get('potential_data_exposure', 0)} items</p>
        """

        html_content += """
    </div>
    
    <h2>Detailed Findings</h2>
    """

        # Add findings
        findings = report_data.get("findings", [])
        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", 1)
            severity_class = f"severity-{severity}"
            html_content += f"""
    <div class="finding {severity_class}">
        <h3>{i}. {finding.get('type', 'Unknown Type')}</h3>
        <p><strong>Target:</strong> {finding.get('target', 'Unknown')}</p>
        <p><strong>Severity:</strong> {severity}/5</p>
        <p><strong>Description:</strong> {finding.get('description', 'No description provided')}</p>
        """
            
            evidence = finding.get('evidence')
            if evidence:
                html_content += f"<p><strong>Evidence:</strong> {evidence[:500]}{'...' if len(evidence) > 500 else ''}</p>"
            
            html_content += "</div>"

        # Add remediation guidance
        guidance = report_data.get("remediation_guidance", [])
        if guidance:
            html_content += "<h2>Remediation Guidance</h2>"
            for item in guidance:
                html_content += f"""
    <div class="finding">
        <h3>{item.get('vulnerability_type', 'Unknown')}</h3>
        <p><strong>Severity:</strong> {item.get('severity', 'N/A')}</p>
        <p><strong>Description:</strong> {item.get('description', 'No description')}</p>
        <p><strong>Remediation Steps:</strong></p>
        <ul>
        """
                for step in item.get('remediation_steps', []):
                    html_content += f"<li>{step}</li>"
                html_content += "</ul>"
                html_content += "</div>"

        html_content += """
</body>
</html>
        """

        # Write HTML file
        html_path = os.path.join(outdir, "reports", "security_report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return html_path
    except Exception as e:
        print(f"Warning: Failed to generate HTML report: {e}")
        return ""

def generate_pdf_report(report_data: Dict[str, Any], outdir: str) -> str:
    """Generate a PDF report using WeasyPrint."""
    if not WEASYPRINT_AVAILABLE:
        return ""
    
    try:
        # First generate HTML report
        html_path = generate_html_report(report_data, outdir)
        if not html_path:
            return ""
        
        # Convert to PDF
        pdf_path = os.path.join(outdir, "reports", "security_report.pdf")
        if HTML:
            HTML(html_path).write_pdf(pdf_path)
        
        return pdf_path
    except Exception as e:
        print(f"Warning: Failed to generate PDF report: {e}")
        return ""

def generate_json_report(report_data: Dict[str, Any], outdir: str) -> str:
    """Generate a JSON report."""
    try:
        json_path = os.path.join(outdir, "reports", "security_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        return json_path
    except Exception as e:
        print(f"Warning: Failed to generate JSON report: {e}")
        return ""

def export_all_formats(report_data: Dict[str, Any], outdir: str) -> Dict[str, str]:
    """Export report in all available formats."""
    results = {}
    
    # Generate JSON (always available)
    json_path = generate_json_report(report_data, outdir)
    if json_path:
        results["json"] = json_path
    
    # Generate HTML
    html_path = generate_html_report(report_data, outdir)
    if html_path:
        results["html"] = html_path
    
    # Generate PDF
    pdf_path = generate_pdf_report(report_data, outdir)
    if pdf_path:
        results["pdf"] = pdf_path
    
    return results

# Integration with enhanced reporter
def integrate_with_enhanced_reporter():
    """Integrate export formats with the enhanced reporter."""
    try:
        # Integration would go here if needed
        pass
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_enhanced_reporter()