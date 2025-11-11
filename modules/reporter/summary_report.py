#!/usr/bin/env python3
"""
Summary Report Generator for PenAI.

This module generates easy-to-understand summarized reports from scan findings.
"""

from __future__ import annotations
import json
import os
from typing import List, Dict, Any, Optional
from collections import defaultdict

def generate_summary_report(findings: List[Dict[str, Any]], meta: Dict[str, Any], outdir: str) -> Dict[str, Any]:
    """
    Generate a summarized report from findings and metadata.
    
    Args:
        findings: List of vulnerability findings
        meta: Metadata from the scan
        outdir: Output directory
        
    Returns:
        Dictionary containing the summary report
    """
    # Categorize findings by severity
    severity_counts = defaultdict(int)
    vulnerability_types = defaultdict(int)
    high_risk_targets = set()
    
    # Process findings
    processed_findings = []
    for finding in findings:
        # Get severity (default to 1 if not present)
        severity = finding.get("severity", 1)
        severity_counts[severity] += 1
        
        # Get vulnerability type
        vuln_type = finding.get("type", "unknown")
        vulnerability_types[vuln_type] += 1
        
        # Track high-risk targets (severity 4 or 5)
        if severity >= 4:
            target = finding.get("target", "unknown")
            high_risk_targets.add(target)
        
        # Add to processed findings if it's a real vulnerability (not info)
        if severity > 1:
            processed_findings.append({
                "type": vuln_type,
                "target": finding.get("target", "unknown"),
                "severity": severity,
                "confidence": finding.get("confidence", "unknown"),
                "evidence": finding.get("evidence", "")[:200] + "..." if len(str(finding.get("evidence", ""))) > 200 else finding.get("evidence", ""),
                "ai_prediction": finding.get("ai", finding.get("meta", {}).get("ai_prediction", {}))
            })
    
    # Sort findings by severity (highest first)
    processed_findings.sort(key=lambda x: x["severity"], reverse=True)
    
    # Create summary report
    summary = {
        "scan_summary": {
            "total_findings": len(findings),
            "vulnerabilities_found": len([f for f in findings if f.get("severity", 1) > 1]),
            "severity_distribution": dict(severity_counts),
            "critical_findings": severity_counts[5],
            "high_severity": severity_counts[4],
            "medium_severity": severity_counts[3],
            "low_severity": severity_counts[2],
            "info_findings": severity_counts[1]
        },
        "vulnerability_breakdown": dict(vulnerability_types),
        "high_risk_targets": list(high_risk_targets),
        "top_vulnerabilities": processed_findings[:10],  # Top 10 most critical findings
        "meta": meta,
        "recommendations": generate_recommendations(processed_findings, meta)
    }
    
    # Write summary report to file
    summary_path = os.path.join(outdir, "reports", "summary_report.json")
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    # Also write a human-readable text version
    text_summary_path = os.path.join(outdir, "reports", "summary_report.txt")
    with open(text_summary_path, "w", encoding="utf-8") as f:
        f.write(format_human_readable_summary(summary))
    
    return summary

def generate_recommendations(findings: List[Dict[str, Any]], meta: Dict[str, Any]) -> List[str]:
    """
    Generate security recommendations based on findings.
    
    Args:
        findings: List of vulnerability findings
        meta: Metadata from the scan
        
    Returns:
        List of security recommendations
    """
    recommendations = []
    
    # Count vulnerabilities by type
    vuln_counts = defaultdict(int)
    for finding in findings:
        vuln_type = finding.get("type", "unknown")
        vuln_counts[vuln_type] += 1
    
    # Generate recommendations based on findings
    if vuln_counts.get("xss-reflected", 0) > 0 or vuln_counts.get("xss-stored", 0) > 0:
        recommendations.append("Implement proper input validation and output encoding to prevent XSS attacks")
    
    if vuln_counts.get("sqli-error", 0) > 0 or vuln_counts.get("sqli-blind", 0) > 0:
        recommendations.append("Use parameterized queries and input validation to prevent SQL injection")
    
    if any(f.get("severity", 0) >= 4 for f in findings):
        recommendations.append("Immediately address critical and high-severity vulnerabilities")
    
    if len(findings) > 50:
        recommendations.append("Consider implementing a Web Application Firewall (WAF) for additional protection")
    
    # General recommendations
    recommendations.extend([
        "Keep all software and dependencies up to date with the latest security patches",
        "Implement proper authentication and authorization mechanisms",
        "Regularly scan for vulnerabilities using automated tools",
        "Conduct periodic security assessments and penetration testing"
    ])
    
    return list(set(recommendations))  # Remove duplicates

def format_human_readable_summary(summary: Dict[str, Any]) -> str:
    """
    Format the summary into a human-readable text report.
    
    Args:
        summary: The summary dictionary
        
    Returns:
        Formatted text string
    """
    lines = []
    
    lines.append("=" * 60)
    lines.append("PENAI SECURITY SCAN SUMMARY REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    # Scan Summary
    scan_summary = summary.get("scan_summary", {})
    lines.append("SCAN SUMMARY")
    lines.append("-" * 20)
    lines.append(f"Total Findings: {scan_summary.get('total_findings', 0)}")
    lines.append(f"Vulnerabilities Found: {scan_summary.get('vulnerabilities_found', 0)}")
    lines.append(f"Critical (Severity 5): {scan_summary.get('critical_findings', 0)}")
    lines.append(f"High (Severity 4): {scan_summary.get('high_severity', 0)}")
    lines.append(f"Medium (Severity 3): {scan_summary.get('medium_severity', 0)}")
    lines.append(f"Low (Severity 2): {scan_summary.get('low_severity', 0)}")
    lines.append(f"Info (Severity 1): {scan_summary.get('info_findings', 0)}")
    lines.append("")
    
    # Vulnerability Breakdown
    vuln_breakdown = summary.get("vulnerability_breakdown", {})
    if vuln_breakdown:
        lines.append("VULNERABILITY BREAKDOWN")
        lines.append("-" * 25)
        for vuln_type, count in sorted(vuln_breakdown.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"{vuln_type}: {count}")
        lines.append("")
    
    # High-Risk Targets
    high_risk_targets = summary.get("high_risk_targets", [])
    if high_risk_targets:
        lines.append("HIGH-RISK TARGETS")
        lines.append("-" * 18)
        for target in high_risk_targets:
            lines.append(f"- {target}")
        lines.append("")
    
    # Top Vulnerabilities
    top_vulns = summary.get("top_vulnerabilities", [])
    if top_vulns:
        lines.append("TOP VULNERABILITIES")
        lines.append("-" * 19)
        for i, vuln in enumerate(top_vulns[:5], 1):  # Show top 5
            lines.append(f"{i}. {vuln['type'].upper()} on {vuln['target']}")
            lines.append(f"   Severity: {vuln['severity']} | Confidence: {vuln['confidence']}")
            if vuln['evidence']:
                lines.append(f"   Evidence: {vuln['evidence']}")
            lines.append("")
    
    # Recommendations
    recommendations = summary.get("recommendations", [])
    if recommendations:
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 15)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        lines.append("")
    
    lines.append("=" * 60)
    lines.append("END OF REPORT")
    lines.append("=" * 60)
    
    return "\n".join(lines)

def integrate_with_reporter():
    """
    Integrate the summary report generation with the existing Reporter class.
    """
    try:
        from modules import reporter as ReporterModule
        Reporter = getattr(ReporterModule, 'Reporter', None)
        
        # Only integrate if Reporter is available and has write_reports method
        if Reporter is not None and hasattr(Reporter, 'write_reports'):
            # Save original method
            original_write_reports = Reporter.write_reports
            
            @staticmethod
            def enhanced_write_reports(outdir, meta, findings):
                # Call original method
                original_write_reports(outdir, meta, findings)
                
                # Generate summary report
                try:
                    generate_summary_report(findings, meta, outdir)
                except Exception as e:
                    print(f"Warning: Failed to generate summary report: {e}")
            
            # Replace the method
            Reporter.write_reports = enhanced_write_reports
        
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_reporter()

# Import and integrate advanced analytics if available
try:
    import modules.reporter.advanced_analytics as advanced_analytics
    
    # Save original method
    original_generate_summary_report = generate_summary_report
    
    def enhanced_generate_summary_report(findings, meta, outdir):
        # Call original method
        summary = original_generate_summary_report(findings, meta, outdir)
        
        # Run advanced analytics
        try:
            if hasattr(advanced_analytics, 'run_comprehensive_analysis'):
                advanced_analytics.run_comprehensive_analysis(findings, meta, outdir)
        except Exception as e:
            print(f"Warning: Failed to run comprehensive analysis: {e}")
        
        return summary
    
    # Replace the function
    generate_summary_report = enhanced_generate_summary_report
    
except ImportError:
    pass