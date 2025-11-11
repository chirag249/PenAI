#!/usr/bin/env python3
"""
Test script for enhanced reporting features in PenAI.
"""

import json
import os
from datetime import datetime

# Test data
test_findings = [
    {
        "type": "sqli",
        "target": "https://example.com/admin/login",
        "severity": 5,
        "confidence": "high",
        "evidence": "SQL error message visible in response",
        "description": "SQL Injection vulnerability in admin login form"
    },
    {
        "type": "xss-reflected",
        "target": "https://example.com/search?q=test",
        "severity": 4,
        "confidence": "medium",
        "evidence": "<script>alert('xss')</script> executed in search results",
        "description": "Reflected XSS in search functionality"
    },
    {
        "type": "idor",
        "target": "https://example.com/api/user/123",
        "severity": 4,
        "confidence": "high",
        "evidence": "Able to access user data without authorization",
        "description": "Insecure Direct Object Reference in user API"
    },
    {
        "type": "auth-bypass",
        "target": "https://example.com/admin/dashboard",
        "severity": 5,
        "confidence": "high",
        "evidence": "Admin dashboard accessible without authentication",
        "description": "Authentication Bypass in admin area"
    },
    {
        "type": "ssrf",
        "target": "https://example.com/api/fetch?url=http://internal",
        "severity": 4,
        "confidence": "medium",
        "evidence": "Internal service metadata accessible through API",
        "description": "Server-Side Request Forgery in fetch API"
    }
]

test_meta = {
    "primary_domain": "example.com",
    "targets": ["https://example.com"],
    "run_id": "test-enhanced-reporting",
    "start_time": datetime.utcnow().isoformat() + "Z",
    "scan_profile": "thorough"
}

def test_enhanced_reporting():
    """Test the enhanced reporting features."""
    print("Testing enhanced reporting features...")
    
    # Create test output directory
    outdir = "test_output"
    os.makedirs(outdir, exist_ok=True)
    
    try:
        # Import enhanced reporting module
        from modules.reporter.enhanced_reporter import generate_enhanced_report
        
        # Generate enhanced report
        print("Generating enhanced report...")
        enhanced_report = generate_enhanced_report(test_findings, test_meta, outdir)
        
        print(f"Enhanced report generated successfully!")
        print(f"Report saved to: {outdir}/reports/enhanced_report.json")
        
        # Test executive summary
        exec_summary = enhanced_report.get("executive_summary", {})
        print(f"Executive Summary Risk Level: {exec_summary.get('risk_level', 'N/A')}")
        print(f"Total Vulnerabilities: {exec_summary.get('total_vulnerabilities', 0)}")
        
        # Test remediation guidance
        guidance = enhanced_report.get("remediation_guidance", [])
        print(f"Remediation guidance items: {len(guidance)}")
        
        # Test compliance mapping
        compliance = enhanced_report.get("compliance_mapping", {})
        print(f"Compliance standards mapped: {list(compliance.keys())}")
        
        return True
        
    except Exception as e:
        print(f"Error testing enhanced reporting: {e}")
        return False

def test_visualization():
    """Test the visualization features."""
    print("\nTesting visualization features...")
    
    # Create test output directory
    outdir = "test_output"
    os.makedirs(outdir, exist_ok=True)
    
    try:
        # Import visualization module
        from modules.reporter.visualization import generate_visualization_report
        
        # Generate visualization report
        print("Generating visualization report...")
        viz_report = generate_visualization_report(test_findings, test_meta, outdir)
        
        print(f"Visualization report generated!")
        print(f"Visualization data: {viz_report}")
        
        return True
        
    except Exception as e:
        print(f"Visualization libraries may not be installed: {e}")
        print("Install matplotlib and seaborn for visualization features:")
        print("pip install -r requirements-visualization.txt")
        return False

def test_export_formats():
    """Test the export format features."""
    print("\nTesting export format features...")
    
    # Create test output directory
    outdir = "test_output"
    os.makedirs(outdir, exist_ok=True)
    
    try:
        # Import export formats module
        import modules.reporter.export_formats as export_formats
        
        # Create a simple report structure
        test_report = {
            "executive_summary": {
                "risk_level": "HIGH",
                "total_vulnerabilities": len(test_findings)
            },
            "findings": test_findings,
            "remediation_guidance": [
                {
                    "vulnerability_type": "sqli",
                    "severity": 5,
                    "description": "SQL Injection vulnerability",
                    "remediation_steps": [
                        "Use parameterized queries",
                        "Implement input validation"
                    ]
                }
            ]
        }
        
        # Export in all formats
        print("Exporting reports in multiple formats...")
        export_results = export_formats.export_all_formats(test_report, outdir)
        
        print(f"Reports exported in formats: {list(export_results.keys())}")
        for format_name, path in export_results.items():
            print(f"  {format_name.upper()}: {path}")
        
        return True
        
    except Exception as e:
        print(f"Error testing export formats: {e}")
        return False

if __name__ == "__main__":
    print("PenAI Enhanced Reporting Test Suite")
    print("=" * 40)
    
    # Test enhanced reporting
    success1 = test_enhanced_reporting()
    
    # Test visualization
    success2 = test_visualization()
    
    # Test export formats
    success3 = test_export_formats()
    
    print("\n" + "=" * 40)
    if success1 and success2 and success3:
        print("All tests completed successfully!")
    else:
        print("Some tests completed with warnings or errors.")
    
    print("Check the 'test_output' directory for generated reports.")