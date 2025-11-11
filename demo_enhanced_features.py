#!/usr/bin/env python3
"""
Demo script showcasing the new CI/CD and intelligence integration features.
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def demo_vulnerability_intel():
    """Demonstrate vulnerability intelligence features."""
    print("🔍 Demonstrating Vulnerability Intelligence Features")
    print("=" * 50)
    
    from modules.vuln_intel import VulnerabilityIntel
    
    # Create an instance
    vuln_intel = VulnerabilityIntel()
    
    # Show CVE extraction capability
    sample_findings = [
        {
            "type": "xss",
            "description": "Cross-site scripting vulnerability found, related to CVE-2022-1234",
            "severity": 3,
            "target": "https://example.com/search"
        },
        {
            "type": "sqli",
            "description": "SQL injection vulnerability detected, similar to CVE-2021-5678",
            "severity": 4,
            "target": "https://example.com/login"
        }
    ]
    
    print("Sample findings with CVE references:")
    for i, finding in enumerate(sample_findings, 1):
        print(f"  {i}. {finding['description']}")
    
    print("\nExtracting CVE IDs from findings...")
    for i, finding in enumerate(sample_findings, 1):
        cve_ids = vuln_intel._extract_cve_ids(finding)
        print(f"  Finding {i}: {cve_ids}")
    
    # Show threat intelligence capability
    print("\nRetrieving threat intelligence feeds...")
    threat_intel = vuln_intel.get_threat_intel_feeds()
    print(f"  Retrieved {len(threat_intel.get('feeds', {}))} threat intelligence feeds")
    
    print("\n✅ Vulnerability Intelligence demonstration completed\n")

def demo_notifications():
    """Demonstrate notification features."""
    print("🔔 Demonstrating Notification Features")
    print("=" * 40)
    
    from modules.notifications import NotificationManager
    
    # Create an instance
    notifier = NotificationManager()
    
    # Show notification message formatting
    test_message = "Security scan completed successfully for https://example.com"
    print(f"Sample notification message: {test_message}")
    
    # Show notification structure
    print("\nNotification systems supported:")
    print("  • Slack")
    print("  • Microsoft Teams")
    
    if notifier.slack_webhook_url:
        print("  ✓ Slack webhook configured")
    else:
        print("  ⚠ Slack webhook not configured (set SLACK_WEBHOOK_URL)")
        
    if notifier.teams_webhook_url:
        print("  ✓ Teams webhook configured")
    else:
        print("  ⚠ Teams webhook not configured (set TEAMS_WEBHOOK_URL)")
    
    print("\n✅ Notification demonstration completed\n")

def demo_ci_cd_integration():
    """Demonstrate CI/CD integration features."""
    print("🚀 Demonstrating CI/CD Integration Features")
    print("=" * 45)
    
    # Show available CI/CD configuration files
    ci_cd_files = [
        ".github/workflows/security-scan.yml",
        ".gitlab-ci.yml"
    ]
    
    print("CI/CD integration files available:")
    for file in ci_cd_files:
        if Path(file).exists():
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} (missing)")
    
    print("\nGitHub Actions features:")
    print("  • Multi-Python version testing")
    print("  • Basic and enhanced security scans")
    print("  • Artifact archiving")
    print("  • Slack and Teams notifications")
    
    print("\nGitLab CI/CD features:")
    print("  • Multi-stage pipeline")
    print("  • Enhanced scanning capabilities")
    print("  • Comprehensive notifications")
    print("  • Artifact management")
    
    print("\n✅ CI/CD Integration demonstration completed\n")

def main():
    """Run all demonstrations."""
    print("PenAI Enhanced Features Demo")
    print("=" * 30)
    print("This demo showcases the new professional-level CI/CD integration")
    print("and external intelligence capabilities added to the framework.\n")
    
    demo_vulnerability_intel()
    demo_notifications()
    demo_ci_cd_integration()
    
    print("🎉 Demo completed!")
    print("\nTo use these features in practice:")
    print("1. Set up your CI/CD pipeline by configuring the webhook URLs")
    print("2. Add your NVD API key for vulnerability intelligence")
    print("3. Run your security scans as usual - the enhancements work automatically!")

if __name__ == "__main__":
    main()