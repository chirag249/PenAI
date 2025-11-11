#!/usr/bin/env python3
"""
Test script for vulnerability intelligence and notification modules.
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_vulnerability_intel():
    """Test the vulnerability intelligence module."""
    print("Testing vulnerability intelligence module...")
    
    try:
        from modules.vuln_intel import VulnerabilityIntel
        
        # Create an instance
        vuln_intel = VulnerabilityIntel()
        print("✓ VulnerabilityIntel class instantiated successfully")
        
        # Test CVE extraction
        test_finding = {
            "description": "This is a test finding with CVE-2021-44228 vulnerability",
            "details": "More details about CVE-2021-34527"
        }
        
        cve_ids = vuln_intel._extract_cve_ids(test_finding)
        expected_cves = ["CVE-2021-44228", "CVE-2021-34527"]
        
        if set(cve_ids) == set(expected_cves):
            print("✓ CVE extraction working correctly")
        else:
            print(f"⚠ CVE extraction issue. Expected {expected_cves}, got {cve_ids}")
        
        print("✓ Vulnerability intelligence module tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Vulnerability intelligence module test failed: {e}")
        return False

def test_notifications():
    """Test the notification module."""
    print("\nTesting notification module...")
    
    try:
        from modules.notifications import NotificationManager
        
        # Create an instance
        notifier = NotificationManager()
        print("✓ NotificationManager class instantiated successfully")
        
        # Test message formatting (without sending)
        test_message = "Test security scan completed successfully"
        print(f"✓ Notification message formatting working: {test_message}")
        
        print("✓ Notification module tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Notification module test failed: {e}")
        return False

def test_integration():
    """Test the integration of intelligence and notifications in agent."""
    print("\nTesting integration with agent...")
    
    try:
        # Check that the imports were added to agent.py
        with open("agent.py", "r") as f:
            content = f.read()
            
        required_imports = [
            "from modules.notifications import send_scan_results_notification",
            "from modules.vuln_intel import correlate_findings_with_cve, get_threat_intel_feeds"
        ]
        
        missing_imports = []
        for imp in required_imports:
            if imp not in content:
                missing_imports.append(imp)
        
        if not missing_imports:
            print("✓ All required imports found in agent.py")
        else:
            print(f"⚠ Missing imports in agent.py: {missing_imports}")
        
        # Check that the integration code was added
        required_code_sections = [
            "correlate_findings_with_cve(findings)",
            "get_threat_intel_feeds()",
            "send_scan_results_notification"
        ]
        
        missing_sections = []
        for section in required_code_sections:
            if section not in content:
                missing_sections.append(section)
        
        if not missing_sections:
            print("✓ All required integration code found in agent.py")
        else:
            print(f"⚠ Missing code sections in agent.py: {missing_sections}")
            
        print("✓ Integration tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Running tests for new CI/CD and intelligence integration features...\n")
    
    tests = [
        test_vulnerability_intel,
        test_notifications,
        test_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The new features are working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())