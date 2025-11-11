#!/usr/bin/env python3
"""
Enhanced Reporter Module for PenAI
Provides executive summaries, compliance mapping, and advanced visualization capabilities.
"""

import json
import os
from typing import List, Dict, Any, Optional
from collections import defaultdict
import datetime

# Compliance standards mapping
COMPLIANCE_MAPPING = {
    "owasp_top_10_2021": {
        "a01_broken_access_control": ["sqli", "idor", "access-control"],
        "a02_cryptographic_failures": ["crypto", "tls", "ssl", "encryption"],
        "a03_injection": ["sqli", "xss", "command-injection", "ldap-injection"],
        "a04_insecure_design": ["business-logic", "design-flaw"],
        "a05_security_misconfiguration": ["config", "misconfig", "header"],
        "a06_vulnerable_and_outdated_components": ["outdated", "component", "library"],
        "a07_identification_and_authentication_failures": ["auth", "login", "session"],
        "a08_software_and_data_integrity_failures": ["integrity", "tamper", "signature"],
        "a09_security_logging_and_monitoring_failures": ["log", "monitor", "audit"],
        "a10_server_side_request_forgery": ["ssrf"]
    },
    "nist_800_53": {
        "sa_security_assessment": ["vulnerability", "scan"],
        "ra_risk_assessment": ["risk", "threat"],
        "sc_system_and_communications_protection": ["crypto", "tls", "encryption"],
        "ac_access_control": ["auth", "access-control", "privilege"],
        "au_audit_and_accountability": ["log", "audit"],
        "ia_identification_and_authentication": ["auth", "login", "session"]
    },
    "pci_dss": {
        "requirement_6_develop_and_maintain_secure_systems": ["outdated", "patch", "update"],
        "requirement_11_regularly_test_security_systems": ["scan", "test", "vulnerability"],
        "requirement_8_identify_and_authenticate_access": ["auth", "login", "password"]
    },
    "iso_27001": {
        "a_12_information_security_aspects_of_business_process": ["business-logic", "process"],
        "a_13_communications_security": ["crypto", "tls", "ssl"],
        "a_9_access_control": ["auth", "access-control", "privilege"]
    }
}

# Asset criticality scoring based on path
ASSET_CRITICALITY = {
    5.0: ["/admin", "/api", "/payment", "/checkout"],
    4.0: ["/login", "/user", "/account", "/profile"],
    3.0: ["/dashboard", "/settings", "/config"],
    2.0: ["/blog", "/news", "/forum"],
    1.0: []  # Default
}

def calculate_asset_criticality(target_url: str) -> float:
    """Calculate asset criticality score based on URL path."""
    target_lower = target_url.lower()
    for score, paths in ASSET_CRITICALITY.items():
        for path in paths:
            if path in target_lower:
                return score
    return 1.0  # Default score

class EnhancedReporter:
    """Enhanced reporting capabilities for PenAI."""
    
    @staticmethod
    def generate_executive_summary(findings: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an executive summary translating technical findings into business impact."""
        total_findings = len(findings)
        critical_findings = len([f for f in findings if f.get("severity", 0) >= 5])
        high_findings = len([f for f in findings if f.get("severity", 0) == 4])
        medium_findings = len([f for f in findings if f.get("severity", 0) == 3])
        
        # Calculate business impact
        potential_downtime = critical_findings * 8 + high_findings * 4 + medium_findings * 2  # hours
        potential_data_exposure = len([f for f in findings if "sqli" in f.get("type", "") or "xss" in f.get("type", "")])
        estimated_risk_level = "HIGH" if critical_findings > 0 else "MEDIUM" if high_findings > 0 else "LOW"
        
        return {
            "executive_summary": {
                "scan_date": datetime.datetime.utcnow().isoformat() + "Z",
                "total_vulnerabilities": total_findings,
                "risk_level": estimated_risk_level,
                "potential_business_impact": {
                    "estimated_downtime_hours": potential_downtime,
                    "potential_data_exposure": potential_data_exposure,
                    "compliance_risks": EnhancedReporter._map_to_compliance(findings)
                },
                "immediate_actions_required": critical_findings > 0,
                "overall_security_posture": EnhancedReporter._assess_security_posture(findings)
            }
        }
    
    @staticmethod
    def _assess_security_posture(findings: List[Dict[str, Any]]) -> str:
        """Assess overall security posture based on findings."""
        critical = len([f for f in findings if f.get("severity", 0) >= 5])
        high = len([f for f in findings if f.get("severity", 0) == 4])
        total = len(findings)
        
        if critical > 0:
            return "CRITICAL - Immediate attention required"
        elif high > 2 or (high > 0 and total > 10):
            return "POOR - Significant vulnerabilities present"
        elif total > 20:
            return "FAIR - Moderate number of vulnerabilities"
        elif total > 5:
            return "GOOD - Few vulnerabilities found"
        else:
            return "EXCELLENT - Minimal vulnerabilities detected"
    
    @staticmethod
    def _map_to_compliance(findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Map findings to compliance standards."""
        compliance_results = defaultdict(list)
        
        for finding in findings:
            vuln_type = finding.get("type", "").lower()
            for standard, controls in COMPLIANCE_MAPPING.items():
                for control, keywords in controls.items():
                    for keyword in keywords:
                        if keyword in vuln_type:
                            compliance_results[standard].append(control)
                            break
        
        # Remove duplicates
        for standard in compliance_results:
            compliance_results[standard] = list(set(compliance_results[standard]))
        
        return dict(compliance_results)
    
    @staticmethod
    def generate_remediation_guidance(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate detailed remediation guidance with secure coding examples."""
        guidance = []
        vuln_types = defaultdict(list)
        
        # Group findings by type
        for finding in findings:
            vuln_types[finding.get("type", "unknown")].append(finding)
        
        # Generate guidance for each vulnerability type
        for vuln_type, vuln_list in vuln_types.items():
            if not vuln_list:
                continue
                
            # Get the highest severity for this type
            max_severity = max([v.get("severity", 0) for v in vuln_list])
            
            guidance_item = {
                "vulnerability_type": vuln_type,
                "severity": max_severity,
                "affected_targets": list(set([v.get("target", "unknown") for v in vuln_list])),
                "description": EnhancedReporter._get_vuln_description(vuln_type),
                "remediation_steps": EnhancedReporter._get_remediation_steps(vuln_type),
                "secure_coding_example": EnhancedReporter._get_secure_coding_example(vuln_type),
                "configuration_fixes": EnhancedReporter._get_configuration_fixes(vuln_type)
            }
            guidance.append(guidance_item)
        
        return guidance
    
    @staticmethod
    def _get_vuln_description(vuln_type: str) -> str:
        """Get description for vulnerability type."""
        descriptions = {
            "sqli": "SQL Injection vulnerabilities allow attackers to execute malicious SQL queries, potentially accessing, modifying, or deleting sensitive data.",
            "xss-reflected": "Reflected Cross-Site Scripting (XSS) occurs when user input is immediately returned in search results, error messages, or any other response that includes some or all of the input.",
            "xss-stored": "Stored Cross-Site Scripting (XSS) occurs when user input is stored on the target server and then displayed to users without proper sanitization.",
            "idor": "Insecure Direct Object References occur when an application exposes a reference to an internal implementation object without proper access control.",
            "auth-bypass": "Authentication Bypass vulnerabilities allow attackers to gain access to restricted content without proper authentication.",
            "ssrf": "Server-Side Request Forgery (SSRF) occurs when an application fetches a remote resource without validating the user-supplied URL.",
            "crypto-failure": "Cryptographic Failures occur when applications do not properly protect sensitive data through encryption or use weak cryptographic algorithms."
        }
        return descriptions.get(vuln_type, f"Vulnerability type: {vuln_type}")
    
    @staticmethod
    def _get_remediation_steps(vuln_type: str) -> List[str]:
        """Get remediation steps for vulnerability type."""
        remediation = {
            "sqli": [
                "Use parameterized queries or prepared statements for all database interactions",
                "Implement input validation and sanitization for all user-supplied data",
                "Apply the principle of least privilege for database accounts",
                "Regularly update and patch database management systems",
                "Use ORM frameworks that automatically handle parameterization"
            ],
            "xss-reflected": [
                "Implement proper output encoding for all user-supplied data",
                "Use Content Security Policy (CSP) headers to restrict script execution",
                "Validate and sanitize all input before processing",
                "Implement proper session management and authentication",
                "Use modern web frameworks with built-in XSS protection"
            ],
            "idor": [
                "Implement proper access control checks for all object references",
                "Use indirect object references or per-user object mappings",
                "Validate that users have permission to access requested objects",
                "Implement server-side session management",
                "Use UUIDs instead of sequential IDs where possible"
            ]
        }
        return remediation.get(vuln_type, ["Implement proper input validation", "Apply security best practices", "Regularly update dependencies"])
    
    @staticmethod
    def _get_secure_coding_example(vuln_type: str) -> str:
        """Get secure coding example for vulnerability type."""
        examples = {
            "sqli": '''# Vulnerable code
query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

# Secure code using parameterized queries
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))''',
            "xss-reflected": '''# Vulnerable code
print("<h1>Search results for: " + user_input + "</h1>")

# Secure code using output encoding
import html
print("<h1>Search results for: " + html.escape(user_input) + "</h1>")'''
        }
        return examples.get(vuln_type, "# Refer to security best practices for secure coding examples")
    
    @staticmethod
    def _get_configuration_fixes(vuln_type: str) -> List[str]:
        """Get configuration fixes for vulnerability type."""
        fixes = {
            "crypto-failure": [
                "Enforce TLS 1.2 or higher for all connections",
                "Use strong cipher suites and disable weak ones",
                "Implement HTTP Strict Transport Security (HSTS)",
                "Use secure flags for cookies",
                "Regularly rotate encryption keys"
            ],
            "auth-bypass": [
                "Implement multi-factor authentication",
                "Enforce strong password policies",
                "Use secure session management with proper timeouts",
                "Implement account lockout mechanisms",
                "Regularly review access control policies"
            ]
        }
        return fixes.get(vuln_type, ["Refer to security best practices for configuration guidance"])
    
    @staticmethod
    def enhance_findings_with_risk_scoring(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance findings with adjusted risk scoring based on asset criticality."""
        enhanced_findings = []
        
        for finding in findings:
            enhanced_finding = finding.copy()
            
            # Get base severity
            base_severity = finding.get("severity", 1)
            
            # Calculate asset criticality
            target = finding.get("target", "")
            criticality_score = calculate_asset_criticality(target)
            
            # Adjust severity based on asset criticality (weighted approach)
            adjusted_severity = min(5, int(base_severity * (1 + (criticality_score - 1) * 0.2)))
            
            enhanced_finding["adjusted_severity"] = adjusted_severity
            enhanced_finding["asset_criticality"] = criticality_score
            enhanced_finding["risk_factors"] = {
                "base_severity": base_severity,
                "asset_criticality": criticality_score,
                "adjusted_severity": adjusted_severity
            }
            
            enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings

def generate_enhanced_report(findings: List[Dict[str, Any]], meta: Dict[str, Any], outdir: str) -> Dict[str, Any]:
    """Generate an enhanced report with all advanced features."""
    # Enhance findings with risk scoring
    enhanced_findings = EnhancedReporter.enhance_findings_with_risk_scoring(findings)
    
    # Generate executive summary
    executive_summary = EnhancedReporter.generate_executive_summary(enhanced_findings, meta)
    
    # Generate remediation guidance
    remediation_guidance = EnhancedReporter.generate_remediation_guidance(enhanced_findings)
    
    # Create enhanced report
    enhanced_report = {
        "report_metadata": {
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "report_version": "2.0",
            "source_run": meta
        },
        "executive_summary": executive_summary,
        "findings": enhanced_findings,
        "remediation_guidance": remediation_guidance,
        "compliance_mapping": EnhancedReporter._map_to_compliance(enhanced_findings)
    }
    
    # Write to file
    os.makedirs(os.path.join(outdir, "reports"), exist_ok=True)
    report_path = os.path.join(outdir, "reports", "enhanced_report.json")
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(enhanced_report, f, indent=2, ensure_ascii=False)
    
    return enhanced_report

# Integration with existing reporter
def integrate_with_reporter():
    """Integrate enhanced reporting with the existing Reporter class."""
    try:
        from modules.reporter import Reporter
        
        # Save original method
        original_write_reports = Reporter.write_reports
        
        @staticmethod
        def enhanced_write_reports(outdir, meta, findings):
            # Call original method
            original_write_reports(outdir, meta, findings)
            
            # Generate enhanced report
            try:
                generate_enhanced_report(findings, meta, outdir)
            except Exception as e:
                print(f"Warning: Failed to generate enhanced report: {e}")
        
        # Replace the method
        Reporter.write_reports = enhanced_write_reports
        
    except ImportError:
        pass

# Run integration when module is imported
# integrate_with_reporter()  # Disabled for now to avoid conflicts