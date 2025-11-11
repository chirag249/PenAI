#!/usr/bin/env python3
"""
Root Cause Analysis Module for PenAI
Provides automated root cause analysis for recurring vulnerability patterns.
"""

import json
from typing import List, Dict, Any
from collections import defaultdict, Counter
import re

# Common vulnerability patterns and their root causes
ROOT_CAUSE_PATTERNS = {
    "input_validation": {
        "patterns": ["sqli", "xss", "command injection", "ldap injection"],
        "root_cause": "Insufficient input validation and sanitization",
        "remediation": "Implement comprehensive input validation, use parameterized queries, and sanitize all user inputs"
    },
    "authentication": {
        "patterns": ["auth-bypass", "weak-auth", "session", "login"],
        "root_cause": "Weak authentication and session management",
        "remediation": "Implement strong authentication mechanisms, secure session management, and multi-factor authentication"
    },
    "access_control": {
        "patterns": ["idor", "access-control", "privilege"],
        "root_cause": "Inadequate access control implementation",
        "remediation": "Implement proper role-based access control, server-side authorization checks, and principle of least privilege"
    },
    "crypto": {
        "patterns": ["crypto", "tls", "ssl", "encryption"],
        "root_cause": "Cryptographic failures",
        "remediation": "Use strong encryption algorithms, implement proper key management, and enforce TLS 1.2+"
    },
    "configuration": {
        "patterns": ["config", "misconfig", "header", "exposure"],
        "root_cause": "Security misconfigurations",
        "remediation": "Implement secure configuration management, regular configuration reviews, and automated security checks"
    },
    "dependencies": {
        "patterns": ["outdated", "component", "library"],
        "root_cause": "Vulnerable and outdated components",
        "remediation": "Implement dependency management processes, regular updates, and automated vulnerability scanning"
    }
}

def identify_vulnerability_clusters(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings into clusters based on vulnerability type patterns."""
    clusters = defaultdict(list)
    
    for finding in findings:
        vuln_type = finding.get("type", "").lower()
        
        # Group by major vulnerability category
        if "sqli" in vuln_type:
            clusters["sqli"].append(finding)
        elif "xss" in vuln_type:
            clusters["xss"].append(finding)
        elif "auth" in vuln_type or "login" in vuln_type or "session" in vuln_type:
            clusters["authentication"].append(finding)
        elif "idor" in vuln_type or "access" in vuln_type:
            clusters["access_control"].append(finding)
        elif "crypto" in vuln_type or "tls" in vuln_type or "ssl" in vuln_type:
            clusters["crypto"].append(finding)
        elif "config" in vuln_type or "header" in vuln_type:
            clusters["configuration"].append(finding)
        elif "outdated" in vuln_type or "component" in vuln_type or "library" in vuln_type:
            clusters["dependencies"].append(finding)
        else:
            # Try to match with other patterns
            matched = False
            for category, pattern_data in ROOT_CAUSE_PATTERNS.items():
                patterns = pattern_data["patterns"]
                for pattern in patterns:
                    if pattern in vuln_type:
                        clusters[category].append(finding)
                        matched = True
                        break
                if matched:
                    break
            
            # If no match, put in "other" category
            if not matched:
                clusters["other"].append(finding)
    
    return dict(clusters)

def analyze_developer_patterns(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze patterns that might indicate developer practices or weaknesses."""
    # Extract code snippets or evidence that might indicate coding patterns
    code_patterns = []
    for finding in findings:
        evidence = finding.get("evidence", "")
        if evidence:
            # Look for common coding patterns in evidence
            if "SELECT *" in evidence or "WHERE" in evidence.upper():
                code_patterns.append("raw_sql_queries")
            if "<script>" in evidence.lower() or "javascript:" in evidence.lower():
                code_patterns.append("inline_javascript")
            if "eval(" in evidence.lower():
                code_patterns.append("dangerous_eval")
    
    # Count patterns
    pattern_counts = Counter(code_patterns)
    
    return {
        "developer_patterns_identified": dict(pattern_counts),
        "total_patterns": sum(pattern_counts.values())
    }

def determine_root_causes(vuln_clusters: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """Determine root causes for each vulnerability cluster."""
    root_causes = []
    
    for cluster_name, findings in vuln_clusters.items():
        if not findings:
            continue
            
        # Get root cause information for this cluster
        root_cause_info = ROOT_CAUSE_PATTERNS.get(cluster_name, {
            "root_cause": f"Recurring {cluster_name} vulnerabilities",
            "remediation": "Implement security best practices for this vulnerability type"
        })
        
        # Calculate severity metrics
        severities = [f.get("severity", 1) for f in findings]
        avg_severity = sum(severities) / len(severities) if severities else 0
        max_severity = max(severities) if severities else 0
        
        # Get affected targets
        targets = list(set([f.get("target", "unknown") for f in findings]))
        
        root_cause = {
            "vulnerability_category": cluster_name,
            "finding_count": len(findings),
            "affected_targets": targets[:10],  # Top 10 targets
            "average_severity": round(avg_severity, 2),
            "max_severity": max_severity,
            "root_cause": root_cause_info["root_cause"],
            "remediation": root_cause_info["remediation"],
            "recommendations": generate_specific_recommendations(cluster_name, findings)
        }
        
        root_causes.append(root_cause)
    
    # Sort by finding count (most frequent issues first)
    root_causes.sort(key=lambda x: x["finding_count"], reverse=True)
    
    return root_causes

def generate_specific_recommendations(category: str, findings: List[Dict[str, Any]]) -> List[str]:
    """Generate specific recommendations based on the vulnerability category and findings."""
    recommendations = []
    
    if category == "sqli":
        recommendations.extend([
            "Use parameterized queries or prepared statements for all database interactions",
            "Implement input validation and sanitization for all user-supplied data",
            "Apply the principle of least privilege for database accounts",
            "Use ORM frameworks that automatically handle parameterization"
        ])
    elif category == "xss":
        recommendations.extend([
            "Implement proper output encoding for all user-supplied data",
            "Use Content Security Policy (CSP) headers to restrict script execution",
            "Validate and sanitize all input before processing",
            "Use modern web frameworks with built-in XSS protection"
        ])
    elif category == "authentication":
        recommendations.extend([
            "Implement multi-factor authentication",
            "Enforce strong password policies",
            "Use secure session management with proper timeouts",
            "Implement account lockout mechanisms"
        ])
    elif category == "access_control":
        recommendations.extend([
            "Implement proper access control checks for all object references",
            "Use indirect object references or per-user object mappings",
            "Validate that users have permission to access requested objects",
            "Implement server-side session management"
        ])
    elif category == "crypto":
        recommendations.extend([
            "Enforce TLS 1.2 or higher for all connections",
            "Use strong cipher suites and disable weak ones",
            "Implement HTTP Strict Transport Security (HSTS)",
            "Use secure flags for cookies"
        ])
    elif category == "configuration":
        recommendations.extend([
            "Implement secure configuration management processes",
            "Regularly review and audit security configurations",
            "Use automated tools to detect misconfigurations",
            "Implement security headers (X-Frame-Options, X-Content-Type-Options, etc.)"
        ])
    elif category == "dependencies":
        recommendations.extend([
            "Implement automated dependency scanning",
            "Regularly update and patch all components",
            "Use software composition analysis (SCA) tools",
            "Maintain an inventory of all third-party components"
        ])
    
    # Add general recommendations based on findings
    if len(findings) > 10:
        recommendations.append("Implement a comprehensive security training program for developers")
    
    high_severity_findings = [f for f in findings if f.get("severity", 1) >= 4]
    if high_severity_findings:
        recommendations.append("Prioritize fixing high-severity vulnerabilities immediately")
    
    return recommendations

def perform_root_cause_analysis(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Perform comprehensive root cause analysis on findings."""
    # Identify vulnerability clusters
    vuln_clusters = identify_vulnerability_clusters(findings)
    
    # Analyze developer patterns
    developer_patterns = analyze_developer_patterns(findings)
    
    # Determine root causes
    root_causes = determine_root_causes(vuln_clusters)
    
    # Create analysis report
    analysis_report = {
        "vulnerability_clusters": vuln_clusters,
        "developer_patterns": developer_patterns,
        "root_causes_identified": root_causes,
        "total_findings_analyzed": len(findings),
        "cluster_summary": {
            cluster: len(findings) 
            for cluster, findings in vuln_clusters.items()
        }
    }
    
    return analysis_report

def enhance_findings_with_root_cause(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enhance findings with root cause analysis information."""
    # Perform root cause analysis
    analysis_report = perform_root_cause_analysis(findings)
    root_causes = analysis_report.get("root_causes_identified", [])
    
    # Create a mapping of vulnerability types to root causes
    vuln_to_root_case = {}
    for root_cause in root_causes:
        category = root_cause["vulnerability_category"]
        # Map category to its root cause info
        vuln_to_root_case[category] = root_cause
    
    # Enhance each finding with relevant root cause information
    enhanced_findings = []
    for finding in findings:
        enhanced_finding = finding.copy()
        
        # Try to match finding to root cause
        vuln_type = finding.get("type", "").lower()
        root_cause_info = None
        
        for category, root_cause in vuln_to_root_case.items():
            if category in vuln_type:
                root_cause_info = root_cause
                break
        
        if root_cause_info:
            enhanced_finding["root_cause_analysis"] = {
                "category": root_cause_info["vulnerability_category"],
                "root_cause": root_cause_info["root_cause"],
                "remediation": root_cause_info["remediation"]
            }
        
        enhanced_findings.append(enhanced_finding)
    
    return enhanced_findings

# Integration with enhanced reporter
def integrate_with_enhanced_reporter():
    """Integrate root cause analysis with the enhanced reporter."""
    try:
        # We would modify the enhanced reporter to include root cause analysis
        pass
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_enhanced_reporter()