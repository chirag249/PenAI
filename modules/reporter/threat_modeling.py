#!/usr/bin/env python3
"""
Threat Modeling Module for PenAI
Correlates discovered vulnerabilities with potential attack vectors.
"""

import json
from typing import List, Dict, Any
from collections import defaultdict

# Attack vector mappings
ATTACK_VECTORS = {
    "sqli": {
        "name": "SQL Injection",
        "description": "Attackers can inject malicious SQL queries to manipulate the database",
        "cvss_base_score": 9.8,
        "attack_chain": ["input_validation", "database_access", "data_exfiltration"],
        "mitigation": ["parameterized_queries", "input_validation", "least_privilege"],
        "related_vulns": ["sqli-error", "sqli-blind", "sqli-time"]
    },
    "xss": {
        "name": "Cross-Site Scripting",
        "description": "Attackers can inject malicious scripts into web pages viewed by other users",
        "cvss_base_score": 6.1,
        "attack_chain": ["user_input", "script_execution", "session_hijacking"],
        "mitigation": ["output_encoding", "content_security_policy", "input_validation"],
        "related_vulns": ["xss-reflected", "xss-stored", "xss-dom"]
    },
    "idor": {
        "name": "Insecure Direct Object References",
        "description": "Attackers can bypass authorization and access resources directly",
        "cvss_base_score": 7.5,
        "attack_chain": ["resource_access", "privilege_escalation", "data_access"],
        "mitigation": ["access_control", "indirect_references", "session_management"],
        "related_vulns": ["idor", "access-control"]
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "description": "Attackers can force the server to make requests to internal services",
        "cvss_base_score": 8.2,
        "attack_chain": ["user_input", "internal_network_access", "data_exfiltration"],
        "mitigation": ["whitelist_urls", "network_segmentation", "disable_internal_requests"],
        "related_vulns": ["ssrf", "ssrf-blind"]
    },
    "auth-bypass": {
        "name": "Authentication Bypass",
        "description": "Attackers can gain access to restricted functionality without authentication",
        "cvss_base_score": 9.0,
        "attack_chain": ["auth_mechanism", "privilege_escalation", "system_access"],
        "mitigation": ["strong_auth", "session_management", "multi_factor_auth"],
        "related_vulns": ["auth-bypass", "auth-weak", "session-fixation"]
    }
}

# CWE to attack vector mapping
CWE_MAPPING = {
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-22": "idor",
    "CWE-918": "ssrf",
    "CWE-287": "auth-bypass",
    "CWE-285": "auth-bypass",
    "CWE-639": "idor"
}

def map_vuln_to_attack_vector(vuln_type: str) -> Dict[str, Any]:
    """Map a vulnerability type to an attack vector."""
    # Direct mapping
    if vuln_type in ATTACK_VECTORS:
        return ATTACK_VECTORS[vuln_type]
    
    # Check related vulns
    for vector_key, vector_data in ATTACK_VECTORS.items():
        if vuln_type in vector_data.get("related_vulns", []):
            return vector_data
    
    # Check CWE mapping
    for cwe, vector_key in CWE_MAPPING.items():
        if cwe.lower() in vuln_type.lower():
            return ATTACK_VECTORS.get(vector_key, {})
    
    # No mapping found
    return {}

def correlate_findings_with_attack_vectors(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlate findings with potential attack vectors."""
    correlated_findings = []
    
    # Group findings by target for attack chain analysis
    findings_by_target = defaultdict(list)
    for finding in findings:
        target = finding.get("target", "unknown")
        findings_by_target[target].append(finding)
    
    for finding in findings:
        # Copy original finding
        correlated_finding = finding.copy()
        
        # Map to attack vector
        vuln_type = finding.get("type", "").lower()
        attack_vector = map_vuln_to_attack_vector(vuln_type)
        
        if attack_vector:
            correlated_finding["attack_vector"] = {
                "name": attack_vector.get("name", ""),
                "description": attack_vector.get("description", ""),
                "cvss_base_score": attack_vector.get("cvss_base_score", 0),
                "attack_chain": attack_vector.get("attack_chain", []),
                "mitigation": attack_vector.get("mitigation", []),
                "related_vulnerabilities": attack_vector.get("related_vulns", [])
            }
        
        # Analyze potential attack chains for this target
        target = finding.get("target", "unknown")
        target_findings = findings_by_target.get(target, [])
        
        # Find complementary vulnerabilities that could form an attack chain
        attack_chain_opportunities = []
        for other_finding in target_findings:
            if other_finding == finding:
                continue
                
            other_vuln_type = other_finding.get("type", "").lower()
            other_attack_vector = map_vuln_to_attack_vector(other_vuln_type)
            
            if attack_vector and other_attack_vector:
                # Check if attack chains can be linked
                current_chain = attack_vector.get("attack_chain", [])
                other_chain = other_attack_vector.get("attack_chain", [])
                
                # Find common elements in attack chains
                common_elements = set(current_chain) & set(other_chain)
                if common_elements:
                    attack_chain_opportunities.append({
                        "related_vulnerability": other_vuln_type,
                        "common_attack_chain_elements": list(common_elements),
                        "combined_risk": (finding.get("severity", 1) + other_finding.get("severity", 1)) / 2
                    })
        
        if attack_chain_opportunities:
            correlated_finding["attack_chain_opportunities"] = attack_chain_opportunities
        
        correlated_findings.append(correlated_finding)
    
    return correlated_findings

def generate_threat_model(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate a comprehensive threat model from findings."""
    # Correlate findings with attack vectors
    correlated_findings = correlate_findings_with_attack_vectors(findings)
    
    # Identify unique attack vectors
    attack_vectors = {}
    for finding in correlated_findings:
        attack_vector_info = finding.get("attack_vector")
        if attack_vector_info:
            vector_name = attack_vector_info.get("name")
            if vector_name and vector_name not in attack_vectors:
                attack_vectors[vector_name] = attack_vector_info
    
    # Group findings by attack vector
    findings_by_vector = defaultdict(list)
    for finding in correlated_findings:
        attack_vector_info = finding.get("attack_vector")
        if attack_vector_info:
            vector_name = attack_vector_info.get("name")
            if vector_name:
                findings_by_vector[vector_name].append(finding)
    
    # Calculate risk metrics for each attack vector
    vector_risk_metrics = {}
    for vector_name, vector_findings in findings_by_vector.items():
        severities = [f.get("severity", 1) for f in vector_findings]
        avg_severity = sum(severities) / len(severities) if severities else 0
        max_severity = max(severities) if severities else 0
        finding_count = len(vector_findings)
        
        vector_risk_metrics[vector_name] = {
            "average_severity": round(avg_severity, 2),
            "max_severity": max_severity,
            "finding_count": finding_count,
            "risk_score": round(avg_severity * (1 + finding_count / 10), 2)  # Weighted risk score
        }
    
    # Identify high-risk targets
    target_risk_scores = defaultdict(float)
    for finding in correlated_findings:
        target = finding.get("target", "unknown")
        severity = finding.get("severity", 1)
        # Adjust severity by asset criticality if available
        criticality = finding.get("asset_criticality", 1.0)
        risk_score = severity * criticality
        target_risk_scores[target] = max(target_risk_scores[target], risk_score)
    
    # Sort targets by risk score
    high_risk_targets = sorted(
        target_risk_scores.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]  # Top 10 high-risk targets
    
    threat_model = {
        "attack_vectors_identified": attack_vectors,
        "findings_by_attack_vector": dict(findings_by_vector),
        "vector_risk_metrics": vector_risk_metrics,
        "high_risk_targets": [
            {"target": target, "risk_score": round(score, 2)} 
            for target, score in high_risk_targets
        ],
        "total_correlated_findings": len(correlated_findings)
    }
    
    return threat_model

def enhance_report_with_threat_modeling(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enhance findings with threat modeling information."""
    return correlate_findings_with_attack_vectors(findings)

# Integration with enhanced reporter
def integrate_with_enhanced_reporter():
    """Integrate threat modeling with the enhanced reporter."""
    try:
        # We would modify the enhanced reporter to include threat modeling
        pass
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_enhanced_reporter()