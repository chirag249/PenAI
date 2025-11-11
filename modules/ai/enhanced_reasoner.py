# modules/ai/enhanced_reasoner.py
"""
Enhanced AI Reasoner with chain-of-thought reasoning for complex vulnerability analysis.
"""

from __future__ import annotations
import json
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

def chain_of_thought_analysis(finding: Dict[str, Any], related_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Perform chain-of-thought reasoning on a finding considering related findings.
    
    Args:
        finding: The primary finding to analyze
        related_findings: List of related findings for context
        
    Returns:
        Enhanced analysis with reasoning steps
    """
    # Extract key information from the primary finding
    vuln_type = finding.get("type", "unknown")
    target = finding.get("target", "unknown")
    evidence = finding.get("evidence", "")
    severity = finding.get("severity", 1)
    confidence = finding.get("confidence", 0.5)
    source = finding.get("source", {})
    
    # Initialize reasoning structure
    reasoning = {
        "primary_finding": {
            "type": vuln_type,
            "target": target,
            "evidence": evidence[:200],  # Truncate for readability
            "severity": severity,
            "confidence": confidence,
            "source_tool": source.get("tool", "unknown")
        },
        "related_findings_count": len(related_findings),
        "reasoning_steps": [],
        "risk_factors": [],
        "business_impact": "unknown",
        "exploitation_likelihood": "unknown",
        "recommendations": [],
        "mitigation_complexity": "unknown",
        "false_positive_likelihood": 0.0
    }
    
    # Step 1: Identify vulnerability category
    category = _categorize_vulnerability(vuln_type)
    reasoning["reasoning_steps"].append(f"1. Identified vulnerability category: {category}")
    
    # Step 2: Analyze evidence strength
    evidence_strength = _analyze_evidence_strength(evidence, confidence)
    reasoning["reasoning_steps"].append(f"2. Evidence strength assessed as: {evidence_strength}")
    
    # Step 3: Consider related findings
    if related_findings:
        correlation_analysis = _analyze_related_findings(related_findings)
        reasoning["reasoning_steps"].append(f"3. Related findings analysis: {correlation_analysis['summary']}")
        reasoning["risk_factors"].extend(correlation_analysis["risk_factors"])
    
    # Step 4: Assess business impact
    business_impact = _assess_business_impact(target, category)
    reasoning["business_impact"] = business_impact
    reasoning["reasoning_steps"].append(f"4. Business impact assessed as: {business_impact}")
    
    # Step 5: Evaluate exploitation likelihood
    exploitation_likelihood = _evaluate_exploitation_likelihood(category, evidence_strength, confidence)
    reasoning["exploitation_likelihood"] = exploitation_likelihood
    reasoning["reasoning_steps"].append(f"5. Exploitation likelihood: {exploitation_likelihood}")
    
    # Step 6: Assess mitigation complexity
    mitigation_complexity = _assess_mitigation_complexity(category)
    reasoning["mitigation_complexity"] = mitigation_complexity
    reasoning["reasoning_steps"].append(f"6. Mitigation complexity: {mitigation_complexity}")
    
    # Step 7: Evaluate false positive likelihood
    false_positive_likelihood = _evaluate_false_positive_likelihood(vuln_type, evidence, source)
    reasoning["false_positive_likelihood"] = false_positive_likelihood
    reasoning["reasoning_steps"].append(f"7. False positive likelihood: {false_positive_likelihood:.2f}")
    
    # Step 8: Generate recommendations
    recommendations = _generate_recommendations(category, business_impact)
    reasoning["recommendations"] = recommendations
    reasoning["reasoning_steps"].append(f"8. Generated {len(recommendations)} recommendations")
    
    return reasoning

def _categorize_vulnerability(vuln_type: str) -> str:
    """Categorize vulnerability type for better analysis."""
    vuln_type = vuln_type.lower()
    
    if any(keyword in vuln_type for keyword in ["xss", "cross-site"]):
        return "Cross-Site Scripting (XSS)"
    elif any(keyword in vuln_type for keyword in ["sql", "inject"]):
        return "SQL Injection"
    elif any(keyword in vuln_type for keyword in ["rce", "command", "exec"]):
        return "Remote Code Execution"
    elif any(keyword in vuln_type for keyword in ["lfi", "rfi", "traversal", "path"]):
        return "File Inclusion/Traversal"
    elif any(keyword in vuln_type for keyword in ["csrf", "cross-site request"]):
        return "Cross-Site Request Forgery"
    elif any(keyword in vuln_type for keyword in ["auth", "login", "session"]):
        return "Authentication Issues"
    elif any(keyword in vuln_type for keyword in ["info", "disclosure", "exposure"]):
        return "Information Disclosure"
    elif any(keyword in vuln_type for keyword in ["xxe", "xml"]):
        return "XML External Entity"
    else:
        return "Other Vulnerability"

def _analyze_evidence_strength(evidence: str, confidence: float) -> str:
    """Analyze the strength of evidence provided."""
    evidence_length = len(evidence)
    
    if evidence_length > 200 and confidence >= 0.8:
        return "Strong"
    elif evidence_length > 100 and confidence >= 0.6:
        return "Moderate"
    elif evidence_length > 50 and confidence >= 0.4:
        return "Weak"
    else:
        return "Insufficient"

def _analyze_related_findings(related_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze related findings for correlation and risk factors."""
    if not related_findings:
        return {"summary": "No related findings", "risk_factors": []}
    
    # Group by vulnerability type
    vuln_types = defaultdict(int)
    total_severity = 0
    total_confidence = 0.0
    
    for finding in related_findings:
        vuln_type = finding.get("type", "unknown")
        vuln_types[vuln_type] += 1
        total_severity += finding.get("severity", 1)
        total_confidence += finding.get("confidence", 0.5)
    
    avg_severity = total_severity / len(related_findings)
    avg_confidence = total_confidence / len(related_findings)
    
    # Identify risk factors
    risk_factors = []
    if len(related_findings) > 3:
        risk_factors.append("Multiple related findings indicate systemic issues")
    
    if avg_severity > 3:
        risk_factors.append("High average severity of related findings")
        
    if avg_confidence > 0.7:
        risk_factors.append("High confidence in related findings")
    
    # Find most common vulnerability types
    if vuln_types:
        most_common = max(vuln_types.items(), key=lambda x: x[1])
        if most_common[1] > 1:
            risk_factors.append(f"Multiple instances of {most_common[0]}")
    
    return {
        "summary": f"Found {len(related_findings)} related findings with average severity {avg_severity:.1f}",
        "risk_factors": risk_factors
    }

def _assess_business_impact(target: str, category: str) -> str:
    """Assess business impact based on target and vulnerability category."""
    target = target.lower()
    
    # High impact targets
    high_impact_paths = ["/admin", "/api", "/payment", "/login", "/user", "/account"]
    if any(path in target for path in high_impact_paths):
        return "High"
    
    # Medium impact targets
    medium_impact_paths = ["/dashboard", "/profile", "/settings", "/cart"]
    if any(path in target for path in medium_impact_paths):
        return "Medium"
    
    # Low impact by default
    return "Low"

def _evaluate_exploitation_likelihood(category: str, evidence_strength: str, confidence: float) -> str:
    """Evaluate how likely the vulnerability is to be exploited."""
    # High risk categories
    high_risk_categories = [
        "Remote Code Execution",
        "SQL Injection",
        "Authentication Issues"
    ]
    
    if category in high_risk_categories and evidence_strength in ["Strong", "Moderate"] and confidence > 0.7:
        return "High"
    elif evidence_strength == "Strong" and confidence > 0.8:
        return "High"
    elif evidence_strength in ["Strong", "Moderate"] and confidence > 0.6:
        return "Medium"
    elif evidence_strength == "Weak" or confidence < 0.5:
        return "Low"
    else:
        return "Medium"

def _generate_recommendations(category: str, business_impact: str) -> List[str]:
    """Generate recommendations based on vulnerability category and business impact."""
    recommendations = []
    
    # Generic recommendations
    recommendations.append("Validate and sanitize all user inputs")
    recommendations.append("Implement proper error handling to avoid information disclosure")
    recommendations.append("Regularly update and patch all software components")
    
    # Category-specific recommendations
    if category == "Cross-Site Scripting (XSS)":
        recommendations.append("Implement Content Security Policy (CSP)")
        recommendations.append("Use proper output encoding for all user-generated content")
        recommendations.append("Consider implementing XSS protection headers")
    
    elif category == "SQL Injection":
        recommendations.append("Use parameterized queries or prepared statements")
        recommendations.append("Implement proper input validation for all database queries")
        recommendations.append("Consider using an ORM to prevent direct query construction")
    
    elif category == "Remote Code Execution":
        recommendations.append("Implement strict input validation and sanitization")
        recommendations.append("Use secure coding practices to prevent code injection")
        recommendations.append("Apply principle of least privilege to execution environments")
    
    elif category == "Authentication Issues":
        recommendations.append("Implement multi-factor authentication")
        recommendations.append("Use secure session management")
        recommendations.append("Enforce strong password policies")
    
    # Impact-based recommendations
    if business_impact == "High":
        recommendations.append("Perform immediate security assessment")
        recommendations.append("Consider temporary mitigation measures")
        recommendations.append("Engage security team for in-depth analysis")
    elif business_impact == "Medium":
        recommendations.append("Schedule remediation within 30 days")
        recommendations.append("Monitor for exploitation attempts")
    
    return recommendations

def _assess_mitigation_complexity(category: str) -> str:
    """Assess the complexity of mitigating a vulnerability."""
    # High complexity categories
    high_complexity = [
        "Remote Code Execution",
        "Buffer Overflow",
        "XML External Entity"
    ]
    
    # Medium complexity categories
    medium_complexity = [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Cross-Site Request Forgery",
        "Insecure Direct Object Reference"
    ]
    
    if category in high_complexity:
        return "High"
    elif category in medium_complexity:
        return "Medium"
    else:
        return "Low"

def _evaluate_false_positive_likelihood(vuln_type: str, evidence: str, source: Dict[str, Any]) -> float:
    """Evaluate the likelihood that a finding is a false positive."""
    likelihood = 0.0
    
    # Tool-specific false positive rates
    tool = source.get("tool", "unknown").lower()
    high_fp_tools = ["nuclei", "nikto", "arachni"]
    medium_fp_tools = ["sqlmap", "xsstrike", "dalfox"]
    
    if tool in high_fp_tools:
        likelihood += 0.3
    elif tool in medium_fp_tools:
        likelihood += 0.1
    
    # Evidence quality
    if len(evidence) < 50:
        likelihood += 0.2
    elif len(evidence) < 100:
        likelihood += 0.1
    
    # Vulnerability type
    high_fp_types = ["info-disclosure", "other"]
    if vuln_type in high_fp_types:
        likelihood += 0.2
    
    return min(likelihood, 1.0)

def correlate_findings_with_reasoning(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Correlate findings with enhanced reasoning capabilities.
    
    Args:
        findings: List of findings from various tools
        
    Returns:
        List of correlated findings with enhanced reasoning
    """
    # Group findings by target
    target_findings = defaultdict(list)
    for finding in findings:
        target = finding.get("target", "unknown")
        target_findings[target].append(finding)
    
    # Correlate findings within each target
    correlated = []
    for target, target_finding_list in target_findings.items():
        # Group by vulnerability type
        vuln_groups = defaultdict(list)
        for finding in target_finding_list:
            vuln_type = finding.get("type", "unknown")
            # Normalize vulnerability types
            normalized_type = _normalize_vuln_type(vuln_type)
            vuln_groups[normalized_type].append(finding)
        
        # Also group by parameter for more detailed correlation
        param_groups = defaultdict(list)
        for finding in target_finding_list:
            # Extract parameter information if available
            parameter = finding.get("parameter", finding.get("evidence", "")).split("=")[0] if "=" in finding.get("parameter", finding.get("evidence", "")) else "unknown"
            param_groups[parameter].append(finding)
        
        # Group by tool for cross-tool correlation
        tool_groups = defaultdict(list)
        for finding in target_finding_list:
            tool = finding.get("source", {}).get("tool", "unknown")
            tool_groups[tool].append(finding)
        
        # Process each vulnerability group
        for vuln_type, group_findings in vuln_groups.items():
            if len(group_findings) > 1:
                # Multiple findings of same type - potential pattern
                # Use the first finding as primary and others as related
                primary_finding = group_findings[0]
                related_findings = group_findings[1:]
                
                # Apply chain-of-thought reasoning
                reasoning = chain_of_thought_analysis(primary_finding, related_findings)
                
                correlated_finding = primary_finding.copy()
                correlated_finding["enhanced_analysis"] = reasoning
                correlated_finding["correlation"] = {
                    "related_findings_count": len(related_findings),
                    "tools": list(set(f.get("source", {}).get("tool", "unknown") for f in group_findings)),
                    "confidence_boost": min(0.2 * (len(group_findings) - 1), 0.5),
                    "correlation_type": "vulnerability-type",
                    "correlation_strength": _calculate_correlation_strength(group_findings)
                }
                correlated.append(correlated_finding)
            else:
                # Single finding - add basic correlation metadata
                single_finding = group_findings[0].copy()
                single_finding["correlation"] = {
                    "related_findings_count": 0,
                    "confidence_boost": 0.0,
                    "correlation_type": "vulnerability-type",
                    "correlation_strength": 0.0
                }
                
                # Apply chain-of-thought reasoning even for single findings
                reasoning = chain_of_thought_analysis(single_finding, [])
                single_finding["enhanced_analysis"] = reasoning
                
                correlated.append(single_finding)
        
        # Process parameter groups for additional correlation
        for param, param_findings in param_groups.items():
            if len(param_findings) > 1:
                # Multiple findings on same parameter - potential attack surface
                primary_finding = param_findings[0]
                related_findings = param_findings[1:]
                
                # Check if this is already processed
                already_processed = any(f.get("target") == primary_finding.get("target") and 
                                      f.get("type") == primary_finding.get("type") for f in correlated)
                
                if not already_processed:
                    # Apply chain-of-thought reasoning
                    reasoning = chain_of_thought_analysis(primary_finding, related_findings)
                    
                    correlated_finding = primary_finding.copy()
                    correlated_finding["enhanced_analysis"] = reasoning
                    correlated_finding["correlation"] = {
                        "related_findings_count": len(related_findings),
                        "tools": list(set(f.get("source", {}).get("tool", "unknown") for f in param_findings)),
                        "confidence_boost": min(0.1 * (len(param_findings) - 1), 0.3),
                        "correlation_type": "parameter-attack-surface",
                        "correlation_strength": _calculate_correlation_strength(param_findings)
                    }
                    correlated.append(correlated_finding)
        
        # Process tool groups for cross-tool validation
        for tool, tool_findings in tool_groups.items():
            if len(tool_findings) > 1:
                # Multiple findings from same tool - check for consistency
                primary_finding = tool_findings[0]
                related_findings = tool_findings[1:]
                
                # Check if this is already processed
                already_processed = any(f.get("target") == primary_finding.get("target") and 
                                      f.get("type") == primary_finding.get("type") for f in correlated)
                
                if not already_processed:
                    # Apply chain-of-thought reasoning
                    reasoning = chain_of_thought_analysis(primary_finding, related_findings)
                    
                    correlated_finding = primary_finding.copy()
                    correlated_finding["enhanced_analysis"] = reasoning
                    correlated_finding["correlation"] = {
                        "related_findings_count": len(related_findings),
                        "tools": [tool],
                        "confidence_boost": min(0.05 * (len(tool_findings) - 1), 0.2),
                        "correlation_type": "tool-consistency",
                        "correlation_strength": _calculate_correlation_strength(tool_findings)
                    }
                    correlated.append(correlated_finding)
    
    return correlated

def _calculate_correlation_strength(findings: List[Dict[str, Any]]) -> float:
    """Calculate the strength of correlation between findings."""
    if len(findings) < 2:
        return 0.0
    
    # Calculate average similarity based on confidence and severity
    total_confidence = sum(f.get("confidence", 0.5) for f in findings)
    total_severity = sum(f.get("severity", 1) for f in findings)
    avg_confidence = total_confidence / len(findings)
    avg_severity = total_severity / len(findings)
    
    # Correlation strength based on consistency
    confidence_consistency = 1.0 - (max(f.get("confidence", 0.5) for f in findings) - min(f.get("confidence", 0.5) for f in findings))
    severity_consistency = 1.0 - (max(f.get("severity", 1) for f in findings) - min(f.get("severity", 1) for f in findings)) / 4.0
    
    # Weighted correlation strength
    strength = (avg_confidence * 0.4 + avg_severity * 0.2 + confidence_consistency * 0.2 + severity_consistency * 0.2)
    
    # Boost for multiple findings
    boost = min(0.1 * (len(findings) - 1), 0.5)
    
    return min(strength + boost, 1.0)

def _normalize_vuln_type(vuln_type: str) -> str:
    """Normalize vulnerability types for better correlation."""
    vuln_type = vuln_type.lower()
    
    # XSS normalization
    if "xss" in vuln_type or "cross-site" in vuln_type:
        return "xss"
    
    # SQLi normalization
    if "sql" in vuln_type or "inject" in vuln_type:
        return "sqli"
    
    # Directory traversal/Path traversal
    if "traversal" in vuln_type or "path" in vuln_type:
        return "path-traversal"
    
    # Command injection
    if "command" in vuln_type or "exec" in vuln_type or "rce" in vuln_type:
        return "rce"
    
    # Information disclosure
    if "disclosure" in vuln_type or "exposure" in vuln_type or "leak" in vuln_type:
        return "info-disclosure"
    
    return vuln_type

def enhanced_risk_scoring(findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Enhanced risk scoring with CVSS and business impact considerations.
    
    Args:
        findings: List of findings to score
        context: Additional context for risk assessment
        
    Returns:
        List of findings with enhanced risk scores
    """
    context = context or {}
    
    scored_findings = []
    for finding in findings:
        # Calculate base risk score
        base_score = _calculate_base_risk_score(finding)
        
        # Add CVSS-like scoring
        cvss_score = _calculate_cvss_score(finding)
        
        # Add business impact scoring
        business_impact_score = _calculate_business_impact_score(finding, context)
        
        # Add temporal factors (exploitation activity, remediation level)
        temporal_score = _calculate_temporal_score(finding)
        
        # Add environmental factors (asset value, existing controls)
        environmental_score = _calculate_environmental_score(finding, context)
        
        # Combine scores for final risk assessment
        # Weighted average with additional factors
        final_score = (base_score * 0.3 + cvss_score * 0.3 + business_impact_score * 0.2 + 
                      temporal_score * 0.1 + environmental_score * 0.1)
        
        # Add to finding
        enhanced_finding = finding.copy()
        enhanced_finding["enhanced_risk_score"] = {
            "final_score": min(final_score, 10.0),
            "base_score": base_score,
            "cvss_score": cvss_score,
            "business_impact_score": business_impact_score,
            "temporal_score": temporal_score,
            "environmental_score": environmental_score,
            "priority": _score_to_priority(final_score)
        }
        
        scored_findings.append(enhanced_finding)
    
    return scored_findings

def _calculate_temporal_score(finding: Dict[str, Any]) -> float:
    """Calculate temporal score based on exploitation activity and remediation level."""
    # Exploitation activity (0-2)
    exploitation_activity = 0.5  # Medium by default
    evidence = finding.get("evidence", "").lower()
    if "exploit" in evidence or "poc" in evidence or "proof" in evidence:
        exploitation_activity = 1.5  # High
    elif "scan" in evidence or "detect" in evidence:
        exploitation_activity = 0.5  # Low
    
    # Remediation level (0-2)
    remediation_level = 1.0  # Medium by default
    vuln_type = finding.get("type", "").lower()
    if "rce" in vuln_type or "sqli" in vuln_type:
        remediation_level = 1.8  # Difficult to remediate
    elif "info" in vuln_type:
        remediation_level = 0.5  # Easy to remediate
    
    # Temporal score (scale to 10)
    temporal_base = (exploitation_activity + remediation_level)
    return min(temporal_base * 2.5, 10.0)  # Scale to 10

def _calculate_environmental_score(finding: Dict[str, Any], context: Dict[str, Any]) -> float:
    """Calculate environmental score based on asset value and existing controls."""
    # Asset value from context (1-5)
    asset_value = 3  # Medium by default
    target = finding.get("target", "").lower()
    critical_assets = context.get("critical_assets", [])
    
    if any(asset in target for asset in critical_assets):
        asset_value = 5  # Critical
    elif any(path in target for path in ["/admin", "/api", "/payment"]):
        asset_value = 4  # High
    elif any(path in target for path in ["/user", "/profile", "/login"]):
        asset_value = 3  # Medium
    else:
        asset_value = 2  # Low
    
    # Existing controls (0-2)
    existing_controls = 1.0  # Medium by default
    # In a real implementation, this would come from context
    
    # Environmental score (scale to 10)
    environmental_base = (asset_value * 0.6 + existing_controls * 0.4)
    return min(environmental_base * 2.0, 10.0)  # Scale to 10

def _calculate_base_risk_score(finding: Dict[str, Any]) -> float:
    """Calculate base risk score from severity and confidence."""
    severity = finding.get("severity", 1)
    confidence = finding.get("confidence", 0.5)
    
    # Weighted score (scale to 10)
    return min((severity * 2.0 + confidence * 4.0), 10.0)

def _calculate_cvss_score(finding: Dict[str, Any]) -> float:
    """Calculate a CVSS-like score based on vulnerability characteristics."""
    vuln_type = finding.get("type", "").lower()
    target = finding.get("target", "").lower()
    
    # Attack vector scoring (0-3)
    attack_vector = 2  # Network by default
    if "local" in vuln_type or "internal" in target:
        attack_vector = 0.5  # Local
    elif "adjacent" in target:
        attack_vector = 1.5  # Adjacent network
    
    # Attack complexity (0-3)
    attack_complexity = 1  # Low by default
    if "rce" in vuln_type or "remote" in vuln_type:
        attack_complexity = 2  # High
    
    # Privileges required (0-3)
    privileges_required = 1  # Low by default
    if "/admin" in target or "admin" in vuln_type:
        privileges_required = 2  # High
    
    # User interaction (0-1)
    user_interaction = 0.5  # Required by default
    if "xss" in vuln_type or "csrf" in vuln_type:
        user_interaction = 1  # Required
    
    # Calculate score (scale to 10)
    cvss_base = (attack_vector + attack_complexity + privileges_required + user_interaction)
    return min(cvss_base * 2.0, 10.0)  # Scale to 10

def _calculate_business_impact_score(finding: Dict[str, Any], context: Dict[str, Any]) -> float:
    """Calculate business impact score."""
    target = finding.get("target", "").lower()
    
    # Critical assets from context
    critical_assets = context.get("critical_assets", [])
    
    # Check if target is critical
    if any(asset in target for asset in critical_assets):
        return 10.0
    
    # High impact paths
    high_impact = ["/payment", "/api", "/admin", "/login", "/user"]
    if any(path in target for path in high_impact):
        return 8.0
    
    # Medium impact paths
    medium_impact = ["/profile", "/settings", "/cart", "/dashboard"]
    if any(path in target for path in medium_impact):
        return 5.0
    
    # Low impact by default
    return 2.0

def _score_to_priority(score: float) -> str:
    """Convert score to priority level."""
    if score >= 8.0:
        return "critical"
    elif score >= 6.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score >= 2.0:
        return "low"
    else:
        return "info"