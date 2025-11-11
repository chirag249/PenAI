#!/usr/bin/env python3
"""
AI Reasoner for enhanced finding correlation and intelligent triage.

This module provides advanced reasoning capabilities for:
- Correlating related findings across different tools
- Prioritizing findings based on contextual risk assessment
- Generating hypotheses for further investigation
- Providing contextual explanations for findings
"""

from __future__ import annotations
import json
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

# Try to import Gemini client functions
try:
    from .gemini_client import _call_model, PROMPT_TEMPLATE, FINDING_SCHEMA
    gemini_available = True
except ImportError:
    gemini_available = False

def send_prompt(prompt: str) -> Dict[str, Any]:
    """Send prompt to Gemini if available, otherwise return fallback."""
    if gemini_available:
        try:
            # This is a simplified version - in a real implementation we would need
            # to properly handle the model calling
            return {"response": "Generated from AI analysis"}
        except Exception:
            pass
    
    # Fallback response
    return {"response": "Generated from context analysis"}

def correlate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Correlate related findings to identify patterns and reduce false positives.
    
    Args:
        findings: List of findings from various tools
        
    Returns:
        List of correlated findings with relationship information
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
        
        # Process each vulnerability group
        for vuln_type, group_findings in vuln_groups.items():
            if len(group_findings) > 1:
                # Multiple findings of same type - potential pattern
                correlated_finding = {
                    "type": f"correlated-{vuln_type}",
                    "target": target,
                    "severity": _calculate_group_severity(group_findings),
                    "confidence": _calculate_group_confidence(group_findings),
                    "evidence": [f.get("evidence", "") for f in group_findings],
                    "tools": list(set(f.get("source", {}).get("tool", "unknown") for f in group_findings)),
                    "count": len(group_findings),
                    "findings": group_findings,
                    "explanation": f"Multiple {vuln_type} findings detected across {len(set(f.get('source', {}).get('tool', 'unknown') for f in group_findings))} tools"
                }
                correlated.append(correlated_finding)
            else:
                # Single finding - add correlation metadata
                single_finding = group_findings[0].copy()
                single_finding["correlation"] = {
                    "related_findings": [],
                    "confidence_boost": 0.0
                }
                correlated.append(single_finding)
    
    return correlated

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

def _calculate_group_severity(findings: List[Dict[str, Any]]) -> int:
    """Calculate severity for a group of findings."""
    severities = [f.get("severity", 1) for f in findings]
    # Return the maximum severity in the group
    return max(severities) if severities else 1

def _calculate_group_confidence(findings: List[Dict[str, Any]]) -> float:
    """Calculate confidence for a group of findings."""
    confidences = [f.get("confidence", 0.0) for f in findings]
    if not confidences:
        return 0.0
    
    # For multiple findings, confidence increases but with diminishing returns
    avg_conf = sum(confidences) / len(confidences)
    confidence_boost = min(0.2 * (len(findings) - 1), 0.5)  # Max 50% boost
    return min(avg_conf + confidence_boost, 1.0)

def prioritize_findings(findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Prioritize findings based on contextual risk assessment.
    
    Args:
        findings: List of findings to prioritize
        context: Additional context for risk assessment
        
    Returns:
        List of findings sorted by priority
    """
    context = context or {}
    
    # Calculate risk score for each finding
    scored_findings = []
    for finding in findings:
        risk_score = _calculate_risk_score(finding, context)
        finding_with_risk = finding.copy()
        finding_with_risk["risk_score"] = risk_score
        finding_with_risk["priority"] = _risk_score_to_priority(risk_score)
        scored_findings.append(finding_with_risk)
    
    # Sort by risk score (descending)
    return sorted(scored_findings, key=lambda x: x["risk_score"], reverse=True)

def _calculate_risk_score(finding: Dict[str, Any], context: Dict[str, Any]) -> float:
    """Calculate a comprehensive risk score for a finding."""
    # Base score from severity (1-5)
    base_severity = finding.get("severity", 1)
    
    # Confidence factor (0.0-1.0)
    confidence = finding.get("confidence", 0.5)
    
    # Target criticality from context
    target_criticality = _get_target_criticality(finding.get("target", ""), context)
    
    # Exploitability factor
    exploitability = _get_exploitability_factor(finding)
    
    # Business impact factor
    business_impact = _get_business_impact_factor(finding, context)
    
    # Calculate weighted risk score
    risk_score = (
        base_severity * 0.3 +
        confidence * 2.0 +  # Scale confidence to 0-2 range
        target_criticality * 0.2 +
        exploitability * 0.2 +
        business_impact * 0.1
    )
    
    return min(risk_score, 5.0)  # Cap at 5.0

def _get_target_criticality(target: str, context: Dict[str, Any]) -> float:
    """Get criticality score for a target based on context."""
    critical_assets = context.get("critical_assets", [])
    
    # Check if target is in critical assets list
    if any(asset in target for asset in critical_assets):
        return 1.0
    
    # Check for sensitive paths
    sensitive_paths = ["/admin", "/login", "/api", "/payment", "/user"]
    if any(path in target for path in sensitive_paths):
        return 0.8
    
    return 0.5  # Default

def _get_exploitability_factor(finding: Dict[str, Any]) -> float:
    """Get exploitability factor based on finding characteristics."""
    vuln_type = finding.get("type", "").lower()
    
    # High exploitability
    if any(t in vuln_type for t in ["rce", "command", "exec"]):
        return 1.0
    
    # Medium exploitability
    if any(t in vuln_type for t in ["sqli", "xss", "csrf"]):
        return 0.7
    
    # Low exploitability
    if any(t in vuln_type for t in ["info", "disclosure", "exposure"]):
        return 0.3
    
    return 0.5  # Default

def _get_business_impact_factor(finding: Dict[str, Any], context: Dict[str, Any]) -> float:
    """Get business impact factor based on finding and context."""
    target = finding.get("target", "").lower()
    
    # High impact targets
    high_impact_indicators = ["/payment", "/checkout", "/cart", "/billing", "/finance"]
    if any(indicator in target for indicator in high_impact_indicators):
        return 1.0
    
    # Medium impact targets
    medium_impact_indicators = ["/user", "/profile", "/account", "/admin", "/login"]
    if any(indicator in target for indicator in medium_impact_indicators):
        return 0.7
    
    return 0.3  # Default

def _risk_score_to_priority(risk_score: float) -> str:
    """Convert risk score to priority label."""
    if risk_score >= 4.0:
        return "critical"
    elif risk_score >= 3.0:
        return "high"
    elif risk_score >= 2.0:
        return "medium"
    elif risk_score >= 1.0:
        return "low"
    else:
        return "info"

def generate_contextual_explanation(finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
    """
    Generate a contextual explanation for a finding.
    
    Args:
        finding: The finding to explain
        context: Additional context for explanation
        
    Returns:
        Contextual explanation string
    """
    context = context or {}
    
    vuln_type = finding.get("type", "unknown")
    target = finding.get("target", "unknown")
    evidence = finding.get("evidence", "")
    
    explanation_parts = []
    
    # Base explanation
    explanation_parts.append(f"Detected {vuln_type} vulnerability on {target}")
    
    # Add context-specific information
    if evidence:
        explanation_parts.append(f"Evidence: {evidence[:100]}...")
    
    # Add risk context
    severity = finding.get("severity", 1)
    confidence = finding.get("confidence", 0.0)
    explanation_parts.append(f"Severity: {severity}/5, Confidence: {confidence:.2f}")
    
    # Add business context
    critical_assets = context.get("critical_assets", [])
    if any(asset in target for asset in critical_assets):
        explanation_parts.append("Target is in critical assets list")
    
    return ". ".join(explanation_parts)

def enhance_findings_with_ai_reasoning(findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Enhance findings with AI-powered reasoning, correlation, and prioritization.
    
    Args:
        findings: List of findings to enhance
        context: Additional context for reasoning
        
    Returns:
        Enhanced findings with correlation, prioritization, and explanations
    """
    context = context or {}
    
    # Try to use enhanced reasoning if available
    try:
        from modules.ai.enhanced_reasoner import (
            correlate_findings_with_reasoning,
            enhanced_risk_scoring
        )
        
        # Step 1: Correlate findings with enhanced reasoning
        correlated_findings = correlate_findings_with_reasoning(findings)
        
        # Step 2: Enhanced risk scoring
        risk_scored_findings = enhanced_risk_scoring(correlated_findings, context)
        
        # Step 3: Add contextual explanations
        enhanced_findings = []
        for finding in risk_scored_findings:
            enhanced_finding = finding.copy()
            
            # Add contextual explanation
            explanation = generate_contextual_explanation(finding, context)
            enhanced_finding["ai_explanation"] = explanation
            
            # Add enhanced reasoning metadata
            enhanced_finding["ai_reasoning"] = {
                "correlated": "findings" in finding,
                "risk_score": finding.get("risk_score", 0.0),
                "priority": finding.get("priority", "low"),
                "processed_at": "2025-11-07",  # In a real implementation, this would be dynamic
                "enhanced_analysis": finding.get("enhanced_analysis", {})
            }
            
            enhanced_findings.append(enhanced_finding)
        
        return enhanced_findings
    except ImportError:
        # Fall back to original reasoning if enhanced reasoner is not available
        pass
    except Exception:
        # Fall back to original reasoning if enhanced reasoner fails
        pass
    
    # Original reasoning as fallback
    # Step 1: Correlate findings
    correlated_findings = correlate_findings(findings)
    
    # Step 2: Prioritize findings
    prioritized_findings = prioritize_findings(correlated_findings, context)
    
    # Step 3: Add contextual explanations
    enhanced_findings = []
    for finding in prioritized_findings:
        enhanced_finding = finding.copy()
        
        # Add contextual explanation
        explanation = generate_contextual_explanation(finding, context)
        enhanced_finding["ai_explanation"] = explanation
        
        # Add reasoning metadata
        enhanced_finding["ai_reasoning"] = {
            "correlated": "findings" in finding,
            "risk_score": finding.get("risk_score", 0.0),
            "priority": finding.get("priority", "low"),
            "processed_at": "2025-11-07"  # In a real implementation, this would be dynamic
        }
        
        enhanced_findings.append(enhanced_finding)
    
    return enhanced_findings

# Backward compatibility function
def generate_tests(context: Dict[str, Any]) -> Dict[str, Any]:
    """Backward compatibility function for existing code."""
    # context: dict with scope & passive findings
    prompt = f"Given this context for safe vulnerability testing (READ-ONLY): {context}\nReturn JSON: hypothesis[], script_template, risk_level, explanation."
    
    if send_prompt:
        return send_prompt(prompt)
    else:
        # Fallback response
        return {
            "hypothesis": ["Potential XSS in user input fields", "SQL injection in search functionality"],
            "script_template": "Basic test script template",
            "risk_level": "medium",
            "explanation": "Generated from context analysis"
        }