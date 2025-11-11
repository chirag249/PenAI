#!/usr/bin/env python3
# tests/test_enhanced_reasoner.py
"""
Test suite for the enhanced AI reasoner with chain-of-thought capabilities.
"""

import sys
import os
import json

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.ai.enhanced_reasoner import (
    chain_of_thought_analysis,
    correlate_findings_with_reasoning,
    enhanced_risk_scoring
)

def test_chain_of_thought_analysis():
    """Test the chain-of-thought analysis function."""
    print("Testing chain-of-thought analysis...")
    
    # Sample finding
    finding = {
        "type": "xss-reflected",
        "target": "https://example.com/search?q=test",
        "severity": 3,
        "confidence": 0.8,
        "evidence": "Reflected script tag <script>alert(1)</script> in query parameter q",
        "source": {"tool": "dalfox", "raw": "test data"}
    }
    
    # Related findings
    related_findings = [
        {
            "type": "xss-reflected",
            "target": "https://example.com/search?q=test2",
            "severity": 3,
            "confidence": 0.7,
            "evidence": "Reflected script tag in different parameter",
            "source": {"tool": "xsstrike", "raw": "test data"}
        }
    ]
    
    # Perform analysis
    result = chain_of_thought_analysis(finding, related_findings)
    
    # Check that all expected keys are present
    expected_keys = [
        "primary_finding", "related_findings_count", "reasoning_steps",
        "risk_factors", "business_impact", "exploitation_likelihood",
        "recommendations", "mitigation_complexity", "false_positive_likelihood"
    ]
    
    for key in expected_keys:
        assert key in result, f"Missing key: {key}"
    
    # Check that we have reasoning steps
    assert len(result["reasoning_steps"]) > 0, "No reasoning steps generated"
    
    print("✓ Chain-of-thought analysis test passed")
    return result

def test_correlate_findings_with_reasoning():
    """Test the correlation function with reasoning."""
    print("Testing correlation with reasoning...")
    
    # Sample findings
    findings = [
        {
            "type": "xss-reflected",
            "target": "https://example.com/search",
            "severity": 3,
            "confidence": 0.8,
            "evidence": "Reflected script tag in query parameter",
            "source": {"tool": "dalfox"}
        },
        {
            "type": "xss-reflected",
            "target": "https://example.com/search",
            "severity": 3,
            "confidence": 0.7,
            "evidence": "Another reflected XSS in search",
            "source": {"tool": "xsstrike"}
        },
        {
            "type": "sqli",
            "target": "https://example.com/login",
            "severity": 4,
            "confidence": 0.9,
            "evidence": "SQL injection in login form",
            "source": {"tool": "sqlmap"}
        }
    ]
    
    # Perform correlation
    result = correlate_findings_with_reasoning(findings)
    
    # Check that we have results (may be different count due to correlation)
    assert len(result) > 0, "No findings returned"
    
    for finding in result:
        assert "enhanced_analysis" in finding, "Missing enhanced analysis"
        assert "correlation" in finding, "Missing correlation data"
        correlation = finding["correlation"]
        assert "correlation_type" in correlation, "Missing correlation type"
        assert "correlation_strength" in correlation, "Missing correlation strength"
    
    print("✓ Correlation with reasoning test passed")
    return result

def test_enhanced_risk_scoring():
    """Test the enhanced risk scoring function."""
    print("Testing enhanced risk scoring...")
    
    # Sample findings
    findings = [
        {
            "type": "rce",
            "target": "https://example.com/api/upload",
            "severity": 5,
            "confidence": 0.9,
            "evidence": "Remote code execution via file upload"
        }
    ]
    
    # Context with critical assets
    context = {
        "critical_assets": ["/api", "/admin"]
    }
    
    # Perform risk scoring
    result = enhanced_risk_scoring(findings, context)
    
    # Check that we have enhanced risk scores
    assert len(result) == len(findings), "Number of findings mismatch"
    
    for finding in result:
        assert "enhanced_risk_score" in finding, "Missing enhanced risk score"
        risk_score = finding["enhanced_risk_score"]
        assert "final_score" in risk_score, "Missing final score"
        assert "priority" in risk_score, "Missing priority"
    
    print("✓ Enhanced risk scoring test passed")
    return result

def main():
    """Run all tests."""
    print("Running enhanced reasoner tests...\n")
    
    try:
        # Run individual tests
        cot_result = test_chain_of_thought_analysis()
        print(f"Chain-of-thought analysis generated {len(cot_result['reasoning_steps'])} reasoning steps\n")
        
        correlation_result = test_correlate_findings_with_reasoning()
        print(f"Correlation processed {len(correlation_result)} findings\n")
        
        risk_result = test_enhanced_risk_scoring()
        print(f"Risk scoring generated scores for {len(risk_result)} findings\n")
        
        print("All tests passed! ✓")
        
        # Print sample output for demonstration
        print("\n--- Sample Chain-of-Thought Analysis Output ---")
        print(json.dumps(cot_result, indent=2)[:1000] + "...")
        
    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()