#!/usr/bin/env python3
# demo_enhanced_ai.py
"""
Demonstration script showing the enhanced AI capabilities.
"""

import sys
import os
import json

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

def demo_enhanced_classification():
    """Demonstrate enhanced vulnerability classification."""
    print("=== Enhanced Vulnerability Classification ===")
    
    # Sample vulnerability descriptions
    samples = [
        {
            "text": "Reflected cross-site scripting vulnerability in user profile page. Script tag <script>alert(1)</script> reflected in query parameter.",
            "expected": "xss-reflected"
        },
        {
            "text": "SQL injection vulnerability in login form allows remote attackers to execute arbitrary SQL commands via ' OR 1=1-- in id parameter.",
            "expected": "sqli"
        },
        {
            "text": "Remote code execution vulnerability in image processing component due to unsafe deserialization.",
            "expected": "rce"
        },
        {
            "text": "Path traversal vulnerability allows attackers to read arbitrary files on the server through file parameter.",
            "expected": "lfi"
        }
    ]
    
    # Try to use the enhanced classifier
    try:
        from modules.ai.vuln_types import TYPE_KEYWORDS
        
        for i, sample in enumerate(samples, 1):
            text = sample["text"].lower()
            expected = sample["expected"]
            
            # Simple keyword-based classification (in a real implementation, this would use the trained model)
            predicted = "other"
            for vuln_type, keywords in TYPE_KEYWORDS.items():
                if any(keyword in text for keyword in keywords):
                    predicted = vuln_type
                    break
            
            print(f"Sample {i}:")
            print(f"  Text: {sample['text'][:100]}...")
            print(f"  Expected: {expected}")
            print(f"  Predicted: {predicted}")
            print(f"  Match: {'✓' if predicted == expected else '✗'}")
            print()
            
    except ImportError:
        print("Enhanced classification not available (missing modules)")
        print()

def demo_chain_of_thought_reasoning():
    """Demonstrate chain-of-thought reasoning."""
    print("=== Chain-of-Thought Reasoning ===")
    
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
    
    try:
        from modules.ai.enhanced_reasoner import chain_of_thought_analysis
        
        # Perform analysis
        result = chain_of_thought_analysis(finding, related_findings)
        
        print("Reasoning Steps:")
        for step in result["reasoning_steps"]:
            print(f"  {step}")
        
        print(f"\nBusiness Impact: {result['business_impact']}")
        print(f"Exploitation Likelihood: {result['exploitation_likelihood']}")
        print(f"Mitigation Complexity: {result['mitigation_complexity']}")
        print(f"False Positive Likelihood: {result['false_positive_likelihood']:.2f}")
        
        print(f"\nRecommendations:")
        for i, rec in enumerate(result["recommendations"], 1):
            print(f"  {i}. {rec}")
            
    except ImportError:
        print("Chain-of-thought reasoning not available (missing modules)")
    
    print()

def demo_enhanced_correlation():
    """Demonstrate enhanced correlation."""
    print("=== Enhanced Correlation ===")
    
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
        }
    ]
    
    try:
        from modules.ai.enhanced_reasoner import correlate_findings_with_reasoning
        
        # Perform correlation
        result = correlate_findings_with_reasoning(findings)
        
        print(f"Processed {len(result)} correlated findings:")
        for i, finding in enumerate(result, 1):
            correlation = finding.get("correlation", {})
            print(f"  Finding {i}:")
            print(f"    Type: {finding.get('type', 'unknown')}")
            print(f"    Correlation Type: {correlation.get('correlation_type', 'none')}")
            print(f"    Correlation Strength: {correlation.get('correlation_strength', 0.0):.2f}")
            print(f"    Confidence Boost: {correlation.get('confidence_boost', 0.0):.2f}")
            
    except ImportError:
        print("Enhanced correlation not available (missing modules)")
    
    print()

def demo_enhanced_risk_scoring():
    """Demonstrate enhanced risk scoring."""
    print("=== Enhanced Risk Scoring ===")
    
    # Sample finding
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
    
    try:
        from modules.ai.enhanced_reasoner import enhanced_risk_scoring
        
        # Perform risk scoring
        result = enhanced_risk_scoring(findings, context)
        
        for finding in result:
            risk_score = finding["enhanced_risk_score"]
            print(f"Finding Type: {finding.get('type', 'unknown')}")
            print(f"Final Risk Score: {risk_score['final_score']:.1f}/10.0")
            print(f"Base Score: {risk_score['base_score']:.1f}")
            print(f"CVSS Score: {risk_score['cvss_score']:.1f}")
            print(f"Business Impact Score: {risk_score['business_impact_score']:.1f}")
            print(f"Temporal Score: {risk_score['temporal_score']:.1f}")
            print(f"Environmental Score: {risk_score['environmental_score']:.1f}")
            print(f"Priority: {risk_score['priority']}")
            
    except ImportError:
        print("Enhanced risk scoring not available (missing modules)")
    
    print()

def main():
    """Run all demonstrations."""
    print("Pentest AI Enhanced Capabilities Demonstration")
    print("=" * 50)
    print()
    
    demo_enhanced_classification()
    demo_chain_of_thought_reasoning()
    demo_enhanced_correlation()
    demo_enhanced_risk_scoring()
    
    print("Demonstration complete!")

if __name__ == "__main__":
    main()