#!/usr/bin/env python3
"""
False Positive Reduction Module for PenAI
Implements machine learning and rule-based mechanisms to reduce false positives.
"""

import json
import os
from typing import List, Dict, Any
from collections import defaultdict

# Try to import ML libraries
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    TfidfVectorizer = None
    RandomForestClassifier = None
    train_test_split = None
    classification_report = None
    np = None

def extract_features_from_finding(finding: Dict[str, Any]) -> str:
    """Extract text features from a finding for ML analysis."""
    features = []
    
    # Extract text from various fields
    for field in ['type', 'description', 'evidence', 'target', 'parameter']:
        value = finding.get(field, "")
        if isinstance(value, str) and value.strip():
            features.append(value.strip())
        elif isinstance(value, dict):
            for v in value.values():
                if isinstance(v, str) and v.strip():
                    features.append(v.strip())
    
    return " ".join(features).lower()

def rule_based_filtering(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply rule-based filtering to reduce false positives."""
    filtered_findings = []
    
    for finding in findings:
        # Skip if it's already marked as low confidence
        confidence = finding.get("confidence", "medium").lower()
        if confidence in ["low", "info"]:
            # But still include if severity is high
            severity = finding.get("severity", 1)
            if severity < 4:
                continue
        
        # Filter out common false positive patterns
        evidence = str(finding.get("evidence", "")).lower()
        target = str(finding.get("target", "")).lower()
        
        # Skip if evidence contains common false positive indicators
        false_positive_indicators = [
            "404 page", "not found", "page not found",
            "default page", "welcome page",
            "test page", "sample page",
            "under construction"
        ]
        
        if any(indicator in evidence for indicator in false_positive_indicators):
            # But still include if severity is critical
            if finding.get("severity", 1) < 5:
                continue
        
        # Skip low severity findings on non-sensitive paths
        severity = finding.get("severity", 1)
        if severity <= 2:
            non_sensitive_paths = ["/images/", "/css/", "/js/", "/static/"]
            if any(path in target for path in non_sensitive_paths):
                continue
        
        filtered_findings.append(finding)
    
    return filtered_findings

def train_false_positive_model(training_data: List[Dict[str, Any]]) -> Any:
    """Train a model to identify false positives."""
    if not ML_AVAILABLE:
        return None
    
    try:
        # Prepare training data
        texts = []
        labels = []  # 1 = real finding, 0 = false positive
        
        for item in training_data:
            text = extract_features_from_finding(item)
            label = item.get("is_real_finding", 1)  # Default to real finding
            
            texts.append(text)
            labels.append(label)
        
        if len(set(labels)) < 2:
            # Not enough variation in labels for training
            return None
        
        # Vectorize text
        vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        X = vectorizer.fit_transform(texts)
        y = np.array(labels)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        
        return {
            'model': model,
            'vectorizer': vectorizer
        }
    except Exception as e:
        print(f"Warning: Failed to train false positive model: {e}")
        return None

def apply_ml_filtering(findings: List[Dict[str, Any]], model_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Apply ML-based filtering to reduce false positives."""
    if not ML_AVAILABLE or not model_data:
        return findings
    
    try:
        model = model_data.get('model')
        vectorizer = model_data.get('vectorizer')
        
        if not model or not vectorizer:
            return findings
        
        filtered_findings = []
        
        for finding in findings:
            # Extract features
            text = extract_features_from_finding(finding)
            
            # Vectorize
            X = vectorizer.transform([text])
            
            # Predict
            prediction = model.predict(X)[0]
            probability = model.predict_proba(X)[0]
            
            # If model predicts it's a real finding, or if confidence is high, keep it
            if prediction == 1 or max(probability) > 0.8:
                # Add ML prediction info to finding
                finding['ml_filtering'] = {
                    'prediction': 'real_finding' if prediction == 1 else 'false_positive',
                    'confidence': float(max(probability)),
                    'probabilities': {
                        'false_positive': float(probability[0]),
                        'real_finding': float(probability[1])
                    }
                }
                filtered_findings.append(finding)
        
        return filtered_findings
    except Exception as e:
        print(f"Warning: Failed to apply ML filtering: {e}")
        return findings

def reduce_false_positives(findings: List[Dict[str, Any]], training_data_path: str = None) -> List[Dict[str, Any]]:
    """Main function to reduce false positives using both rule-based and ML approaches."""
    # Apply rule-based filtering first
    filtered_findings = rule_based_filtering(findings)
    
    # Apply ML-based filtering if model is available
    model_data = None
    if training_data_path and os.path.exists(training_data_path):
        try:
            with open(training_data_path, 'r') as f:
                training_data = json.load(f)
            model_data = train_false_positive_model(training_data)
        except Exception as e:
            print(f"Warning: Failed to load training data: {e}")
    
    if model_data:
        filtered_findings = apply_ml_filtering(filtered_findings, model_data)
    
    # Add filtering metadata
    for finding in filtered_findings:
        if 'filtering_info' not in finding:
            finding['filtering_info'] = {
                'original_count': len(findings),
                'after_filtering': len(filtered_findings),
                'reduction_percentage': round((len(findings) - len(filtered_findings)) / len(findings) * 100, 2) if findings else 0
            }
    
    return filtered_findings

# Integration with enhanced reporter
def integrate_with_enhanced_reporter():
    """Integrate false positive reduction with the enhanced reporter."""
    try:
        # We would modify the enhanced reporter to use this functionality
        pass
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_enhanced_reporter()