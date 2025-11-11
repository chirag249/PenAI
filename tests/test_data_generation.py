#!/usr/bin/env python3
# tests/test_data_generation.py
"""
Test script for the enhanced training data generation.
"""

import sys
import os

# Add the scripts directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from scripts.generate_enhanced_training_data import generate_sample_cve_data

def test_sample_data_generation():
    """Test that sample CVE data generation works."""
    print("Testing sample CVE data generation...")
    
    # Generate sample data
    sample_data = generate_sample_cve_data()
    
    # Check that we have data
    assert len(sample_data) > 0, "No sample data generated"
    
    # Check structure of first entry
    first_entry = sample_data[0]
    assert "cve" in first_entry, "Missing CVE field"
    assert "description" in first_entry, "Missing description field"
    assert "impact" in first_entry, "Missing impact field"
    
    print(f"✓ Generated {len(sample_data)} sample CVE entries")
    print(f"  First CVE: {first_entry['cve']}")
    print(f"  Description: {first_entry['description'][:100]}...")
    
    return sample_data

def test_data_diversity():
    """Test that generated data has good diversity."""
    print("\nTesting data diversity...")
    
    # Generate sample data
    sample_data = generate_sample_cve_data()
    
    # Check for diversity in CVE numbers
    cve_numbers = [entry["cve"] for entry in sample_data]
    unique_cves = set(cve_numbers)
    assert len(unique_cves) == len(cve_numbers), "Duplicate CVE numbers found"
    
    # Check for diversity in descriptions
    descriptions = [entry["description"] for entry in sample_data]
    unique_descriptions = set(descriptions)
    # Allow some duplicates but not too many
    assert len(unique_descriptions) > len(descriptions) * 0.8, "Too many duplicate descriptions"
    
    # Check for variety in severity levels
    severities = []
    for entry in sample_data:
        if "impact" in entry and "baseMetricV3" in entry["impact"]:
            severity = entry["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
            severities.append(severity)
    
    unique_severities = set(severities)
    expected_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert unique_severities.issubset(expected_severities), "Unexpected severity levels found"
    
    print(f"✓ Data diversity check passed")
    print(f"  Unique CVEs: {len(unique_cves)}")
    print(f"  Unique descriptions: {len(unique_descriptions)}")
    print(f"  Severity levels: {sorted(unique_severities)}")
    
    return True

def main():
    """Run all tests."""
    print("Running data generation tests...\n")
    
    try:
        # Run individual tests
        sample_data = test_sample_data_generation()
        test_data_diversity()
        
        print("\nAll tests passed! ✓")
        
    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()