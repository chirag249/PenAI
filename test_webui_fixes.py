#!/usr/bin/env python3
"""
Test script to verify all web UI fixes
"""

import requests
import time

def test_webui_fixes():
    base_url = 'http://localhost:5000'
    
    print("Testing Web UI Fixes...")
    
    # Test 1: Frontend loading
    print("\n1. Testing frontend loading...")
    try:
        response = requests.get(f'{base_url}/')
        assert response.status_code == 200
        assert '<title>PenAI - Penetration Testing Automation</title>' in response.text
        print("   ✓ Frontend loads correctly")
    except Exception as e:
        print(f"   ✗ Frontend loading failed: {e}")
        return False
    
    # Test 2: API endpoints
    print("\n2. Testing API endpoints...")
    try:
        response = requests.get(f'{base_url}/api/latest')
        assert response.status_code == 200
        data = response.json()
        assert 'latest' in data
        print("   ✓ /api/latest endpoint works")
    except Exception as e:
        print(f"   ✗ /api/latest failed: {e}")
        return False
    
    # Test 3: Summary report JSON download
    print("\n3. Testing summary report JSON download...")
    try:
        response = requests.get(f'{base_url}/api/download/test/reports/summary_report.json')
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'application/json'
        data = response.json()
        assert 'scan_summary' in data
        print("   ✓ Summary report JSON download works")
    except Exception as e:
        print(f"   ✗ Summary report JSON download failed: {e}")
        return False
    
    # Test 4: Summary report TXT download
    print("\n4. Testing summary report TXT download...")
    try:
        response = requests.get(f'{base_url}/api/download/test/reports/summary_report.txt')
        assert response.status_code == 200
        assert 'text/plain' in response.headers['Content-Type']
        assert 'PENAI SECURITY SCAN SUMMARY REPORT' in response.text
        print("   ✓ Summary report TXT download works")
    except Exception as e:
        print(f"   ✗ Summary report TXT download failed: {e}")
        return False
    
    # Test 5: Button disable during scan (simulated)
    print("\n5. Testing button disable logic...")
    try:
        # This would be tested in browser, but we can verify the JavaScript exists
        response = requests.get(f'{base_url}/')
        assert 'scanInProgress = false;' in response.text
        assert 'allButtons.forEach(button => {' in response.text
        print("   ✓ Button disable logic present in frontend")
    except Exception as e:
        print(f"   ✗ Button disable logic check failed: {e}")
        return False
    
    # Test 6: Report visibility
    print("\n6. Testing report visibility...")
    try:
        response = requests.get(f'{base_url}/')
        assert 'id="report-content"' in response.text
        assert 'id="latest-run-card"' in response.text
        print("   ✓ Report visibility elements present")
    except Exception as e:
        print(f"   ✗ Report visibility check failed: {e}")
        return False
    
    print("\n🎉 All tests passed! Web UI fixes are working correctly.")
    return True

if __name__ == "__main__":
    test_webui_fixes()