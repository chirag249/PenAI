#!/usr/bin/env python3
"""
Test script for the web UI functionality
"""

import requests
import time
import json

def test_webui():
    # Test accessing the main page
    print("Testing main page access...")
    try:
        response = requests.get('http://localhost:5000/')
        print(f"Main page status code: {response.status_code}")
        print(f"Main page content length: {len(response.text)}")
    except Exception as e:
        print(f"Error accessing main page: {e}")
    
    # Test accessing the summary report endpoint
    print("\nTesting summary report endpoint...")
    try:
        response = requests.get('http://localhost:5000/summary/test')
        print(f"Summary report status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Summary report keys: {list(data.keys())}")
            print(f"Total findings: {data['scan_summary']['total_findings']}")
    except Exception as e:
        print(f"Error accessing summary report: {e}")
    
    # Test accessing the latest endpoint
    print("\nTesting latest endpoint...")
    try:
        response = requests.get('http://localhost:5000/latest')
        print(f"Latest endpoint status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Latest data: {data}")
    except Exception as e:
        print(f"Error accessing latest endpoint: {e}")

if __name__ == "__main__":
    test_webui()