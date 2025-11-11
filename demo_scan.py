#!/usr/bin/env python3
"""
Demo script to start a scan through the web UI
"""

import requests

def start_demo_scan():
    # URL of the web UI
    url = 'http://localhost:5000/start'
    
    # Scan parameters
    data = {
        'target': 'https://testphp.vulnweb.com',
        'mode': 'non-destructive',
        'run_id': 'demo-scan-1'
    }
    
    try:
        # Send POST request to start scan
        response = requests.post(url, data=data)
        if response.status_code == 204:
            print("Scan started successfully!")
            print("Check the web UI at http://localhost:5000 to monitor progress")
        else:
            print(f"Failed to start scan. Status code: {response.status_code}")
            print(response.text)
    except Exception as e:
        print(f"Error starting scan: {e}")

if __name__ == "__main__":
    start_demo_scan()