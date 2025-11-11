#!/usr/bin/env python3
"""
Test script to verify the mode argument fix
"""

import subprocess
import sys

def test_mode_arguments():
    print("Testing mode argument fix...")
    
    # Test 1: Check if agent.py accepts --force-destructive
    print("\n1. Testing --force-destructive argument...")
    try:
        result = subprocess.run([
            "python3", "agent.py", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        if "--force-destructive" in result.stdout:
            print("   ✓ --force-destructive argument is supported")
        else:
            print("   ✗ --force-destructive argument not found")
            return False
    except Exception as e:
        print(f"   ✗ Error testing --force-destructive: {e}")
        return False
    
    # Test 2: Check if agent.py accepts --skip-destructive
    print("\n2. Testing --skip-destructive argument...")
    try:
        result = subprocess.run([
            "python3", "agent.py", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        if "--skip-destructive" in result.stdout:
            print("   ✓ --skip-destructive argument is supported")
        else:
            print("   ✗ --skip-destructive argument not found")
            return False
    except Exception as e:
        print(f"   ✗ Error testing --skip-destructive: {e}")
        return False
    
    # Test 3: Verify that --mode is NOT in agent.py (should fail)
    print("\n3. Verifying --mode argument is NOT supported by agent.py...")
    try:
        result = subprocess.run([
            "python3", "agent.py", "--help"
        ], capture_output=True, text=True, timeout=10)
        
        if "--mode" not in result.stdout:
            print("   ✓ --mode argument is correctly NOT supported")
        else:
            print("   ✗ --mode argument should not be supported")
            return False
    except Exception as e:
        print(f"   ✗ Error testing --mode: {e}")
        return False
    
    print("\n🎉 All tests passed! Mode argument fix is working correctly.")
    return True

if __name__ == "__main__":
    test_mode_arguments()