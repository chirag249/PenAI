#!/usr/bin/env python3
"""
Test script for validating the enhanced security testing adapters.

This script tests all the enhanced adapters to ensure they:
1. Load correctly
2. Handle errors appropriately
3. Produce expected output formats
4. Integrate with the adaptive scanner
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path

# Add the modules directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / "modules"))

def test_nmap_adapter():
    """Test the enhanced Nmap adapter."""
    print("Testing Nmap enhanced adapter...")
    
    try:
        from modules.tools.nmap_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a simple target (localhost)
            result = run(
                outdir=tmpdir,
                target="127.0.0.1",
                extra_args=["--top-ports", "10"],  # Quick scan
                timeout=30
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "nmap", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ Nmap enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ Nmap enhanced adapter test failed: {e}")
        return False

def test_sqlmap_adapter():
    """Test the enhanced SQLmap adapter."""
    print("Testing SQLmap enhanced adapter...")
    
    try:
        from modules.tools.sqlmap_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a mock target
            result = run(
                outdir=tmpdir,
                target="http://testphp.vulnweb.com/artists.php?artist=1",
                extra_args=["--level=1", "--risk=1"],  # Minimal scan
                timeout=30
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "sqlmap", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ SQLmap enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ SQLmap enhanced adapter test failed: {e}")
        return False

def test_nuclei_adapter():
    """Test the enhanced Nuclei adapter."""
    print("Testing Nuclei enhanced adapter...")
    
    try:
        from modules.tools.nuclei_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a simple target
            result = run(
                outdir=tmpdir,
                target="http://example.com",
                extra_args=["-tags", "misconfig"],  # Quick scan
                timeout=30
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "nuclei", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ Nuclei enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ Nuclei enhanced adapter test failed: {e}")
        return False

def test_nikto_adapter():
    """Test the enhanced Nikto adapter."""
    print("Testing Nikto enhanced adapter...")
    
    try:
        from modules.tools.nikto_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a simple target
            result = run(
                outdir=tmpdir,
                target="http://example.com",
                extra_args=["-Cgidirs", "none", "-maxtime", "60"],  # Quick scan
                timeout=60
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "nikto", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ Nikto enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ Nikto enhanced adapter test failed: {e}")
        return False

def test_wpscan_adapter():
    """Test the enhanced WPScan adapter."""
    print("Testing WPScan enhanced adapter...")
    
    try:
        from modules.tools.wpscan_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a mock target (WPScan needs a WordPress site)
            result = run(
                outdir=tmpdir,
                target="http://wordpress.org",
                extra_args=["--enumerate", "vp", "--max-threads", "5"],  # Quick scan
                timeout=60
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "wpscan", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ WPScan enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ WPScan enhanced adapter test failed: {e}")
        return False

def test_xss_adapter():
    """Test the enhanced XSS adapter."""
    print("Testing XSS enhanced adapter...")
    
    try:
        from modules.tools.xss_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a mock target
            result = run(
                outdir=tmpdir,
                target="http://testphp.vulnweb.com/search.php?test=query",
                extra_args=["--threads", "5"],  # Quick scan
                timeout=60
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "xss", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Detected tool: {result['meta'].get('detected_tool', 'N/A')}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ XSS enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ XSS enhanced adapter test failed: {e}")
        return False

def test_sslyze_adapter():
    """Test the enhanced SSLyze adapter."""
    print("Testing SSLyze enhanced adapter...")
    
    try:
        from modules.tools.sslyze_enhanced_adapter import run
        
        # Create a temporary directory for output
        with tempfile.TemporaryDirectory() as tmpdir:
            # Test with a simple target (Google's HTTPS port)
            result = run(
                outdir=tmpdir,
                target="www.google.com:443",
                extra_args=["--tlsv1_2", "--certinfo"],  # Quick scan
                timeout=60
            )
            
            # Check that we got a result
            assert "meta" in result, "Missing meta section in result"
            assert "result" in result, "Missing result section in result"
            assert result["meta"]["tool"] == "sslyze", "Incorrect tool name"
            
            print(f"  Status: {result['meta']['status']}")
            print(f"  Execution time: {result['result'].get('execution_time', 'N/A')}s")
            
            # Check that output file was created
            assert "output_file" in result, "Missing output_file in result"
            assert os.path.exists(result["output_file"]), "Output file not created"
            
            print("  ✓ SSLyze enhanced adapter test passed")
            return True
            
    except Exception as e:
        print(f"  ✗ SSLyze enhanced adapter test failed: {e}")
        return False

def test_adapter_loading():
    """Test that all enhanced adapters can be loaded."""
    print("Testing adapter loading...")
    
    adapters = [
        "nmap_enhanced_adapter",
        "sqlmap_enhanced_adapter",
        "nuclei_enhanced_adapter",
        "nikto_enhanced_adapter",
        "wpscan_enhanced_adapter",
        "xss_enhanced_adapter",
        "sslyze_enhanced_adapter"
    ]
    
    success_count = 0
    for adapter_name in adapters:
        try:
            module = __import__(f"modules.tools.{adapter_name}", fromlist=["run"])
            assert hasattr(module, "run"), f"Module {adapter_name} missing run function"
            print(f"  ✓ {adapter_name} loaded successfully")
            success_count += 1
        except Exception as e:
            print(f"  ✗ {adapter_name} failed to load: {e}")
    
    print(f"Adapter loading: {success_count}/{len(adapters)} passed")
    return success_count == len(adapters)

def main():
    """Run all tests."""
    print("Running enhanced adapter validation tests...\n")
    
    # Test adapter loading
    if not test_adapter_loading():
        print("\nAdapter loading tests failed. Exiting.")
        return 1
    
    # Test individual adapters
    tests = [
        test_nmap_adapter,
        test_sqlmap_adapter,
        test_nuclei_adapter,
        test_nikto_adapter,
        test_wpscan_adapter,
        test_xss_adapter,
        test_sslyze_adapter
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"Test {test.__name__} failed with exception: {e}")
        print()  # Add spacing between tests
    
    print(f"Enhanced adapter tests: {passed}/{total} passed")
    
    if passed == total:
        print("🎉 All enhanced adapter tests passed!")
        return 0
    else:
        print("❌ Some tests failed. Please check the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())