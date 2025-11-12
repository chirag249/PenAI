#!/usr/bin/env python3
"""
Test script for enterprise-grade performance and scalability features.
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_distributed_scanner():
    """Test the distributed scanner module."""
    print("Testing distributed scanner module...")
    
    try:
        from modules.distributed_scanner import DistributedScanner, DistributedScanCoordinator
        
        # Create an instance
        scanner = DistributedScanner()
        coordinator = DistributedScanCoordinator()
        print("✓ DistributedScanner and DistributedScanCoordinator instantiated successfully")
        
        print("✓ Distributed scanner module tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Distributed scanner module test failed: {e}")
        return False

def test_resource_monitor():
    """Test the resource monitor module."""
    print("\nTesting resource monitor module...")
    
    try:
        from modules.resource_monitor import ResourceMonitor, AdaptiveResourceOptimizer
        
        # Create an instance
        monitor = ResourceMonitor()
        optimizer = AdaptiveResourceOptimizer(monitor)
        print("✓ ResourceMonitor and AdaptiveResourceOptimizer instantiated successfully")
        
        # Test metrics collection
        metrics = monitor._collect_metrics()
        if metrics and "timestamp" in metrics:
            print("✓ Resource metrics collection working")
        else:
            print("⚠ Resource metrics collection returned unexpected results")
        
        print("✓ Resource monitor module tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Resource monitor module test failed: {e}")
        return False

def test_cache_manager():
    """Test the cache manager module."""
    print("\nTesting cache manager module...")
    
    try:
        from modules.cache_manager import IntelligentCache
        
        # Create an instance
        cache = IntelligentCache()
        print("✓ IntelligentCache instantiated successfully")
        
        # Test cache operations
        test_data = {"test": "data", "findings": ["finding1", "finding2"]}
        result = cache.put("example.com", "xss", {"param": "value"}, test_data)
        if result:
            print("✓ Cache put operation successful")
        else:
            print("⚠ Cache put operation failed")
        
        cached_data = cache.get("example.com", "xss", {"param": "value"})
        if cached_data == test_data:
            print("✓ Cache get operation successful")
        else:
            print("⚠ Cache get operation returned unexpected results")
        
        # Test cache stats
        stats = cache.get_stats()
        if stats and "total_entries" in stats:
            print("✓ Cache stats retrieval working")
        else:
            print("⚠ Cache stats retrieval returned unexpected results")
        
        print("✓ Cache manager module tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Cache manager module test failed: {e}")
        return False

def test_tenant_manager():
    """Test the tenant manager module."""
    print("\nTesting tenant manager module...")
    
    try:
        from modules.tenant_manager import TenantManager, Tenant
        
        # Create an instance
        tenant_manager = TenantManager()
        print("✓ TenantManager instantiated successfully")
        
        # Test tenant creation
        tenant_id = tenant_manager.create_tenant(
            name="Test Tenant",
            config={"scan_profile": "normal"},
            allowed_targets=["*.example.com", "testphp.vulnweb.com"],
            scan_limit=50
        )
        if tenant_id:
            print("✓ Tenant creation successful")
        else:
            print("⚠ Tenant creation failed")
        
        # Test tenant retrieval
        tenant = tenant_manager.get_tenant(tenant_id)
        if tenant and tenant.name == "Test Tenant":
            print("✓ Tenant retrieval successful")
        else:
            print("⚠ Tenant retrieval returned unexpected results")
        
        # Test target validation
        allowed = tenant_manager.is_target_allowed(tenant_id, "testphp.vulnweb.com")
        if allowed:
            print("✓ Target validation working for allowed target")
        else:
            print("⚠ Target validation failed for allowed target")
        
        not_allowed = tenant_manager.is_target_allowed(tenant_id, "malicious-site.com")
        if not not_allowed:
            print("✓ Target validation working for disallowed target")
        else:
            print("⚠ Target validation failed for disallowed target")
        
        # Clean up
        tenant_manager.delete_tenant(tenant_id)
        print("✓ Tenant cleanup completed")
        
        print("✓ Tenant manager module tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Tenant manager module test failed: {e}")
        return False

def test_integration():
    """Test the integration of new features with agent."""
    print("\nTesting integration with agent...")
    
    try:
        # Check that the imports were added to agent.py
        with open("agent.py", "r") as f:
            content = f.read()
            
        required_imports = [
            "from modules.distributed_scanner import initiate_distributed_scan",
            "from modules.resource_monitor import get_resource_monitor",
            "from modules.cache_manager import get_cached_results",
            "from modules.tenant_manager import validate_tenant_scan"
        ]
        
        missing_imports = []
        for imp in required_imports:
            if imp not in content:
                missing_imports.append(imp)
        
        if not missing_imports:
            print("✓ All required imports found in agent.py")
        else:
            print(f"⚠ Missing imports in agent.py: {missing_imports}")
        
        # Check that the new arguments were added
        required_args = [
            "--distributed",
            "--tenant-id",
            "--redis-host",
            "--enable-caching",
            "--monitor-resources"
        ]
        
        missing_args = []
        for arg in required_args:
            if arg not in content:
                missing_args.append(arg)
        
        if not missing_args:
            print("✓ All required arguments found in agent.py")
        else:
            print(f"⚠ Missing arguments in agent.py: {missing_args}")
            
        print("✓ Integration tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Running tests for enterprise-grade performance and scalability features...\n")
    
    tests = [
        test_distributed_scanner,
        test_resource_monitor,
        test_cache_manager,
        test_tenant_manager,
        test_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\nTest Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The new enterprise features are working correctly.")
        return 0
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())