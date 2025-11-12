#!/usr/bin/env python3
"""
Test script to verify security and compliance modules
"""

def test_module_imports():
    """Test that all security and compliance modules can be imported."""
    modules_to_test = [
        "modules.audit_logger",
        "modules.access_control",
        "modules.compliance.compliance_reporter",
        "modules.compliance.data_protection",
        "modules.compliance.privacy_preserving"
    ]
    
    failed_imports = []
    
    for module_name in modules_to_test:
        try:
            __import__(module_name)
            print(f"✓ {module_name} imported successfully")
        except ImportError as e:
            print(f"✗ {module_name} failed to import: {e}")
            failed_imports.append(module_name)
    
    if failed_imports:
        print(f"\nFailed to import {len(failed_imports)} modules:")
        for module in failed_imports:
            print(f"  - {module}")
        return False
    else:
        print("\nAll modules imported successfully!")
        return True

def test_basic_functionality():
    """Test basic functionality of key modules."""
    try:
        # Test audit logger
        from modules.audit_logger import AuditLogger
        audit = AuditLogger("/tmp/test")
        event_id = audit.log_event("TEST", "test_user", "test_resource", "test_action")
        print(f"✓ Audit logger working, event ID: {event_id}")
        
        # Test access control
        from modules.access_control import AccessControlManager
        acm = AccessControlManager()
        acm.create_user("testuser", "testpass", ["testrole"])
        print("✓ Access control manager working")
        
        # Test compliance reporter
        from modules.compliance.compliance_reporter import ComplianceReporter
        cr = ComplianceReporter("/tmp/test")
        print("✓ Compliance reporter initialized")
        
        # Test data protection
        from modules.compliance.data_protection import DataProtectionManager
        dpm = DataProtectionManager("/tmp/test")
        encrypted = dpm.encrypt_data("test data")
        decrypted = dpm.decrypt_data(encrypted)
        print(f"✓ Data protection working: {decrypted}")
        
        # Test privacy preserving
        from modules.compliance.privacy_preserving import PrivacyPreservingScanner
        pps = PrivacyPreservingScanner("/tmp/test", "standard")
        print("✓ Privacy preserving scanner initialized")
        
        return True
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

if __name__ == "__main__":
    print("Testing Security and Compliance Module Imports")
    print("=" * 50)
    
    import_success = test_module_imports()
    
    print("\nTesting Basic Functionality")
    print("=" * 30)
    
    functionality_success = test_basic_functionality()
    
    print("\n" + "=" * 50)
    if import_success and functionality_success:
        print("All tests passed! Security and compliance modules are working correctly.")
    else:
        print("Some tests failed. Please check the output above.")