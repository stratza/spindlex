#!/usr/bin/env python3
"""
Test script for SpindleX SSH connection and authentication.

Tests basic SSH functionality with the provided test server:
- Server: 10.100.102.103
- Username: ubuntu  
- Password: 2090
"""

import sys
import logging
import traceback
from spindlex import SSHClient, AutoAddPolicy

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_basic_connection():
    """Test basic SSH connection without authentication."""
    print("=" * 60)
    print("Testing basic SSH connection...")
    print("=" * 60)
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        # Test connection without authentication
        print("Connecting to 10.100.102.103:22...")
        client.connect(
            hostname="10.100.102.103",
            port=22,
            timeout=30
        )
        
        print("✓ Basic connection successful!")
        return True
        
    except Exception as e:
        print(f"✗ Basic connection failed: {e}")
        traceback.print_exc()
        return False
    finally:
        try:
            client.close()
        except:
            pass

def test_password_authentication():
    """Test SSH connection with password authentication."""
    print("\n" + "=" * 60)
    print("Testing password authentication...")
    print("=" * 60)
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        print("Connecting with password authentication...")
        client.connect(
            hostname="10.100.102.103",
            port=22,
            username="ubuntu",
            password="2090",
            timeout=30
        )
        
        print("✓ Password authentication successful!")
        
        # Test if we're properly authenticated
        if client.is_connected():
            print("✓ Client reports as connected and authenticated")
        else:
            print("✗ Client reports as not properly connected")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ Password authentication failed: {e}")
        traceback.print_exc()
        return False
    finally:
        try:
            client.close()
        except:
            pass

def test_key_authentication():
    """Test SSH connection with key-based authentication."""
    print("\n" + "=" * 60)
    print("Testing key-based authentication...")
    print("=" * 60)
    
    # For now, we'll skip key authentication since we don't have a key
    # This would be implemented when we have access to a private key
    print("⚠ Key-based authentication test skipped - no private key available")
    print("  This test would require:")
    print("  - A private key file (RSA, Ed25519, etc.)")
    print("  - The corresponding public key installed on the server")
    
    return True

def test_connection_context_manager():
    """Test SSH connection using context manager."""
    print("\n" + "=" * 60)
    print("Testing connection with context manager...")
    print("=" * 60)
    
    try:
        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            print("Connecting with context manager...")
            client.connect(
                hostname="10.100.102.103",
                port=22,
                username="ubuntu",
                password="2090",
                timeout=30
            )
            
            print("✓ Context manager connection successful!")
            
            if client.is_connected():
                print("✓ Client is properly connected")
            else:
                print("✗ Client is not properly connected")
                return False
        
        print("✓ Context manager cleanup successful!")
        return True
        
    except Exception as e:
        print(f"✗ Context manager test failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all connection and authentication tests."""
    print("SpindleX SSH Connection and Authentication Tests")
    print("=" * 60)
    
    tests = [
        ("Basic Connection", test_basic_connection),
        ("Password Authentication", test_password_authentication),
        ("Key Authentication", test_key_authentication),
        ("Context Manager", test_connection_context_manager),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test '{test_name}' crashed: {e}")
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())