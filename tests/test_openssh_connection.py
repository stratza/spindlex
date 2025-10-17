#!/usr/bin/env python3
"""
Test connection using a known working SSH library (paramiko) for comparison.
"""

import sys

def test_paramiko_connection():
    """Test connection using paramiko to see if the server works."""
    try:
        import paramiko
        
        print("Testing connection with paramiko...")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            hostname="10.100.102.103",
            port=22,
            username="ubuntu",
            password="2090",
            timeout=30
        )
        
        print("✓ Paramiko connection successful!")
        
        # Test command execution
        stdin, stdout, stderr = client.exec_command("echo 'Hello from SSH'")
        output = stdout.read().decode().strip()
        print(f"✓ Command output: {output}")
        
        client.close()
        return True
        
    except ImportError:
        print("⚠ Paramiko not available - install with: pip install paramiko")
        return False
    except Exception as e:
        print(f"✗ Paramiko connection failed: {e}")
        return False

def main():
    """Test with paramiko to verify the server works."""
    print("Testing SSH server with known working client")
    print("=" * 60)
    
    result = test_paramiko_connection()
    
    if result:
        print("\n🎉 Server is working with paramiko!")
        print("The issue is likely in our SpindleX implementation.")
    else:
        print("\n❌ Could not test with paramiko.")
    
    return 0 if result else 1

if __name__ == "__main__":
    sys.exit(main())