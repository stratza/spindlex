#!/usr/bin/env python3
"""
Basic SpindleX Usage Examples

This module demonstrates fundamental SSH operations using SpindleX.
"""

import sys
from pathlib import Path

from spindlex import SSHClient, AutoAddPolicy, RejectPolicy
from spindlex.crypto.pkey import PKey, load_key_from_file
from spindlex.exceptions import AuthenticationException, SSHException


def basic_connection_example():
    """Demonstrate basic SSH connection and command execution."""
    print("=== Basic Connection Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        # Connect to server
        client.connect(
            hostname='example.com',
            username='demo',
            password='password',
            timeout=10
        )
        
        print("Connected successfully!")
        
        # Execute a simple command
        stdin, stdout, stderr = client.exec_command('uname -a')
        
        # Read and display output
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        exit_code = stdout._channel.get_exit_status()
        
        print(f"Command output: {output}")
        if error:
            print(f"Command error: {error}")
        print(f"Exit code: {exit_code}")
        
    except AuthenticationException:
        print("Authentication failed - check your credentials")
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()
        print("Connection closed")


def key_based_authentication_example():
    """Demonstrate SSH key-based authentication."""
    print("\n=== Key-Based Authentication Example ===")
    
    # Generate a new key pair for demonstration
    private_key = PKey.generate("ed25519")
    
    # In practice, you would load an existing key:
    # private_key = load_key_from_file('/path/to/private_key')
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            pkey=private_key
        )
        
        print("Connected with SSH key!")
        
        # Execute command
        stdin, stdout, stderr = client.exec_command('whoami')
        username = stdout.read().decode('utf-8').strip()
        print(f"Logged in as: {username}")
        
    except AuthenticationException:
        print("Key authentication failed")
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def multiple_commands_example():
    """Demonstrate executing multiple commands on the same connection."""
    print("\n=== Multiple Commands Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        commands = [
            'date',
            'pwd',
            'ls -la',
            'df -h'
        ]
        
        for cmd in commands:
            print(f"\nExecuting: {cmd}")
            stdin, stdout, stderr = client.exec_command(cmd)
            
            output = stdout.read().decode('utf-8').strip()
            print(f"Output: {output}")
            
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def interactive_shell_example():
    """Demonstrate using an interactive shell."""
    print("\n=== Interactive Shell Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        # Start interactive shell
        shell = client.invoke_shell()
        
        # Send commands
        commands = ['ls\n', 'pwd\n', 'exit\n']
        
        for cmd in commands:
            shell.send(cmd)
            
            # Wait for output
            import time
            time.sleep(1)
            
            # Read available output
            if shell.recv_ready():
                output = shell.recv(1024).decode('utf-8')
                print(f"Shell output: {output}")
        
        shell.close()
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def context_manager_example():
    """Demonstrate using SSH client as a context manager."""
    print("\n=== Context Manager Example ===")
    
    try:
        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(
                hostname='example.com',
                username='demo',
                password='password'
            )
            
            print("Connected using context manager")
            
            stdin, stdout, stderr = client.exec_command('echo "Hello from context manager"')
            output = stdout.read().decode('utf-8').strip()
            print(f"Output: {output}")
            
        print("Connection automatically closed")
        
    except SSHException as e:
        print(f"SSH error: {e}")


def error_handling_example():
    """Demonstrate proper error handling."""
    print("\n=== Error Handling Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(RejectPolicy())  # Strict host key checking
    
    try:
        # This will likely fail due to strict host key policy
        client.connect(
            hostname='unknown-host.example.com',
            username='demo',
            password='wrongpassword',
            timeout=5
        )
        
    except AuthenticationException:
        print("Authentication failed - credentials are incorrect")
    except SSHException as e:
        print(f"SSH connection failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        client.close()


def connection_info_example():
    """Demonstrate getting connection information."""
    print("\n=== Connection Information Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        # Get transport information
        transport = client.get_transport()
        
        print(f"Connected: {transport.active}")
        print(f"Server version: {transport._server_version}")
        print(f"Client version: {transport._client_version}")
        
        # Get security information
        print(f"Cipher: {transport._cipher_c2s}")
        print(f"MAC: {transport._mac_c2s}")
        
        # Get host key information
        host_key = transport.get_server_host_key()
        print(f"Host key type: {host_key.get_name()}")
        print(f"Host key fingerprint: {host_key.get_fingerprint()}")
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def main():
    """Run all examples."""
    print("SpindleX Basic Usage Examples")
    print("=" * 40)
    
    examples = [
        basic_connection_example,
        key_based_authentication_example,
        multiple_commands_example,
        interactive_shell_example,
        context_manager_example,
        error_handling_example,
        connection_info_example,
    ]
    
    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"Example failed: {e}")
        print()  # Add spacing between examples


if __name__ == '__main__':
    main()