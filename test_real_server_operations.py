#!/usr/bin/env python3
"""
Test script for SpindleX command execution and SFTP operations.

Tests advanced SSH functionality with the provided test server:
- Server: 10.100.102.103
- Username: ubuntu  
- Password: 2090

This script implements task 10.2: Test command execution and SFTP operations
"""

import sys
import os
import tempfile
import logging
import traceback
import time
from pathlib import Path
from spindlex import SSHClient, AutoAddPolicy

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class RealServerTester:
    """Test class for real SSH server operations."""
    
    def __init__(self):
        self.hostname = "10.100.102.103"
        self.port = 22
        self.username = "ubuntu"
        self.password = "2090"
        self.timeout = 30
        
    def create_client(self):
        """Create and configure SSH client."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        return client
    
    def test_basic_command_execution(self):
        """Test basic command execution functionality."""
        print("=" * 60)
        print("Testing basic command execution...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            # Connect to server
            print("Connecting to server...")
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            print("✓ Connected successfully")
            
            # Test simple echo command
            print("\nTesting simple echo command...")
            stdin, stdout, stderr = client.exec_command("echo 'Hello from SpindleX'")
            
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            print(f"Command output: '{output}'")
            if error:
                print(f"Command error: '{error}'")
            
            if output == "Hello from SpindleX":
                print("✓ Simple echo command successful")
            else:
                print(f"✗ Expected 'Hello from SpindleX', got '{output}'")
                return False
            
            # Test command with special characters
            print("\nTesting command with special characters...")
            test_string = "Test with spaces & special chars: $HOME, $(whoami), `date`"
            stdin, stdout, stderr = client.exec_command(f"echo '{test_string}'")
            
            output = stdout.read().decode('utf-8').strip()
            print(f"Special chars output: '{output}'")
            
            if test_string in output:
                print("✓ Special characters command successful")
            else:
                print(f"✗ Special characters test failed")
                return False
            
            # Test multiline output command
            print("\nTesting multiline output command...")
            stdin, stdout, stderr = client.exec_command("echo -e 'Line 1\\nLine 2\\nLine 3'")
            
            output = stdout.read().decode('utf-8')
            lines = output.strip().split('\n')
            print(f"Multiline output ({len(lines)} lines):")
            for i, line in enumerate(lines, 1):
                print(f"  Line {i}: '{line}'")
            
            if len(lines) == 3 and "Line 1" in lines[0] and "Line 3" in lines[2]:
                print("✓ Multiline output command successful")
            else:
                print("✗ Multiline output test failed")
                return False
            
            return True
            
        except Exception as e:
            print(f"✗ Basic command execution failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                client.close()
            except:
                pass
    
    def test_system_commands(self):
        """Test various system commands."""
        print("\n" + "=" * 60)
        print("Testing system commands...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            # Test whoami command
            print("Testing whoami command...")
            stdin, stdout, stderr = client.exec_command("whoami")
            username = stdout.read().decode('utf-8').strip()
            print(f"Current user: '{username}'")
            
            if username == self.username:
                print("✓ whoami command successful")
            else:
                print(f"✗ Expected '{self.username}', got '{username}'")
                return False
            
            # Test pwd command
            print("\nTesting pwd command...")
            stdin, stdout, stderr = client.exec_command("pwd")
            current_dir = stdout.read().decode('utf-8').strip()
            print(f"Current directory: '{current_dir}'")
            
            if current_dir.startswith('/'):
                print("✓ pwd command successful")
            else:
                print(f"✗ Invalid directory path: '{current_dir}'")
                return False
            
            # Test ls command
            print("\nTesting ls command...")
            stdin, stdout, stderr = client.exec_command("ls -la")
            ls_output = stdout.read().decode('utf-8')
            print(f"Directory listing (first 200 chars): {ls_output[:200]}...")
            
            if "total" in ls_output and ("." in ls_output or ".." in ls_output):
                print("✓ ls command successful")
            else:
                print("✗ ls command failed")
                return False
            
            # Test date command
            print("\nTesting date command...")
            stdin, stdout, stderr = client.exec_command("date")
            date_output = stdout.read().decode('utf-8').strip()
            print(f"Server date: '{date_output}'")
            
            if len(date_output) > 10:  # Basic sanity check
                print("✓ date command successful")
            else:
                print("✗ date command failed")
                return False
            
            # Test uname command
            print("\nTesting uname command...")
            stdin, stdout, stderr = client.exec_command("uname -a")
            uname_output = stdout.read().decode('utf-8').strip()
            print(f"System info: '{uname_output}'")
            
            if "Linux" in uname_output or "linux" in uname_output.lower():
                print("✓ uname command successful")
            else:
                print("✗ uname command failed")
                return False
            
            return True
            
        except Exception as e:
            print(f"✗ System commands test failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                client.close()
            except:
                pass
    
    def test_command_with_stderr(self):
        """Test commands that produce stderr output."""
        print("\n" + "=" * 60)
        print("Testing commands with stderr output...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            # Test command that writes to stderr
            print("Testing command with stderr output...")
            stdin, stdout, stderr = client.exec_command("echo 'stdout message'; echo 'stderr message' >&2")
            
            stdout_data = stdout.read().decode('utf-8').strip()
            stderr_data = stderr.read().decode('utf-8').strip()
            
            print(f"STDOUT: '{stdout_data}'")
            print(f"STDERR: '{stderr_data}'")
            
            if "stdout message" in stdout_data and "stderr message" in stderr_data:
                print("✓ stderr command successful")
            else:
                print("✗ stderr command failed")
                return False
            
            # Test command that fails (non-zero exit code)
            print("\nTesting command with non-zero exit code...")
            stdin, stdout, stderr = client.exec_command("ls /nonexistent_directory_12345")
            
            stdout_data = stdout.read().decode('utf-8').strip()
            stderr_data = stderr.read().decode('utf-8').strip()
            
            print(f"STDOUT: '{stdout_data}'")
            print(f"STDERR: '{stderr_data}'")
            
            # Should have error message in stderr
            if "No such file" in stderr_data or "cannot access" in stderr_data:
                print("✓ Error command produced expected stderr")
            else:
                print("✗ Error command didn't produce expected stderr")
                return False
            
            return True
            
        except Exception as e:
            print(f"✗ stderr commands test failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                client.close()
            except:
                pass
    
    def test_sftp_basic_operations(self):
        """Test basic SFTP operations."""
        print("\n" + "=" * 60)
        print("Testing basic SFTP operations...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            # Open SFTP session
            print("Opening SFTP session...")
            sftp = client.open_sftp()
            print("✓ SFTP session opened")
            
            # Test directory listing
            print("\nTesting directory listing...")
            files = sftp.listdir('.')
            print(f"Found {len(files)} items in current directory:")
            for i, filename in enumerate(files[:10]):  # Show first 10 files
                print(f"  {i+1}. {filename}")
            if len(files) > 10:
                print(f"  ... and {len(files) - 10} more items")
            
            if len(files) > 0:
                print("✓ Directory listing successful")
            else:
                print("✗ Directory listing returned no files")
                return False
            
            # Test getting file attributes
            print("\nTesting file attributes...")
            if files:
                test_file = files[0]
                try:
                    attrs = sftp.stat(test_file)
                    print(f"File '{test_file}' attributes:")
                    print(f"  Size: {attrs.st_size} bytes")
                    if hasattr(attrs, 'st_mode'):
                        print(f"  Mode: {oct(attrs.st_mode)}")
                    if hasattr(attrs, 'st_mtime'):
                        print(f"  Modified: {attrs.st_mtime}")
                    print("✓ File attributes retrieved successfully")
                except Exception as e:
                    print(f"⚠ Could not get attributes for '{test_file}': {e}")
            
            sftp.close()
            return True
            
        except Exception as e:
            print(f"✗ Basic SFTP operations failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                client.close()
            except:
                pass
    
    def test_sftp_file_transfer(self):
        """Test SFTP file upload and download operations."""
        print("\n" + "=" * 60)
        print("Testing SFTP file transfer operations...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            sftp = client.open_sftp()
            
            # Create a temporary test file
            test_content = f"SpindleX SFTP Test File\nCreated at: {time.ctime()}\nTest data: {'X' * 100}\n"
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(test_content)
                local_test_file = temp_file.name
            
            try:
                print(f"Created local test file: {local_test_file}")
                print(f"Test file size: {len(test_content)} bytes")
                
                # Upload file
                remote_test_file = f"spindlex_test_{int(time.time())}.txt"
                print(f"\nUploading file to: {remote_test_file}")
                
                start_time = time.time()
                sftp.put(local_test_file, remote_test_file)
                upload_time = time.time() - start_time
                
                print(f"✓ File uploaded successfully in {upload_time:.2f} seconds")
                
                # Verify file exists on server
                print("\nVerifying uploaded file...")
                remote_attrs = sftp.stat(remote_test_file)
                print(f"Remote file size: {remote_attrs.st_size} bytes")
                
                if remote_attrs.st_size == len(test_content):
                    print("✓ File size matches")
                else:
                    print(f"✗ File size mismatch: expected {len(test_content)}, got {remote_attrs.st_size}")
                    return False
                
                # Download file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as download_file:
                    download_path = download_file.name
                
                print(f"\nDownloading file to: {download_path}")
                
                start_time = time.time()
                sftp.get(remote_test_file, download_path)
                download_time = time.time() - start_time
                
                print(f"✓ File downloaded successfully in {download_time:.2f} seconds")
                
                # Verify downloaded content
                print("\nVerifying downloaded content...")
                with open(download_path, 'r') as f:
                    downloaded_content = f.read()
                
                if downloaded_content == test_content:
                    print("✓ Downloaded content matches original")
                else:
                    print("✗ Downloaded content doesn't match original")
                    print(f"Original length: {len(test_content)}")
                    print(f"Downloaded length: {len(downloaded_content)}")
                    return False
                
                # Clean up remote file
                print(f"\nCleaning up remote file: {remote_test_file}")
                sftp.remove(remote_test_file)
                print("✓ Remote file cleaned up")
                
                # Clean up local files
                os.unlink(local_test_file)
                os.unlink(download_path)
                
                return True
                
            finally:
                # Ensure cleanup
                try:
                    sftp.remove(remote_test_file)
                except:
                    pass
                try:
                    os.unlink(local_test_file)
                except:
                    pass
                try:
                    os.unlink(download_path)
                except:
                    pass
            
        except Exception as e:
            print(f"✗ SFTP file transfer failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                sftp.close()
            except:
                pass
            try:
                client.close()
            except:
                pass
    
    def test_sftp_directory_operations(self):
        """Test SFTP directory operations."""
        print("\n" + "=" * 60)
        print("Testing SFTP directory operations...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            sftp = client.open_sftp()
            
            # Create test directory
            test_dir = f"spindlex_test_dir_{int(time.time())}"
            print(f"Creating test directory: {test_dir}")
            
            sftp.mkdir(test_dir)
            print("✓ Directory created successfully")
            
            # Verify directory exists
            print("\nVerifying directory exists...")
            files = sftp.listdir('.')
            if test_dir in files:
                print("✓ Directory appears in listing")
            else:
                print("✗ Directory not found in listing")
                return False
            
            # Create subdirectory
            subdir = f"{test_dir}/subdir"
            print(f"\nCreating subdirectory: {subdir}")
            sftp.mkdir(subdir)
            print("✓ Subdirectory created successfully")
            
            # List contents of test directory
            print(f"\nListing contents of {test_dir}...")
            subdir_contents = sftp.listdir(test_dir)
            print(f"Found {len(subdir_contents)} items:")
            for item in subdir_contents:
                print(f"  - {item}")
            
            if "subdir" in subdir_contents:
                print("✓ Subdirectory appears in parent directory listing")
            else:
                print("✗ Subdirectory not found in parent directory")
                return False
            
            # Create a file in the subdirectory
            test_file_content = "Test file in subdirectory"
            test_file_path = f"{subdir}/test_file.txt"
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(test_file_content)
                local_temp_file = temp_file.name
            
            try:
                print(f"\nUploading file to subdirectory: {test_file_path}")
                sftp.put(local_temp_file, test_file_path)
                print("✓ File uploaded to subdirectory")
                
                # List subdirectory contents
                print(f"\nListing contents of {subdir}...")
                subdir_files = sftp.listdir(subdir)
                print(f"Found {len(subdir_files)} items:")
                for item in subdir_files:
                    print(f"  - {item}")
                
                if "test_file.txt" in subdir_files:
                    print("✓ File appears in subdirectory listing")
                else:
                    print("✗ File not found in subdirectory")
                    return False
                
                # Clean up: remove file, then directories
                print(f"\nCleaning up...")
                sftp.remove(test_file_path)
                print("✓ File removed")
                
                sftp.rmdir(subdir)
                print("✓ Subdirectory removed")
                
                sftp.rmdir(test_dir)
                print("✓ Test directory removed")
                
                return True
                
            finally:
                try:
                    os.unlink(local_temp_file)
                except:
                    pass
            
        except Exception as e:
            print(f"✗ SFTP directory operations failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                # Cleanup in case of failure
                try:
                    sftp.remove(f"{test_dir}/subdir/test_file.txt")
                except:
                    pass
                try:
                    sftp.rmdir(f"{test_dir}/subdir")
                except:
                    pass
                try:
                    sftp.rmdir(test_dir)
                except:
                    pass
                sftp.close()
            except:
                pass
            try:
                client.close()
            except:
                pass
    
    def test_large_file_transfer(self):
        """Test SFTP with larger file transfers."""
        print("\n" + "=" * 60)
        print("Testing large file transfer...")
        print("=" * 60)
        
        client = self.create_client()
        
        try:
            client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
            
            sftp = client.open_sftp()
            
            # Create a larger test file (100KB)
            file_size = 100 * 1024  # 100KB
            test_content = "SpindleX Large File Test\n" + ("X" * (file_size - 25))
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
                temp_file.write(test_content)
                local_test_file = temp_file.name
            
            try:
                print(f"Created large test file: {len(test_content)} bytes ({len(test_content)/1024:.1f} KB)")
                
                # Upload large file
                remote_test_file = f"spindlex_large_test_{int(time.time())}.txt"
                print(f"\nUploading large file to: {remote_test_file}")
                
                start_time = time.time()
                sftp.put(local_test_file, remote_test_file)
                upload_time = time.time() - start_time
                upload_speed = len(test_content) / upload_time / 1024  # KB/s
                
                print(f"✓ Large file uploaded in {upload_time:.2f} seconds ({upload_speed:.1f} KB/s)")
                
                # Verify file size
                remote_attrs = sftp.stat(remote_test_file)
                if remote_attrs.st_size == len(test_content):
                    print("✓ Large file size verified")
                else:
                    print(f"✗ Large file size mismatch: expected {len(test_content)}, got {remote_attrs.st_size}")
                    return False
                
                # Download large file
                with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as download_file:
                    download_path = download_file.name
                
                print(f"\nDownloading large file to: {download_path}")
                
                start_time = time.time()
                sftp.get(remote_test_file, download_path)
                download_time = time.time() - start_time
                download_speed = len(test_content) / download_time / 1024  # KB/s
                
                print(f"✓ Large file downloaded in {download_time:.2f} seconds ({download_speed:.1f} KB/s)")
                
                # Verify content integrity
                with open(download_path, 'r') as f:
                    downloaded_content = f.read()
                
                if len(downloaded_content) == len(test_content):
                    print("✓ Large file content length verified")
                    
                    # Check first and last parts of content
                    if (downloaded_content[:50] == test_content[:50] and 
                        downloaded_content[-50:] == test_content[-50:]):
                        print("✓ Large file content integrity verified")
                    else:
                        print("✗ Large file content integrity check failed")
                        return False
                else:
                    print(f"✗ Large file content length mismatch")
                    return False
                
                # Clean up
                sftp.remove(remote_test_file)
                os.unlink(download_path)
                
                return True
                
            finally:
                try:
                    os.unlink(local_test_file)
                except:
                    pass
                try:
                    sftp.remove(remote_test_file)
                except:
                    pass
            
        except Exception as e:
            print(f"✗ Large file transfer failed: {e}")
            traceback.print_exc()
            return False
        finally:
            try:
                sftp.close()
            except:
                pass
            try:
                client.close()
            except:
                pass

def main():
    """Run all command execution and SFTP operation tests."""
    print("SpindleX Command Execution and SFTP Operations Tests")
    print("=" * 60)
    print(f"Target server: 10.100.102.103:22")
    print(f"Username: ubuntu")
    print("=" * 60)
    
    tester = RealServerTester()
    
    tests = [
        ("Basic Command Execution", tester.test_basic_command_execution),
        ("System Commands", tester.test_system_commands),
        ("Commands with STDERR", tester.test_command_with_stderr),
        ("Basic SFTP Operations", tester.test_sftp_basic_operations),
        ("SFTP File Transfer", tester.test_sftp_file_transfer),
        ("SFTP Directory Operations", tester.test_sftp_directory_operations),
        ("Large File Transfer", tester.test_large_file_transfer),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} Starting: {test_name} {'='*20}")
        try:
            result = test_func()
            results.append((test_name, result))
            
            if result:
                print(f"✓ {test_name}: PASSED")
            else:
                print(f"✗ {test_name}: FAILED")
                
        except Exception as e:
            print(f"✗ Test '{test_name}' crashed: {e}")
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print final summary
    print("\n" + "=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name:<35} {status}")
        if result:
            passed += 1
    
    print("-" * 80)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! Command execution and SFTP operations are working correctly.")
        return 0
    else:
        print("❌ Some tests failed! Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())