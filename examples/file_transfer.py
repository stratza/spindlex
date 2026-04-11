#!/usr/bin/env python3
"""
SFTP File Transfer Examples

This module demonstrates file transfer operations using SpindleX's SFTP client.
"""

import os
import tempfile
from pathlib import Path

from spindlex import AutoAddPolicy, SSHClient
from spindlex.exceptions import SFTPError, SSHException


def basic_file_transfer_example():
    """Demonstrate basic file upload and download."""
    print("=== Basic File Transfer Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        # Open SFTP session
        sftp = client.open_sftp()
        
        # Create a temporary file to upload
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write("Hello, SFTP World!\nThis is a test file.")
            local_file = temp_file.name
        
        try:
            # Upload file
            remote_file = '/tmp/test_upload.txt'
            print(f"Uploading {local_file} to {remote_file}")
            sftp.put(local_file, remote_file)
            print("Upload completed")
            
            # Download file
            download_file = local_file + '.downloaded'
            print(f"Downloading {remote_file} to {download_file}")
            sftp.get(remote_file, download_file)
            print("Download completed")
            
            # Verify files are identical
            with open(local_file) as f1, open(download_file) as f2:
                if f1.read() == f2.read():
                    print("Files are identical - transfer successful!")
                else:
                    print("Files differ - transfer may have failed")
            
        finally:
            # Clean up temporary files
            os.unlink(local_file)
            if os.path.exists(download_file):
                os.unlink(download_file)
            
            sftp.close()
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def directory_operations_example():
    """Demonstrate directory operations."""
    print("\n=== Directory Operations Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        sftp = client.open_sftp()
        
        # List current directory
        print("Current directory contents:")
        files = sftp.listdir('.')
        for filename in files:
            print(f"  {filename}")
        
        # Create a directory
        test_dir = '/tmp/spindlex_test'
        try:
            sftp.mkdir(test_dir)
            print(f"Created directory: {test_dir}")
        except SFTPError:
            print(f"Directory {test_dir} already exists or creation failed")
        
        # List contents
        dir_contents = sftp.listdir(test_dir)
        print(f"Directory contents: {dir_contents}")
        
        # Create a file in the directory
        test_file = f"{test_dir}/test_file.txt"
        with sftp.open(test_file, 'w') as remote_file:
            remote_file.write("This is a test file created via SFTP")
        
        print(f"Created file: {test_file}")
        
        # List directory again
        dir_contents = sftp.listdir(test_dir)
        print(f"Directory contents after file creation: {dir_contents}")
        
        # Clean up
        sftp.remove(test_file)
        sftp.rmdir(test_dir)
        print("Cleaned up test directory and file")
        
        sftp.close()
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def file_attributes_example():
    """Demonstrate file attribute operations."""
    print("\n=== File Attributes Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        sftp = client.open_sftp()
        
        # Create a test file
        test_file = '/tmp/attr_test.txt'
        with sftp.open(test_file, 'w') as f:
            f.write("Test file for attribute operations")
        
        # Get file attributes
        attrs = sftp.stat(test_file)
        print(f"File: {test_file}")
        print(f"Size: {attrs.st_size} bytes")
        print(f"Mode: {oct(attrs.st_mode)}")
        print(f"Modified: {attrs.st_mtime}")
        
        # Change file permissions
        new_mode = 0o644
        sftp.chmod(test_file, new_mode)
        print(f"Changed permissions to {oct(new_mode)}")
        
        # Verify permission change
        attrs = sftp.stat(test_file)
        print(f"New mode: {oct(attrs.st_mode)}")
        
        # Clean up
        sftp.remove(test_file)
        
        sftp.close()
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def bulk_transfer_example():
    """Demonstrate bulk file transfer with progress tracking."""
    print("\n=== Bulk Transfer Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        sftp = client.open_sftp()
        
        # Create multiple test files
        temp_dir = Path(tempfile.mkdtemp())
        test_files = []
        
        for i in range(5):
            test_file = temp_dir / f"test_file_{i}.txt"
            with open(test_file, 'w') as f:
                f.write(f"This is test file number {i}\n" * 100)
            test_files.append(test_file)
        
        # Upload files with progress tracking
        remote_dir = '/tmp/bulk_test'
        try:
            sftp.mkdir(remote_dir)
        except SFTPError:
            pass  # Directory might already exist
        
        print(f"Uploading {len(test_files)} files...")
        for i, local_file in enumerate(test_files):
            remote_file = f"{remote_dir}/{local_file.name}"
            
            print(f"Uploading {i+1}/{len(test_files)}: {local_file.name}")
            sftp.put(str(local_file), remote_file)
        
        print("Upload completed!")
        
        # List uploaded files
        uploaded_files = sftp.listdir(remote_dir)
        print(f"Uploaded files: {uploaded_files}")
        
        # Download files to a different directory
        download_dir = temp_dir / 'downloads'
        download_dir.mkdir()
        
        print(f"Downloading {len(uploaded_files)} files...")
        for i, filename in enumerate(uploaded_files):
            remote_file = f"{remote_dir}/{filename}"
            local_file = download_dir / filename
            
            print(f"Downloading {i+1}/{len(uploaded_files)}: {filename}")
            sftp.get(remote_file, str(local_file))
        
        print("Download completed!")
        
        # Clean up remote files
        for filename in uploaded_files:
            sftp.remove(f"{remote_dir}/{filename}")
        sftp.rmdir(remote_dir)
        
        # Clean up local files
        import shutil
        shutil.rmtree(temp_dir)
        
        sftp.close()
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def streaming_transfer_example():
    """Demonstrate streaming file transfer for large files."""
    print("\n=== Streaming Transfer Example ===")
    
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(
            hostname='example.com',
            username='demo',
            password='password'
        )
        
        sftp = client.open_sftp()
        
        # Create a large test file
        large_file = '/tmp/large_test_file.dat'
        chunk_size = 8192
        total_size = 1024 * 1024  # 1MB
        
        print(f"Creating large file ({total_size} bytes)...")
        with sftp.open(large_file, 'wb') as remote_file:
            bytes_written = 0
            while bytes_written < total_size:
                chunk = b'x' * min(chunk_size, total_size - bytes_written)
                remote_file.write(chunk)
                bytes_written += len(chunk)
                
                # Show progress
                progress = (bytes_written / total_size) * 100
                print(f"\rProgress: {progress:.1f}%", end='', flush=True)
        
        print("\nFile created!")
        
        # Stream download with progress
        local_file = '/tmp/downloaded_large_file.dat'
        print("Downloading with streaming...")
        
        with sftp.open(large_file, 'rb') as remote_file, \
             open(local_file, 'wb') as local_file_handle:
            
            bytes_downloaded = 0
            while True:
                chunk = remote_file.read(chunk_size)
                if not chunk:
                    break
                
                local_file_handle.write(chunk)
                bytes_downloaded += len(chunk)
                
                progress = (bytes_downloaded / total_size) * 100
                print(f"\rDownload progress: {progress:.1f}%", end='', flush=True)
        
        print("\nDownload completed!")
        
        # Verify file sizes
        remote_attrs = sftp.stat(large_file)
        local_size = os.path.getsize(local_file)
        
        print(f"Remote file size: {remote_attrs.st_size}")
        print(f"Local file size: {local_size}")
        
        if remote_attrs.st_size == local_size:
            print("File sizes match - transfer successful!")
        else:
            print("File sizes don't match - transfer may have failed")
        
        # Clean up
        sftp.remove(large_file)
        os.unlink(local_file)
        
        sftp.close()
        
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def sftp_context_manager_example():
    """Demonstrate using SFTP with context managers."""
    print("\n=== SFTP Context Manager Example ===")
    
    try:
        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(
                hostname='example.com',
                username='demo',
                password='password'
            )
            
            with client.open_sftp() as sftp:
                # All SFTP operations here
                files = sftp.listdir('.')
                print(f"Directory listing: {files[:5]}...")  # Show first 5 files
                
                # Create and remove a test file
                test_file = '/tmp/context_test.txt'
                with sftp.open(test_file, 'w') as f:
                    f.write("Test file created with context manager")
                
                # Verify file exists
                attrs = sftp.stat(test_file)
                print(f"Created file size: {attrs.st_size} bytes")
                
                # Clean up
                sftp.remove(test_file)
                print("Test file removed")
            
            print("SFTP session automatically closed")
        
        print("SSH connection automatically closed")
        
    except SSHException as e:
        print(f"SSH error: {e}")


def main():
    """Run all SFTP examples."""
    print("SpindleX SFTP Examples")
    print("=" * 30)
    
    examples = [
        basic_file_transfer_example,
        directory_operations_example,
        file_attributes_example,
        bulk_transfer_example,
        streaming_transfer_example,
        sftp_context_manager_example,
    ]
    
    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"Example failed: {e}")
        print()  # Add spacing between examples


if __name__ == '__main__':
    main()
