"""
SpindleX SFTP Demo - File Operations
This script demonstrates basic SFTP operations like listing files, uploading, and downloading.
"""

import os
import time

from spindlex import SSHClient

# --- CONFIGURATION ---
SSH_HOST = "my.server.com"
SSH_USER = "user"
SSH_PASS = "my-password"

SSH_KEY  = None        # Path to private key file if needed
# ---------------------

def main():
    print("="*50)
    print(f"📁 SpindleX SFTP Demo: {SSH_HOST}")
    print("="*50)
    
    client = SSHClient()
    
    try:
        print(f"🔗 Connecting to {SSH_USER}@{SSH_HOST}...")
        client.connect(
            hostname=SSH_HOST, 
            username=SSH_USER, 
            password=SSH_PASS, 
            key_filename=SSH_KEY
        )
        print("✅ Connected. Opening SFTP...")
        
        sftp = client.open_sftp()
        
        # 1. List directory
        print("\n📂 Listing current directory:")
        files = sftp.listdir(".")
        for f in files[:10]: # Limit for demo
            print(f" - {f}")
            
        # 2. Upload a file
        temp_file = "demo_upload.txt"
        with open(temp_file, "w") as f:
            f.write("This is a test file for SpindleX SFTP demo.\n" * 10)
            
        print(f"\n📤 Uploading {temp_file}...")
        sftp.put(temp_file, f"remote_{temp_file}")
        print("✅ Upload complete.")
        
        # 3. Download the file back
        print(f"\n📥 Downloading remote_{temp_file}...")
        sftp.get(f"remote_{temp_file}", f"downloaded_{temp_file}")
        print("✅ Download complete.")
        
        # 4. Clean up
        print("\n🧹 Cleaning up...")
        sftp.remove(f"remote_{temp_file}")
        if os.path.exists(temp_file): os.remove(temp_file)
        if os.path.exists(f"downloaded_{temp_file}"): os.remove(f"downloaded_{temp_file}")
        
    except Exception as e:
        print(f"❌ SFTP Error: {e}")
    finally:
        client.close()
        print("\n👋 SFTP Session closed.")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"\n✨ Total execution time: {time.time() - start_time:.2f} seconds")
