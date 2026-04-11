"""
SpindleX Ecosystem Setup Demo - "The Full Cycle"
This script demonstrates a complex real-world workflow:
1. Generate a brand new SSH Ed25519 key pair locally.
2. Connect to a remote server using traditional password authentication.
3. Use SFTP to push the new public key to authorize future logins.
4. Execute administrative tasks (sudo) using the password connection.
5. Disconnect and reconnect using ONLY the newly created SSH keys.
6. Verify successful passwordless authentication.
"""

import os
import sys
import time

# Fix for Windows console emoji support
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)


from spindlex import SSHClient
from spindlex.crypto.pkey import Ed25519Key
from spindlex.hostkeys.policy import AutoAddPolicy

# --- CONFIGURATION (Synced with other demos) ---
SSH_HOST = "my.server.com"
SSH_USER = "user"
SSH_PASS = "my-password"


# ---------------------------------------------

def cleanup_keys(private_path):
    """Remove local key files after demo."""
    public_path = f"{private_path}.pub"
    if os.path.exists(private_path): os.remove(private_path)
    if os.path.exists(public_path): os.remove(public_path)
    print("🧹 Local key files cleaned up.")

def main():
    total_start = time.time()
    private_key_file = "demo_ed25519"
    
    print("="*60)
    print("🏗️  SpindleX COMPLEX ECOSYSTEM SETUP DEMO")
    print("="*60)

    # STEP 1: Generate Keys Locally
    print("\n[STEP 1] 🔑 Generating new Ed25519 key pair...")
    key = Ed25519Key.generate()
    key.save_to_file(private_key_file)
    pub_key_str = key.get_openssh_string()
    print(f"✅ Key generated: {pub_key_str[:30]}...")



    # STEP 2: Connect via Password
    print(f"\n[STEP 2] 🔐 Connecting to {SSH_HOST} using PASSWORD...")
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    try:
        client.connect(hostname=SSH_HOST, username=SSH_USER, password=SSH_PASS)
        print("✅ Password authentication successful!")

        # STEP 3: Setup Authorized Keys via SFTP
        print("\n[STEP 3] 📂 Setting up SSH keys on remote server...")
        sftp = client.open_sftp()
        
        # Ensure .ssh directory exists and has correct permissions
        try:
            sftp.mkdir(".ssh", mode=0o700)
            print("📁 Created .ssh directory.")
        except Exception:
            # Explicitly fix permissions even if it exists
            client.exec_command("chmod 700 .ssh")
            print("ℹ️  Ensured .ssh directory has 700 permissions.")

        # Clean and append key to authorized_keys
        auth_file = ".ssh/authorized_keys"
        lines = []
        try:
            with sftp.open(auth_file, "rb") as f:
                content = f.read().decode()
                # Remove any existing demo keys to prevent corruption/duplicates
                lines = [line for line in content.splitlines() if "spindle-demo-key" not in line]
        except Exception:
            pass
        
        # Add the new key
        lines.append(f"{pub_key_str} spindle-demo-key")
        
        with sftp.open(auth_file, "w") as f:
            f.write("\n".join(lines) + "\n")
        print("✅ Public key cleanly written to authorized_keys.")


        
        # Ensure correct permissions
        client.exec_command(f"chmod 600 {auth_file}")
        sftp.close()

        # STEP 4: Perform Sudo Tasks
        print("\n[STEP 4] 🛠️  Performing administrative tasks (sudo)...")
        # Echoing the password directly into sudo -S is often more robust in automation
        cmd = f"echo '{SSH_PASS}' | sudo -S ls -la /root"
        print("🚀 Running: echo '********' | sudo -S ls -la /root")

        stdin, stdout, stderr = client.exec_command(cmd)
        
        # Set a short timeout so we don't hang if the server is slow
        stdout._channel.settimeout(10.0)
        
        try:
            # Read whatever comes back (stdout and stderr)
            output = stdout.read().decode().strip()
            errors = stderr.read().decode().strip()
            
            if output:
                print("📂 /root Directory Listing (Administrative Access):")
                for line in output.split('\n'):
                    print(f"   ┃ {line}")
            else:
                print("⚠️  No output received from sudo command.")

            if errors and "password" not in errors.lower():
                print(f"❌ Sudo Error Detail: {errors}")
        except Exception as e:
            print(f"ℹ️  Note: Sudo command finished or timed out. ({e})")

        
        print("\n⏳ Closing initial password-based session...")
        client.close()

        
        # STEP 5: Reconnect using KEY only
        print("\n[STEP 5] 🔑 Attempting RECONNECTION using the NEW KEYS...")
        time.sleep(2) # Brief pause for visual effect
        
        key_client = SSHClient()
        key_client.set_missing_host_key_policy(AutoAddPolicy())
        
        # Login using private key file, NO password
        key_client.connect(
            hostname=SSH_HOST, 
            username=SSH_USER, 
            key_filename=private_key_file
        )
        print("✅ KEY-BASED authentication successful! No password required.")



        # FINAL VERIFICATION
        print("\n[FINAL] 📋 Verifying system identity...")
        _, stdout, _ = key_client.exec_command("uname -a && uptime")
        print(f"🖥️  Server Response:\n{stdout.read().decode().strip()}")
        
        key_client.close()

    except Exception as e:
        print(f"❌ Error during ecosystem demo: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cleanup_keys(private_key_file)
        duration = time.time() - total_start
        print(f"\n✨ Total ecosystem setup completed in {duration:.2f} seconds.")
        print("="*60)

if __name__ == "__main__":
    main()
