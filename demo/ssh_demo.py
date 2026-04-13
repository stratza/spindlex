"""
SpindleX SSH Demo - Command Execution
This script demonstrates basic SSH connection and command execution using SpindleX.
"""

import os
import sys
import time

# Ensure local 'spindlex' module is used instead of any installed package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from spindlex import SSHClient

# --- CONFIGURATION ---
SSH_HOST = "my.server.com"
SSH_USER = "user"
SSH_PASS = "my-password"

SSH_KEY = None  # Path to private key file if needed
# ---------------------


def main():
    print("=" * 50)
    print(f"🚀 SpindleX SSH Demo: {SSH_HOST}")
    print("=" * 50)

    client = SSHClient()

    try:
        print(f"🔗 Connecting to {SSH_USER}@{SSH_HOST}...")
        client.connect(
            hostname=SSH_HOST,
            username=SSH_USER,
            password=SSH_PASS,
            key_filename=SSH_KEY,
            timeout=10,
        )
        print("✅ Connection established successfully!")

        commands = ["uname -a", "ls -la", "whoami", "df -h"]

        for cmd in commands:
            print(f"\n💻 Executing command: {cmd}")
            stdin, stdout, stderr = client.exec_command(cmd)

            output = stdout.read().decode().strip()
            if output:
                print(f"📤 Output:\n{output}")

            err = stderr.read().decode().strip()
            if err:
                print(f"❌ Error:\n{err}")

            time.sleep(1)  # For visual flow in recording

    except Exception as e:
        print(f"❌ Error during demo: {e}")
    finally:
        client.close()
        print("\n👋 Client closed.")


if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"\n✨ Total execution time: {time.time() - start_time:.2f} seconds")
