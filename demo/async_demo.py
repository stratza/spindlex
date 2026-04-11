"""
SpindleX Async Demo - High Performance SSH & SFTP
This script demonstrates the asynchronous capabilities of SpindleX.
"""

import asyncio
import time

from spindlex import AsyncSSHClient

# --- CONFIGURATION ---
SSH_HOST = "my.server.com"
SSH_USER = "user"
SSH_PASS = "my-password"

SSH_KEY = None  # Path to private key file if needed
# ---------------------


async def run_demo():
    print("=" * 50)
    print(f"⚡ SpindleX Async Demo: {SSH_HOST}")
    print("=" * 50)

    client = AsyncSSHClient()

    try:
        print(f"🔗 Connecting to {SSH_USER}@{SSH_HOST} asynchronously...")
        await client.connect(
            hostname=SSH_HOST, username=SSH_USER, password=SSH_PASS, pkey=SSH_KEY
        )
        print("✅ Async Connection established!")

        # Parallel command execution
        print("\n🚀 Executing multiple commands in parallel...")
        commands = [
            "echo 'Parallel Task 1'",
            "echo 'Parallel Task 2'",
            "echo 'Parallel Task 3'",
            "sleep 1 && echo 'Finished'",
        ]

        tasks = [client.exec_command(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks)

        for i, (_stdin, stdout, _stderr) in enumerate(results):
            output = await stdout.read()
            print(f"📊 Task {i + 1} output: {output.decode().strip()}")

        # Async SFTP
        print("\n📁 Starting Async SFTP operations...")
        async with await client.open_sftp() as sftp:
            files = await sftp.listdir(".")
            print(f"📂 Found {len(files)} files in remote directory.")

            # Async metadata get
            stat = await sftp.stat(".")
            print(f"📝 Remote directory permissions: {oct(stat.st_mode)}")

    except Exception as e:
        print(f"❌ Async error: {e}")
    finally:
        await client.close()
        print("\n👋 Async Client closed.")


if __name__ == "__main__":
    start_time = time.time()
    asyncio.run(run_demo())
    print(f"\n✨ Total execution time: {time.time() - start_time:.2f} seconds")
