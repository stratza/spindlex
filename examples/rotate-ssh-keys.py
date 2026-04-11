#!/usr/bin/env python3
"""
Example: Rotating SSH keys across multiple servers.
This script demonstrates how to automate key rotation and test connectivity.
"""
import asyncio
import os
from spindlex import AsyncSSHClient
from spindlex.crypto.pkey import load_key_from_file

async def rotate_key(hostname, old_key, new_public_key):
    """
    Rotates the SSH key on a target server.
    """
    try:
        async with AsyncSSHClient() as client:
            # Connect using old key
            await client.connect(hostname, username='admin', pkey=old_key)
            
            # Append new key to authorized_keys
            cmd = f'echo "{new_public_key}" >> ~/.ssh/authorized_keys'
            await client.exec_command(cmd)
            
            # Verify new key works
            new_key = load_key_from_file('./new_id_ed25519')
            async with AsyncSSHClient() as new_client:
                await new_client.connect(hostname, username='admin', pkey=new_key)
                print(f"[{hostname}] Rotation successful and verified!")
    except Exception as e:
        print(f"[{hostname}] Rotation failed: {e}")

async def main():
    servers = ['srv1', 'srv2', 'srv3']
    old_key = load_key_from_file('~/.ssh/id_ed25519')
    
    # Normally you'd generate a new key here
    # os.system('spindlex-keygen -t ed25519 -f ./new_id_ed25519')
    with open('./new_id_ed25519.pub', 'r') as f:
        new_public_key = f.read().strip()

    tasks = [rotate_key(s, old_key, new_public_key) for s in servers]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
