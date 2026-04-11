#!/usr/bin/env python3
"""
Example: Backing up Proxmox configuration files recursively.
This script demonstrates using SFTP for downloading configuration directories.
"""

import os

from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy


def download_recursive(sftp, remote_path, local_path):
    """
    Recursively downloads a directory from a remote server.
    """
    if not os.path.exists(local_path):
        os.makedirs(local_path)

    for item in sftp.listdir_attr(remote_path):
        remote_item = os.path.join(remote_path, item.filename).replace("\\", "/")
        local_item = os.path.join(local_path, item.filename)

        if item.st_mode & 0o40000:  # Directory
            download_recursive(sftp, remote_item, local_item)
        else:  # File
            print(f"Downloading: {remote_item}")
            sftp.get(remote_item, local_item)


def main():
    hostname = "proxmox.local"
    username = "root"
    password = "password"
    remote_config_dir = "/etc/pve"
    local_backup_dir = "./backups/proxmox"

    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(hostname, username=username, password=password)

        with client.open_sftp() as sftp:
            download_recursive(sftp, remote_config_dir, local_backup_dir)


if __name__ == "__main__":
    main()
