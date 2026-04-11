# Problem-Based Cookbook

This cookbook provides practical solutions for real-world tasks using SpindleX. Each recipe is designed to solve a specific infrastructure problem.

## SFTP Operations

*   [**Recursive Uploads**](sftp_recipes.md#recursive-upload): How to upload an entire directory tree.
*   [**Large File Progress Tracking**](sftp_recipes.md#progress-callback): Adding progress bars to file transfers.
*   [**Pattern-Based File Deletion**](sftp_recipes.md#pattern-delete): Cleaning up remote directories based on wildcards.

## Automation Tasks

*   [**Sudo Command Execution**](automation.md#sudo-execution): How to handle interactive sudo prompts automatically.
*   [**Parallel Command Execution**](automation.md#parallel-commands): Running the same command on 100+ servers.
*   [**SSH ProxyJump (Bastion Hosts)**](automation.md#proxy-jump): Connecting to internal servers via a gateway.
*   [**Log Monitoring**](automation.md#log-tailing): Streaming remote logs in real-time.

## Custom Solutions

*   [**Key Rotation**](automation.md#key-rotation): Automating the rotation of SSH keys across your fleet.
*   [**Backing up Configs**](automation.md#backup-configs): Example script for backing up Proxmox or Cisco configurations.
