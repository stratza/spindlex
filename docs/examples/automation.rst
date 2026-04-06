Automation Examples
===================

This section provides examples for automating common tasks using SpindleX.

Server Management
-----------------

Basic Server Management Script::

    #!/usr/bin/env python3
    """
    Server management automation script.
    """
    
    from spindlex import SSHClient
    from spindlex.exceptions import SSHException
    import logging
    import sys
    from typing import List, Dict, Any
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    class ServerManager:
        def __init__(self, servers: List[Dict[str, Any]]):
            self.servers = servers
            self.results = {}
        
        def execute_on_all(self, command: str) -> Dict[str, Any]:
            """Execute command on all servers."""
            results = {}
            
            for server in self.servers:
                hostname = server['hostname']
                try:
                    result = self.execute_command(server, command)
                    results[hostname] = {
                        'success': True,
                        'output': result['stdout'],
                        'error': result['stderr'],
                        'exit_code': result['exit_code']
                    }
                    logger.info(f"Command executed successfully on {hostname}")
                    
                except SSHException as e:
                    results[hostname] = {
                        'success': False,
                        'error': str(e)
                    }
                    logger.error(f"Command failed on {hostname}: {e}")
            
            return results
        
        def execute_command(self, server: Dict[str, Any], command: str) -> Dict[str, Any]:
            """Execute command on a single server."""
            client = SSHClient()
            
            try:
                # Connect to server
                client.connect(
                    hostname=server['hostname'],
                    username=server['username'],
                    password=server.get('password'),
                    pkey=server.get('private_key'),
                    timeout=30
                )
                
                # Execute command
                stdin, stdout, stderr = client.exec_command(command)
                
                return {
                    'stdout': stdout.read().decode('utf-8'),
                    'stderr': stderr.read().decode('utf-8'),
                    'exit_code': stdout.channel.recv_exit_status()
                }
                
            finally:
                client.close()
        
        def check_system_status(self) -> Dict[str, Any]:
            """Check system status on all servers."""
            commands = {
                'uptime': 'uptime',
                'disk_usage': 'df -h',
                'memory': 'free -h',
                'load': 'cat /proc/loadavg',
                'processes': 'ps aux --sort=-%cpu | head -10'
            }
            
            status = {}
            for server in self.servers:
                hostname = server['hostname']
                status[hostname] = {}
                
                for check_name, command in commands.items():
                    try:
                        result = self.execute_command(server, command)
                        status[hostname][check_name] = result['stdout'].strip()
                    except Exception as e:
                        status[hostname][check_name] = f"Error: {e}"
            
            return status
        
        def deploy_files(self, local_files: List[str], remote_path: str) -> Dict[str, bool]:
            """Deploy files to all servers."""
            results = {}
            
            for server in self.servers:
                hostname = server['hostname']
                client = SSHClient()
                
                try:
                    client.connect(
                        hostname=hostname,
                        username=server['username'],
                        password=server.get('password'),
                        pkey=server.get('private_key')
                    )
                    
                    sftp = client.open_sftp()
                    
                    for local_file in local_files:
                        remote_file = f"{remote_path}/{os.path.basename(local_file)}"
                        sftp.put(local_file, remote_file)
                        logger.info(f"Deployed {local_file} to {hostname}:{remote_file}")
                    
                    results[hostname] = True
                    
                except Exception as e:
                    results[hostname] = False
                    logger.error(f"Deployment failed on {hostname}: {e}")
                
                finally:
                    client.close()
            
            return results
    
    # Example usage
    if __name__ == "__main__":
        servers = [
            {
                'hostname': 'web1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            },
            {
                'hostname': 'web2.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            },
            {
                'hostname': 'db1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            }
        ]
        
        manager = ServerManager(servers)
        
        # Check system status
        print("Checking system status...")
        status = manager.check_system_status()
        for hostname, checks in status.items():
            print(f"\n{hostname}:")
            for check, result in checks.items():
                print(f"  {check}: {result}")
        
        # Execute command on all servers
        print("\nUpdating packages...")
        results = manager.execute_on_all("sudo apt update && sudo apt upgrade -y")
        for hostname, result in results.items():
            if result['success']:
                print(f"{hostname}: Update completed")
            else:
                print(f"{hostname}: Update failed - {result['error']}")

Configuration Management
------------------------

Configuration Deployment Script::

    #!/usr/bin/env python3
    """
    Configuration management and deployment.
    """
    
    import os
    import yaml
    from spindlex import SSHClient
    from spindlex.exceptions import SSHException
    from typing import Dict, List, Any
    import tempfile
    import hashlib
    
    class ConfigManager:
        def __init__(self, config_file: str):
            with open(config_file, 'r') as f:
                self.config = yaml.safe_load(f)
        
        def deploy_configurations(self) -> Dict[str, bool]:
            """Deploy configurations to all servers."""
            results = {}
            
            for server_config in self.config['servers']:
                hostname = server_config['hostname']
                try:
                    self.deploy_to_server(server_config)
                    results[hostname] = True
                    print(f"Configuration deployed successfully to {hostname}")
                    
                except Exception as e:
                    results[hostname] = False
                    print(f"Configuration deployment failed for {hostname}: {e}")
            
            return results
        
        def deploy_to_server(self, server_config: Dict[str, Any]):
            """Deploy configuration to a single server."""
            client = SSHClient()
            
            try:
                # Connect to server
                client.connect(
                    hostname=server_config['hostname'],
                    username=server_config['username'],
                    pkey=server_config.get('private_key'),
                    password=server_config.get('password')
                )
                
                sftp = client.open_sftp()
                
                # Deploy each configuration file
                for config_item in server_config['configurations']:
                    self.deploy_config_item(client, sftp, config_item)
                
                # Run post-deployment commands
                if 'post_deploy_commands' in server_config:
                    for command in server_config['post_deploy_commands']:
                        stdin, stdout, stderr = client.exec_command(command)
                        exit_code = stdout.channel.recv_exit_status()
                        if exit_code != 0:
                            raise Exception(f"Post-deploy command failed: {command}")
            
            finally:
                client.close()
        
        def deploy_config_item(self, client: SSHClient, sftp, config_item: Dict[str, Any]):
            """Deploy a single configuration item."""
            local_path = config_item['local_path']
            remote_path = config_item['remote_path']
            
            # Check if file needs updating
            if self.needs_update(sftp, local_path, remote_path):
                # Backup existing file if requested
                if config_item.get('backup', False):
                    self.backup_file(sftp, remote_path)
                
                # Upload new configuration
                sftp.put(local_path, remote_path)
                
                # Set permissions if specified
                if 'permissions' in config_item:
                    sftp.chmod(remote_path, int(config_item['permissions'], 8))
                
                print(f"Updated {remote_path}")
            else:
                print(f"No update needed for {remote_path}")
        
        def needs_update(self, sftp, local_path: str, remote_path: str) -> bool:
            """Check if remote file needs updating."""
            try:
                # Get local file hash
                with open(local_path, 'rb') as f:
                    local_hash = hashlib.md5(f.read()).hexdigest()
                
                # Get remote file hash
                with sftp.open(remote_path, 'rb') as f:
                    remote_hash = hashlib.md5(f.read()).hexdigest()
                
                return local_hash != remote_hash
                
            except Exception:
                # If we can't compare, assume update is needed
                return True
        
        def backup_file(self, sftp, remote_path: str):
            """Create backup of existing file."""
            import datetime
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"{remote_path}.backup_{timestamp}"
            
            try:
                # Copy file to backup location
                with sftp.open(remote_path, 'rb') as src:
                    with sftp.open(backup_path, 'wb') as dst:
                        dst.write(src.read())
                print(f"Backed up {remote_path} to {backup_path}")
            except Exception as e:
                print(f"Warning: Could not backup {remote_path}: {e}")
    
    # Example configuration file (config.yaml)
    example_config = """
    servers:
      - hostname: web1.example.com
        username: admin
        private_key: /path/to/key
        configurations:
          - local_path: ./configs/nginx.conf
            remote_path: /etc/nginx/nginx.conf
            permissions: "644"
            backup: true
          - local_path: ./configs/app.conf
            remote_path: /etc/myapp/app.conf
            permissions: "600"
            backup: true
        post_deploy_commands:
          - sudo nginx -t
          - sudo systemctl reload nginx
          - sudo systemctl restart myapp
      
      - hostname: db1.example.com
        username: admin
        private_key: /path/to/key
        configurations:
          - local_path: ./configs/postgresql.conf
            remote_path: /etc/postgresql/13/main/postgresql.conf
            permissions: "644"
            backup: true
        post_deploy_commands:
          - sudo systemctl reload postgresql
    """
    
    # Usage example
    if __name__ == "__main__":
        manager = ConfigManager('config.yaml')
        results = manager.deploy_configurations()
        
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)
        
        print(f"\nDeployment completed: {success_count}/{total_count} servers successful")

Log Collection and Analysis
---------------------------

Log Collection Script::

    #!/usr/bin/env python3
    """
    Automated log collection and analysis.
    """
    
    import os
    import re
    import gzip
    from datetime import datetime, timedelta
    from spindlex import SSHClient
    from typing import Dict, List, Any
    import concurrent.futures
    
    class LogCollector:
        def __init__(self, servers: List[Dict[str, Any]]):
            self.servers = servers
        
        def collect_logs(self, log_paths: List[str], 
                        output_dir: str = './collected_logs',
                        days_back: int = 7) -> Dict[str, Any]:
            """Collect logs from all servers."""
            os.makedirs(output_dir, exist_ok=True)
            
            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            
            results = {}
            
            # Use thread pool for parallel collection
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = {}
                
                for server in self.servers:
                    future = executor.submit(
                        self.collect_from_server,
                        server, log_paths, output_dir, start_date, end_date
                    )
                    futures[future] = server['hostname']
                
                for future in concurrent.futures.as_completed(futures):
                    hostname = futures[future]
                    try:
                        results[hostname] = future.result()
                    except Exception as e:
                        results[hostname] = {'success': False, 'error': str(e)}
            
            return results
        
        def collect_from_server(self, server: Dict[str, Any], 
                              log_paths: List[str],
                              output_dir: str,
                              start_date: datetime,
                              end_date: datetime) -> Dict[str, Any]:
            """Collect logs from a single server."""
            hostname = server['hostname']
            client = SSHClient()
            
            try:
                client.connect(
                    hostname=hostname,
                    username=server['username'],
                    password=server.get('password'),
                    pkey=server.get('private_key')
                )
                
                sftp = client.open_sftp()
                collected_files = []
                
                for log_path in log_paths:
                    # Find log files in date range
                    log_files = self.find_log_files(client, log_path, start_date, end_date)
                    
                    for remote_file in log_files:
                        # Create local filename
                        local_filename = f"{hostname}_{os.path.basename(remote_file)}"
                        local_path = os.path.join(output_dir, local_filename)
                        
                        # Download file
                        sftp.get(remote_file, local_path)
                        collected_files.append(local_path)
                        
                        print(f"Collected {remote_file} from {hostname}")
                
                return {
                    'success': True,
                    'files_collected': len(collected_files),
                    'files': collected_files
                }
                
            finally:
                client.close()
        
        def find_log_files(self, client: SSHClient, log_path: str,
                          start_date: datetime, end_date: datetime) -> List[str]:
            """Find log files within date range."""
            # Get directory and filename pattern
            log_dir = os.path.dirname(log_path)
            log_pattern = os.path.basename(log_path)
            
            # List files in log directory
            stdin, stdout, stderr = client.exec_command(f"find {log_dir} -name '{log_pattern}*' -type f")
            files = stdout.read().decode('utf-8').strip().split('\n')
            
            # Filter files by date (simplified - you might want more sophisticated filtering)
            valid_files = []
            for file_path in files:
                if file_path.strip():
                    # Get file modification time
                    stdin, stdout, stderr = client.exec_command(f"stat -c %Y {file_path}")
                    try:
                        mtime = int(stdout.read().decode('utf-8').strip())
                        file_date = datetime.fromtimestamp(mtime)
                        
                        if start_date <= file_date <= end_date:
                            valid_files.append(file_path)
                    except (ValueError, IndexError):
                        # If we can't get the date, include the file
                        valid_files.append(file_path)
            
            return valid_files
        
        def analyze_logs(self, log_directory: str) -> Dict[str, Any]:
            """Analyze collected logs for common patterns."""
            analysis = {
                'error_patterns': {},
                'warning_patterns': {},
                'access_patterns': {},
                'security_events': []
            }
            
            # Common patterns to look for
            error_patterns = [
                r'ERROR',
                r'FATAL',
                r'Exception',
                r'failed',
                r'timeout'
            ]
            
            warning_patterns = [
                r'WARNING',
                r'WARN',
                r'deprecated'
            ]
            
            security_patterns = [
                r'authentication failure',
                r'invalid user',
                r'connection refused',
                r'permission denied'
            ]
            
            # Process all log files
            for filename in os.listdir(log_directory):
                file_path = os.path.join(log_directory, filename)
                
                if os.path.isfile(file_path):
                    self.analyze_log_file(file_path, analysis, 
                                        error_patterns, warning_patterns, security_patterns)
            
            return analysis
        
        def analyze_log_file(self, file_path: str, analysis: Dict[str, Any],
                           error_patterns: List[str], warning_patterns: List[str],
                           security_patterns: List[str]):
            """Analyze a single log file."""
            try:
                # Handle compressed files
                if file_path.endswith('.gz'):
                    with gzip.open(file_path, 'rt') as f:
                        lines = f.readlines()
                else:
                    with open(file_path, 'r') as f:
                        lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    # Check for error patterns
                    for pattern in error_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            if pattern not in analysis['error_patterns']:
                                analysis['error_patterns'][pattern] = []
                            analysis['error_patterns'][pattern].append({
                                'file': file_path,
                                'line': line_num,
                                'content': line.strip()
                            })
                    
                    # Check for warning patterns
                    for pattern in warning_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            if pattern not in analysis['warning_patterns']:
                                analysis['warning_patterns'][pattern] = []
                            analysis['warning_patterns'][pattern].append({
                                'file': file_path,
                                'line': line_num,
                                'content': line.strip()
                            })
                    
                    # Check for security events
                    for pattern in security_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            analysis['security_events'].append({
                                'file': file_path,
                                'line': line_num,
                                'pattern': pattern,
                                'content': line.strip()
                            })
            
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
    
    # Usage example
    if __name__ == "__main__":
        servers = [
            {
                'hostname': 'web1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            },
            {
                'hostname': 'web2.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            }
        ]
        
        collector = LogCollector(servers)
        
        # Collect logs
        log_paths = [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/syslog',
            '/var/log/auth.log'
        ]
        
        print("Collecting logs...")
        results = collector.collect_logs(log_paths, days_back=7)
        
        # Print collection results
        for hostname, result in results.items():
            if result['success']:
                print(f"{hostname}: Collected {result['files_collected']} files")
            else:
                print(f"{hostname}: Collection failed - {result['error']}")
        
        # Analyze collected logs
        print("\nAnalyzing logs...")
        analysis = collector.analyze_logs('./collected_logs')
        
        # Print analysis results
        print(f"\nFound {len(analysis['security_events'])} security events")
        for event in analysis['security_events'][:10]:  # Show first 10
            print(f"  {event['pattern']}: {event['content'][:100]}...")
        
        print(f"\nError patterns found:")
        for pattern, occurrences in analysis['error_patterns'].items():
            print(f"  {pattern}: {len(occurrences)} occurrences")

Backup Automation
-----------------

Database Backup Script::

    #!/usr/bin/env python3
    """
    Automated database backup script.
    """
    
    import os
    import datetime
    from spindlex import SSHClient
    from spindlex.exceptions import SSHException
    from typing import Dict, List, Any
    import subprocess
    
    class BackupManager:
        def __init__(self, config: Dict[str, Any]):
            self.config = config
        
        def run_backups(self) -> Dict[str, Any]:
            """Run backups for all configured databases."""
            results = {}
            
            for db_config in self.config['databases']:
                db_name = db_config['name']
                try:
                    result = self.backup_database(db_config)
                    results[db_name] = result
                    print(f"Backup completed for {db_name}")
                    
                except Exception as e:
                    results[db_name] = {
                        'success': False,
                        'error': str(e)
                    }
                    print(f"Backup failed for {db_name}: {e}")
            
            return results
        
        def backup_database(self, db_config: Dict[str, Any]) -> Dict[str, Any]:
            """Backup a single database."""
            client = SSHClient()
            
            try:
                # Connect to database server
                client.connect(
                    hostname=db_config['hostname'],
                    username=db_config['username'],
                    password=db_config.get('password'),
                    pkey=db_config.get('private_key')
                )
                
                # Generate backup filename
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_filename = f"{db_config['name']}_{timestamp}.sql"
                remote_backup_path = f"/tmp/{backup_filename}"
                
                # Create backup command based on database type
                if db_config['type'] == 'postgresql':
                    backup_cmd = self.create_postgres_backup_command(db_config, remote_backup_path)
                elif db_config['type'] == 'mysql':
                    backup_cmd = self.create_mysql_backup_command(db_config, remote_backup_path)
                else:
                    raise ValueError(f"Unsupported database type: {db_config['type']}")
                
                # Execute backup command
                stdin, stdout, stderr = client.exec_command(backup_cmd)
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    error_output = stderr.read().decode('utf-8')
                    raise Exception(f"Backup command failed: {error_output}")
                
                # Compress backup if requested
                if db_config.get('compress', True):
                    compress_cmd = f"gzip {remote_backup_path}"
                    stdin, stdout, stderr = client.exec_command(compress_cmd)
                    exit_code = stdout.channel.recv_exit_status()
                    
                    if exit_code == 0:
                        remote_backup_path += '.gz'
                        backup_filename += '.gz'
                
                # Download backup file
                local_backup_dir = self.config.get('local_backup_dir', './backups')
                os.makedirs(local_backup_dir, exist_ok=True)
                local_backup_path = os.path.join(local_backup_dir, backup_filename)
                
                sftp = client.open_sftp()
                sftp.get(remote_backup_path, local_backup_path)
                
                # Clean up remote backup file
                client.exec_command(f"rm {remote_backup_path}")
                
                # Get backup file size
                backup_size = os.path.getsize(local_backup_path)
                
                # Upload to remote storage if configured
                remote_storage_path = None
                if 'remote_storage' in self.config:
                    remote_storage_path = self.upload_to_remote_storage(
                        local_backup_path, backup_filename
                    )
                
                # Clean up old backups
                self.cleanup_old_backups(db_config)
                
                return {
                    'success': True,
                    'backup_file': local_backup_path,
                    'backup_size': backup_size,
                    'remote_storage_path': remote_storage_path,
                    'timestamp': timestamp
                }
                
            finally:
                client.close()
        
        def create_postgres_backup_command(self, db_config: Dict[str, Any], 
                                         backup_path: str) -> str:
            """Create PostgreSQL backup command."""
            cmd_parts = ['pg_dump']
            
            if 'db_host' in db_config:
                cmd_parts.extend(['-h', db_config['db_host']])
            
            if 'db_port' in db_config:
                cmd_parts.extend(['-p', str(db_config['db_port'])])
            
            if 'db_username' in db_config:
                cmd_parts.extend(['-U', db_config['db_username']])
            
            cmd_parts.extend(['-f', backup_path])
            cmd_parts.append(db_config['database_name'])
            
            # Set password environment variable if provided
            if 'db_password' in db_config:
                return f"PGPASSWORD='{db_config['db_password']}' {' '.join(cmd_parts)}"
            
            return ' '.join(cmd_parts)
        
        def create_mysql_backup_command(self, db_config: Dict[str, Any], 
                                      backup_path: str) -> str:
            """Create MySQL backup command."""
            cmd_parts = ['mysqldump']
            
            if 'db_host' in db_config:
                cmd_parts.extend(['-h', db_config['db_host']])
            
            if 'db_port' in db_config:
                cmd_parts.extend(['-P', str(db_config['db_port'])])
            
            if 'db_username' in db_config:
                cmd_parts.extend(['-u', db_config['db_username']])
            
            if 'db_password' in db_config:
                cmd_parts.extend(['-p' + db_config['db_password']])
            
            cmd_parts.extend(['--single-transaction', '--routines', '--triggers'])
            cmd_parts.append(db_config['database_name'])
            
            return f"{' '.join(cmd_parts)} > {backup_path}"
        
        def upload_to_remote_storage(self, local_path: str, filename: str) -> str:
            """Upload backup to remote storage."""
            storage_config = self.config['remote_storage']
            
            if storage_config['type'] == 'sftp':
                return self.upload_to_sftp(local_path, filename, storage_config)
            elif storage_config['type'] == 's3':
                return self.upload_to_s3(local_path, filename, storage_config)
            else:
                raise ValueError(f"Unsupported storage type: {storage_config['type']}")
        
        def upload_to_sftp(self, local_path: str, filename: str, 
                          storage_config: Dict[str, Any]) -> str:
            """Upload backup to SFTP server."""
            client = SSHClient()
            
            try:
                client.connect(
                    hostname=storage_config['hostname'],
                    username=storage_config['username'],
                    password=storage_config.get('password'),
                    pkey=storage_config.get('private_key')
                )
                
                sftp = client.open_sftp()
                remote_path = f"{storage_config['path']}/{filename}"
                
                # Create directory if it doesn't exist
                try:
                    sftp.mkdir(storage_config['path'])
                except:
                    pass  # Directory might already exist
                
                sftp.put(local_path, remote_path)
                return remote_path
                
            finally:
                client.close()
        
        def cleanup_old_backups(self, db_config: Dict[str, Any]):
            """Clean up old backup files."""
            retention_days = db_config.get('retention_days', 30)
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
            
            backup_dir = self.config.get('local_backup_dir', './backups')
            db_name = db_config['name']
            
            for filename in os.listdir(backup_dir):
                if filename.startswith(f"{db_name}_"):
                    file_path = os.path.join(backup_dir, filename)
                    file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_date:
                        os.remove(file_path)
                        print(f"Removed old backup: {filename}")
    
    # Example configuration
    backup_config = {
        'local_backup_dir': './backups',
        'databases': [
            {
                'name': 'production_db',
                'type': 'postgresql',
                'hostname': 'db1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'database_name': 'myapp',
                'db_username': 'postgres',
                'db_password': 'dbpassword',
                'compress': True,
                'retention_days': 30
            },
            {
                'name': 'analytics_db',
                'type': 'mysql',
                'hostname': 'db2.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'database_name': 'analytics',
                'db_username': 'root',
                'db_password': 'mysqlpassword',
                'compress': True,
                'retention_days': 7
            }
        ],
        'remote_storage': {
            'type': 'sftp',
            'hostname': 'backup.example.com',
            'username': 'backup',
            'private_key': '/path/to/backup_key',
            'path': '/backups/databases'
        }
    }
    
    # Usage example
    if __name__ == "__main__":
        manager = BackupManager(backup_config)
        results = manager.run_backups()
        
        # Print results
        for db_name, result in results.items():
            if result['success']:
                size_mb = result['backup_size'] / (1024 * 1024)
                print(f"{db_name}: Backup successful ({size_mb:.1f} MB)")
            else:
                print(f"{db_name}: Backup failed - {result['error']}")