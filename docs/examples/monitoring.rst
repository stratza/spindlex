Monitoring Examples
===================

This section provides examples for monitoring systems and applications using SSH Library.

System Monitoring
-----------------

Comprehensive System Monitor::

    #!/usr/bin/env python3
    """
    Comprehensive system monitoring script.
    """
    
    import json
    import time
    from datetime import datetime
    from ssh_library import SSHClient
    from ssh_library.exceptions import SSHException
    from typing import Dict, List, Any, Optional
    import threading
    import queue
    
    class SystemMonitor:
        def __init__(self, servers: List[Dict[str, Any]], 
                     check_interval: int = 60):
            self.servers = servers
            self.check_interval = check_interval
            self.running = False
            self.results_queue = queue.Queue()
            self.alert_thresholds = {
                'cpu_usage': 80.0,
                'memory_usage': 85.0,
                'disk_usage': 90.0,
                'load_average': 5.0
            }
        
        def start_monitoring(self):
            """Start continuous monitoring."""
            self.running = True
            
            # Start monitoring threads for each server
            threads = []
            for server in self.servers:
                thread = threading.Thread(
                    target=self.monitor_server,
                    args=(server,),
                    daemon=True
                )
                thread.start()
                threads.append(thread)
            
            # Start results processor
            processor_thread = threading.Thread(
                target=self.process_results,
                daemon=True
            )
            processor_thread.start()
            
            return threads
        
        def stop_monitoring(self):
            """Stop monitoring."""
            self.running = False
        
        def monitor_server(self, server: Dict[str, Any]):
            """Monitor a single server continuously."""
            hostname = server['hostname']
            
            while self.running:
                try:
                    metrics = self.collect_server_metrics(server)
                    self.results_queue.put({
                        'hostname': hostname,
                        'timestamp': datetime.now().isoformat(),
                        'metrics': metrics,
                        'status': 'success'
                    })
                    
                except Exception as e:
                    self.results_queue.put({
                        'hostname': hostname,
                        'timestamp': datetime.now().isoformat(),
                        'error': str(e),
                        'status': 'error'
                    })
                
                time.sleep(self.check_interval)
        
        def collect_server_metrics(self, server: Dict[str, Any]) -> Dict[str, Any]:
            """Collect comprehensive metrics from a server."""
            client = SSHClient()
            
            try:
                client.connect(
                    hostname=server['hostname'],
                    username=server['username'],
                    password=server.get('password'),
                    pkey=server.get('private_key'),
                    timeout=30
                )
                
                metrics = {}
                
                # CPU metrics
                metrics['cpu'] = self.get_cpu_metrics(client)
                
                # Memory metrics
                metrics['memory'] = self.get_memory_metrics(client)
                
                # Disk metrics
                metrics['disk'] = self.get_disk_metrics(client)
                
                # Network metrics
                metrics['network'] = self.get_network_metrics(client)
                
                # Process metrics
                metrics['processes'] = self.get_process_metrics(client)
                
                # System load
                metrics['load'] = self.get_load_metrics(client)
                
                # Service status
                if 'services' in server:
                    metrics['services'] = self.get_service_status(client, server['services'])
                
                return metrics
                
            finally:
                client.close()
        
        def get_cpu_metrics(self, client: SSHClient) -> Dict[str, Any]:
            """Get CPU usage metrics."""
            # Get CPU usage from /proc/stat
            stdin, stdout, stderr = client.exec_command(
                "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$3+$4+$5)} END {print usage}'"
            )
            cpu_usage = float(stdout.read().decode().strip())
            
            # Get CPU info
            stdin, stdout, stderr = client.exec_command("nproc")
            cpu_count = int(stdout.read().decode().strip())
            
            # Get CPU model
            stdin, stdout, stderr = client.exec_command(
                "grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs"
            )
            cpu_model = stdout.read().decode().strip()
            
            return {
                'usage_percent': cpu_usage,
                'count': cpu_count,
                'model': cpu_model
            }
        
        def get_memory_metrics(self, client: SSHClient) -> Dict[str, Any]:
            """Get memory usage metrics."""
            stdin, stdout, stderr = client.exec_command("free -b")
            output = stdout.read().decode().strip().split('\n')
            
            # Parse memory info
            mem_line = output[1].split()
            total_mem = int(mem_line[1])
            used_mem = int(mem_line[2])
            free_mem = int(mem_line[3])
            available_mem = int(mem_line[6]) if len(mem_line) > 6 else free_mem
            
            # Parse swap info
            swap_line = output[2].split()
            total_swap = int(swap_line[1])
            used_swap = int(swap_line[2])
            
            return {
                'total_bytes': total_mem,
                'used_bytes': used_mem,
                'free_bytes': free_mem,
                'available_bytes': available_mem,
                'usage_percent': (used_mem / total_mem) * 100,
                'swap': {
                    'total_bytes': total_swap,
                    'used_bytes': used_swap,
                    'usage_percent': (used_swap / total_swap) * 100 if total_swap > 0 else 0
                }
            }
        
        def get_disk_metrics(self, client: SSHClient) -> Dict[str, Any]:
            """Get disk usage metrics."""
            stdin, stdout, stderr = client.exec_command("df -B1")
            output = stdout.read().decode().strip().split('\n')[1:]  # Skip header
            
            filesystems = []
            for line in output:
                parts = line.split()
                if len(parts) >= 6:
                    filesystem = parts[0]
                    total = int(parts[1])
                    used = int(parts[2])
                    available = int(parts[3])
                    usage_percent = float(parts[4].rstrip('%'))
                    mountpoint = parts[5]
                    
                    filesystems.append({
                        'filesystem': filesystem,
                        'mountpoint': mountpoint,
                        'total_bytes': total,
                        'used_bytes': used,
                        'available_bytes': available,
                        'usage_percent': usage_percent
                    })
            
            return {'filesystems': filesystems}
        
        def get_network_metrics(self, client: SSHClient) -> Dict[str, Any]:
            """Get network interface metrics."""
            stdin, stdout, stderr = client.exec_command("cat /proc/net/dev")
            output = stdout.read().decode().strip().split('\n')[2:]  # Skip headers
            
            interfaces = []
            for line in output:
                parts = line.split()
                if len(parts) >= 16:
                    interface = parts[0].rstrip(':')
                    rx_bytes = int(parts[1])
                    rx_packets = int(parts[2])
                    rx_errors = int(parts[3])
                    tx_bytes = int(parts[9])
                    tx_packets = int(parts[10])
                    tx_errors = int(parts[11])
                    
                    interfaces.append({
                        'interface': interface,
                        'rx_bytes': rx_bytes,
                        'rx_packets': rx_packets,
                        'rx_errors': rx_errors,
                        'tx_bytes': tx_bytes,
                        'tx_packets': tx_packets,
                        'tx_errors': tx_errors
                    })
            
            return {'interfaces': interfaces}
        
        def get_process_metrics(self, client: SSHClient) -> Dict[str, Any]:
            """Get process metrics."""
            # Get process count
            stdin, stdout, stderr = client.exec_command("ps aux | wc -l")
            process_count = int(stdout.read().decode().strip()) - 1  # Subtract header
            
            # Get top CPU processes
            stdin, stdout, stderr = client.exec_command(
                "ps aux --sort=-%cpu | head -6 | tail -5"
            )
            top_cpu_output = stdout.read().decode().strip().split('\n')
            
            top_cpu_processes = []
            for line in top_cpu_output:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    top_cpu_processes.append({
                        'user': parts[0],
                        'pid': int(parts[1]),
                        'cpu_percent': float(parts[2]),
                        'memory_percent': float(parts[3]),
                        'command': parts[10]
                    })
            
            # Get top memory processes
            stdin, stdout, stderr = client.exec_command(
                "ps aux --sort=-%mem | head -6 | tail -5"
            )
            top_mem_output = stdout.read().decode().strip().split('\n')
            
            top_mem_processes = []
            for line in top_mem_output:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    top_mem_processes.append({
                        'user': parts[0],
                        'pid': int(parts[1]),
                        'cpu_percent': float(parts[2]),
                        'memory_percent': float(parts[3]),
                        'command': parts[10]
                    })
            
            return {
                'total_count': process_count,
                'top_cpu': top_cpu_processes,
                'top_memory': top_mem_processes
            }
        
        def get_load_metrics(self, client: SSHClient) -> Dict[str, Any]:
            """Get system load metrics."""
            stdin, stdout, stderr = client.exec_command("cat /proc/loadavg")
            output = stdout.read().decode().strip().split()
            
            return {
                'load_1min': float(output[0]),
                'load_5min': float(output[1]),
                'load_15min': float(output[2]),
                'running_processes': int(output[3].split('/')[0]),
                'total_processes': int(output[3].split('/')[1])
            }
        
        def get_service_status(self, client: SSHClient, services: List[str]) -> Dict[str, Any]:
            """Get status of specified services."""
            service_status = {}
            
            for service in services:
                stdin, stdout, stderr = client.exec_command(
                    f"systemctl is-active {service}"
                )
                status = stdout.read().decode().strip()
                
                stdin, stdout, stderr = client.exec_command(
                    f"systemctl is-enabled {service}"
                )
                enabled = stdout.read().decode().strip()
                
                service_status[service] = {
                    'active': status == 'active',
                    'enabled': enabled == 'enabled',
                    'status': status
                }
            
            return service_status
        
        def process_results(self):
            """Process monitoring results and generate alerts."""
            while self.running:
                try:
                    result = self.results_queue.get(timeout=1)
                    
                    # Log result
                    self.log_result(result)
                    
                    # Check for alerts
                    if result['status'] == 'success':
                        alerts = self.check_alerts(result)
                        if alerts:
                            self.handle_alerts(result['hostname'], alerts)
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"Error processing results: {e}")
        
        def log_result(self, result: Dict[str, Any]):
            """Log monitoring result."""
            timestamp = result['timestamp']
            hostname = result['hostname']
            
            if result['status'] == 'success':
                metrics = result['metrics']
                cpu_usage = metrics['cpu']['usage_percent']
                mem_usage = metrics['memory']['usage_percent']
                load_1min = metrics['load']['load_1min']
                
                print(f"[{timestamp}] {hostname}: CPU={cpu_usage:.1f}% "
                      f"MEM={mem_usage:.1f}% LOAD={load_1min:.2f}")
            else:
                print(f"[{timestamp}] {hostname}: ERROR - {result['error']}")
        
        def check_alerts(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
            """Check if any metrics exceed alert thresholds."""
            alerts = []
            metrics = result['metrics']
            
            # CPU usage alert
            cpu_usage = metrics['cpu']['usage_percent']
            if cpu_usage > self.alert_thresholds['cpu_usage']:
                alerts.append({
                    'type': 'cpu_high',
                    'message': f"High CPU usage: {cpu_usage:.1f}%",
                    'value': cpu_usage,
                    'threshold': self.alert_thresholds['cpu_usage']
                })
            
            # Memory usage alert
            mem_usage = metrics['memory']['usage_percent']
            if mem_usage > self.alert_thresholds['memory_usage']:
                alerts.append({
                    'type': 'memory_high',
                    'message': f"High memory usage: {mem_usage:.1f}%",
                    'value': mem_usage,
                    'threshold': self.alert_thresholds['memory_usage']
                })
            
            # Disk usage alerts
            for fs in metrics['disk']['filesystems']:
                if fs['usage_percent'] > self.alert_thresholds['disk_usage']:
                    alerts.append({
                        'type': 'disk_high',
                        'message': f"High disk usage on {fs['mountpoint']}: {fs['usage_percent']:.1f}%",
                        'value': fs['usage_percent'],
                        'threshold': self.alert_thresholds['disk_usage'],
                        'filesystem': fs['mountpoint']
                    })
            
            # Load average alert
            load_1min = metrics['load']['load_1min']
            if load_1min > self.alert_thresholds['load_average']:
                alerts.append({
                    'type': 'load_high',
                    'message': f"High load average: {load_1min:.2f}",
                    'value': load_1min,
                    'threshold': self.alert_thresholds['load_average']
                })
            
            # Service status alerts
            if 'services' in metrics:
                for service, status in metrics['services'].items():
                    if not status['active']:
                        alerts.append({
                            'type': 'service_down',
                            'message': f"Service {service} is not active",
                            'service': service,
                            'status': status['status']
                        })
            
            return alerts
        
        def handle_alerts(self, hostname: str, alerts: List[Dict[str, Any]]):
            """Handle generated alerts."""
            for alert in alerts:
                print(f"ALERT [{hostname}]: {alert['message']}")
                
                # Here you could add additional alert handling:
                # - Send email notifications
                # - Post to Slack/Discord
                # - Write to alert log file
                # - Trigger automated remediation
        
        def get_summary_report(self) -> Dict[str, Any]:
            """Generate a summary report of all servers."""
            summary = {
                'timestamp': datetime.now().isoformat(),
                'servers': {},
                'alerts': []
            }
            
            for server in self.servers:
                try:
                    metrics = self.collect_server_metrics(server)
                    hostname = server['hostname']
                    
                    summary['servers'][hostname] = {
                        'status': 'online',
                        'cpu_usage': metrics['cpu']['usage_percent'],
                        'memory_usage': metrics['memory']['usage_percent'],
                        'load_1min': metrics['load']['load_1min'],
                        'disk_usage': max(fs['usage_percent'] 
                                        for fs in metrics['disk']['filesystems']),
                        'process_count': metrics['processes']['total_count']
                    }
                    
                    # Check for alerts
                    result = {
                        'hostname': hostname,
                        'timestamp': datetime.now().isoformat(),
                        'metrics': metrics,
                        'status': 'success'
                    }
                    alerts = self.check_alerts(result)
                    if alerts:
                        summary['alerts'].extend([
                            {**alert, 'hostname': hostname} for alert in alerts
                        ])
                
                except Exception as e:
                    summary['servers'][server['hostname']] = {
                        'status': 'error',
                        'error': str(e)
                    }
            
            return summary
    
    # Usage example
    if __name__ == "__main__":
        servers = [
            {
                'hostname': 'web1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'services': ['nginx', 'postgresql', 'redis']
            },
            {
                'hostname': 'web2.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'services': ['nginx', 'mysql']
            },
            {
                'hostname': 'db1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'services': ['postgresql', 'redis']
            }
        ]
        
        monitor = SystemMonitor(servers, check_interval=30)
        
        try:
            # Generate initial summary report
            print("Initial system summary:")
            summary = monitor.get_summary_report()
            
            for hostname, info in summary['servers'].items():
                if info['status'] == 'online':
                    print(f"{hostname}: CPU={info['cpu_usage']:.1f}% "
                          f"MEM={info['memory_usage']:.1f}% "
                          f"LOAD={info['load_1min']:.2f}")
                else:
                    print(f"{hostname}: {info['status']} - {info.get('error', '')}")
            
            if summary['alerts']:
                print(f"\nActive alerts: {len(summary['alerts'])}")
                for alert in summary['alerts']:
                    print(f"  {alert['hostname']}: {alert['message']}")
            
            # Start continuous monitoring
            print(f"\nStarting continuous monitoring (interval: {monitor.check_interval}s)")
            print("Press Ctrl+C to stop...")
            
            threads = monitor.start_monitoring()
            
            # Keep main thread alive
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            monitor.stop_monitoring()

Application Performance Monitoring
----------------------------------

Web Application Monitor::

    #!/usr/bin/env python3
    """
    Web application performance monitoring.
    """
    
    import requests
    import time
    from datetime import datetime, timedelta
    from ssh_library import SSHClient
    from typing import Dict, List, Any
    import json
    import re
    
    class WebAppMonitor:
        def __init__(self, config: Dict[str, Any]):
            self.config = config
            self.metrics_history = []
        
        def monitor_application(self) -> Dict[str, Any]:
            """Monitor web application performance."""
            results = {
                'timestamp': datetime.now().isoformat(),
                'url_checks': [],
                'server_metrics': [],
                'log_analysis': {},
                'alerts': []
            }
            
            # Check URL endpoints
            for url_config in self.config.get('urls', []):
                url_result = self.check_url(url_config)
                results['url_checks'].append(url_result)
                
                # Generate alerts for URL issues
                if not url_result['success'] or url_result['response_time'] > url_config.get('max_response_time', 5.0):
                    results['alerts'].append({
                        'type': 'url_issue',
                        'url': url_config['url'],
                        'message': f"URL check failed or slow response: {url_result.get('error', 'Slow response')}"
                    })
            
            # Check server metrics
            for server in self.config.get('servers', []):
                server_result = self.check_server_performance(server)
                results['server_metrics'].append(server_result)
            
            # Analyze application logs
            if 'log_analysis' in self.config:
                log_result = self.analyze_application_logs()
                results['log_analysis'] = log_result
                
                # Generate alerts for log issues
                if log_result.get('error_count', 0) > self.config['log_analysis'].get('max_errors', 10):
                    results['alerts'].append({
                        'type': 'high_error_rate',
                        'message': f"High error rate detected: {log_result['error_count']} errors"
                    })
            
            # Store metrics history
            self.metrics_history.append(results)
            
            # Keep only last 24 hours of data
            cutoff_time = datetime.now() - timedelta(hours=24)
            self.metrics_history = [
                m for m in self.metrics_history 
                if datetime.fromisoformat(m['timestamp']) > cutoff_time
            ]
            
            return results
        
        def check_url(self, url_config: Dict[str, Any]) -> Dict[str, Any]:
            """Check URL endpoint performance."""
            url = url_config['url']
            method = url_config.get('method', 'GET')
            timeout = url_config.get('timeout', 10)
            expected_status = url_config.get('expected_status', 200)
            
            result = {
                'url': url,
                'method': method,
                'timestamp': datetime.now().isoformat()
            }
            
            try:
                start_time = time.time()
                
                if method.upper() == 'GET':
                    response = requests.get(url, timeout=timeout)
                elif method.upper() == 'POST':
                    data = url_config.get('data', {})
                    response = requests.post(url, json=data, timeout=timeout)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                end_time = time.time()
                response_time = end_time - start_time
                
                result.update({
                    'success': True,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'content_length': len(response.content),
                    'headers': dict(response.headers)
                })
                
                # Check expected status code
                if response.status_code != expected_status:
                    result['success'] = False
                    result['error'] = f"Unexpected status code: {response.status_code}"
                
                # Check response content if specified
                if 'expected_content' in url_config:
                    if url_config['expected_content'] not in response.text:
                        result['success'] = False
                        result['error'] = "Expected content not found in response"
                
            except Exception as e:
                result.update({
                    'success': False,
                    'error': str(e),
                    'response_time': timeout  # Max time
                })
            
            return result
        
        def check_server_performance(self, server: Dict[str, Any]) -> Dict[str, Any]:
            """Check server performance metrics."""
            client = SSHClient()
            
            try:
                client.connect(
                    hostname=server['hostname'],
                    username=server['username'],
                    password=server.get('password'),
                    pkey=server.get('private_key')
                )
                
                result = {
                    'hostname': server['hostname'],
                    'timestamp': datetime.now().isoformat(),
                    'success': True
                }
                
                # Get application-specific metrics
                if 'app_processes' in server:
                    result['app_processes'] = self.check_app_processes(client, server['app_processes'])
                
                if 'app_ports' in server:
                    result['app_ports'] = self.check_app_ports(client, server['app_ports'])
                
                if 'app_logs' in server:
                    result['recent_errors'] = self.check_recent_errors(client, server['app_logs'])
                
                # Get system metrics
                result['cpu_usage'] = self.get_cpu_usage(client)
                result['memory_usage'] = self.get_memory_usage(client)
                result['disk_io'] = self.get_disk_io(client)
                result['network_io'] = self.get_network_io(client)
                
                return result
                
            except Exception as e:
                return {
                    'hostname': server['hostname'],
                    'timestamp': datetime.now().isoformat(),
                    'success': False,
                    'error': str(e)
                }
            
            finally:
                client.close()
        
        def check_app_processes(self, client: SSHClient, processes: List[str]) -> Dict[str, Any]:
            """Check application process status."""
            process_status = {}
            
            for process_name in processes:
                stdin, stdout, stderr = client.exec_command(
                    f"pgrep -f {process_name} | wc -l"
                )
                count = int(stdout.read().decode().strip())
                
                # Get process details if running
                if count > 0:
                    stdin, stdout, stderr = client.exec_command(
                        f"ps aux | grep {process_name} | grep -v grep"
                    )
                    process_info = stdout.read().decode().strip().split('\n')
                    
                    total_cpu = 0
                    total_mem = 0
                    for line in process_info:
                        parts = line.split()
                        if len(parts) >= 4:
                            total_cpu += float(parts[2])
                            total_mem += float(parts[3])
                    
                    process_status[process_name] = {
                        'running': True,
                        'count': count,
                        'total_cpu_percent': total_cpu,
                        'total_memory_percent': total_mem
                    }
                else:
                    process_status[process_name] = {
                        'running': False,
                        'count': 0
                    }
            
            return process_status
        
        def check_app_ports(self, client: SSHClient, ports: List[int]) -> Dict[str, Any]:
            """Check if application ports are listening."""
            port_status = {}
            
            for port in ports:
                stdin, stdout, stderr = client.exec_command(
                    f"netstat -ln | grep :{port} | wc -l"
                )
                listening = int(stdout.read().decode().strip()) > 0
                
                if listening:
                    # Get connection count
                    stdin, stdout, stderr = client.exec_command(
                        f"netstat -an | grep :{port} | grep ESTABLISHED | wc -l"
                    )
                    connections = int(stdout.read().decode().strip())
                    
                    port_status[port] = {
                        'listening': True,
                        'connections': connections
                    }
                else:
                    port_status[port] = {
                        'listening': False,
                        'connections': 0
                    }
            
            return port_status
        
        def check_recent_errors(self, client: SSHClient, log_files: List[str]) -> Dict[str, Any]:
            """Check for recent errors in application logs."""
            error_summary = {
                'total_errors': 0,
                'error_types': {},
                'recent_errors': []
            }
            
            # Look for errors in the last 5 minutes
            for log_file in log_files:
                stdin, stdout, stderr = client.exec_command(
                    f"tail -1000 {log_file} | grep -i error | tail -20"
                )
                error_lines = stdout.read().decode().strip().split('\n')
                
                for line in error_lines:
                    if line.strip():
                        error_summary['total_errors'] += 1
                        error_summary['recent_errors'].append({
                            'log_file': log_file,
                            'message': line.strip()
                        })
                        
                        # Categorize error types
                        if 'database' in line.lower():
                            error_summary['error_types']['database'] = error_summary['error_types'].get('database', 0) + 1
                        elif 'timeout' in line.lower():
                            error_summary['error_types']['timeout'] = error_summary['error_types'].get('timeout', 0) + 1
                        elif 'connection' in line.lower():
                            error_summary['error_types']['connection'] = error_summary['error_types'].get('connection', 0) + 1
                        else:
                            error_summary['error_types']['other'] = error_summary['error_types'].get('other', 0) + 1
            
            return error_summary
        
        def get_cpu_usage(self, client: SSHClient) -> float:
            """Get current CPU usage."""
            stdin, stdout, stderr = client.exec_command(
                "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
            )
            return float(stdout.read().decode().strip())
        
        def get_memory_usage(self, client: SSHClient) -> Dict[str, Any]:
            """Get memory usage."""
            stdin, stdout, stderr = client.exec_command("free -m")
            output = stdout.read().decode().strip().split('\n')[1]
            parts = output.split()
            
            total = int(parts[1])
            used = int(parts[2])
            
            return {
                'total_mb': total,
                'used_mb': used,
                'usage_percent': (used / total) * 100
            }
        
        def get_disk_io(self, client: SSHClient) -> Dict[str, Any]:
            """Get disk I/O statistics."""
            stdin, stdout, stderr = client.exec_command(
                "iostat -d 1 2 | tail -n +4 | tail -1"
            )
            output = stdout.read().decode().strip()
            
            if output:
                parts = output.split()
                return {
                    'reads_per_sec': float(parts[3]),
                    'writes_per_sec': float(parts[4]),
                    'read_kb_per_sec': float(parts[5]),
                    'write_kb_per_sec': float(parts[6])
                }
            
            return {}
        
        def get_network_io(self, client: SSHClient) -> Dict[str, Any]:
            """Get network I/O statistics."""
            # This is a simplified version - you might want to use sar or other tools
            stdin, stdout, stderr = client.exec_command(
                "cat /proc/net/dev | grep eth0"
            )
            output = stdout.read().decode().strip()
            
            if output:
                parts = output.split()
                return {
                    'rx_bytes': int(parts[1]),
                    'tx_bytes': int(parts[9]),
                    'rx_packets': int(parts[2]),
                    'tx_packets': int(parts[10])
                }
            
            return {}
        
        def analyze_application_logs(self) -> Dict[str, Any]:
            """Analyze application logs for patterns."""
            log_config = self.config['log_analysis']
            analysis = {
                'error_count': 0,
                'warning_count': 0,
                'patterns': {},
                'performance_issues': []
            }
            
            for server in log_config['servers']:
                client = SSHClient()
                
                try:
                    client.connect(
                        hostname=server['hostname'],
                        username=server['username'],
                        password=server.get('password'),
                        pkey=server.get('private_key')
                    )
                    
                    for log_file in server['log_files']:
                        self.analyze_log_file(client, log_file, analysis)
                
                finally:
                    client.close()
            
            return analysis
        
        def analyze_log_file(self, client: SSHClient, log_file: str, analysis: Dict[str, Any]):
            """Analyze a single log file."""
            # Get recent log entries (last 1000 lines)
            stdin, stdout, stderr = client.exec_command(f"tail -1000 {log_file}")
            log_content = stdout.read().decode()
            
            lines = log_content.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                # Count errors and warnings
                if re.search(r'\b(error|exception|fatal)\b', line, re.IGNORECASE):
                    analysis['error_count'] += 1
                elif re.search(r'\bwarn(ing)?\b', line, re.IGNORECASE):
                    analysis['warning_count'] += 1
                
                # Look for performance issues
                if re.search(r'slow query|timeout|connection pool', line, re.IGNORECASE):
                    analysis['performance_issues'].append(line.strip())
                
                # Pattern matching for specific issues
                for pattern_name, pattern_regex in self.config['log_analysis'].get('patterns', {}).items():
                    if re.search(pattern_regex, line, re.IGNORECASE):
                        if pattern_name not in analysis['patterns']:
                            analysis['patterns'][pattern_name] = 0
                        analysis['patterns'][pattern_name] += 1
        
        def generate_report(self) -> str:
            """Generate a comprehensive monitoring report."""
            if not self.metrics_history:
                return "No monitoring data available."
            
            latest = self.metrics_history[-1]
            
            report = f"""
    Web Application Monitoring Report
    Generated: {latest['timestamp']}
    
    URL Endpoint Status:
    """
            
            for url_check in latest['url_checks']:
                status = "✓" if url_check['success'] else "✗"
                response_time = url_check.get('response_time', 0)
                report += f"  {status} {url_check['url']} - {response_time:.2f}s\n"
            
            report += "\nServer Performance:\n"
            for server in latest['server_metrics']:
                if server['success']:
                    cpu = server.get('cpu_usage', 0)
                    mem = server.get('memory_usage', {}).get('usage_percent', 0)
                    report += f"  {server['hostname']}: CPU={cpu:.1f}% MEM={mem:.1f}%\n"
                else:
                    report += f"  {server['hostname']}: ERROR - {server.get('error', 'Unknown')}\n"
            
            if latest.get('log_analysis'):
                log_analysis = latest['log_analysis']
                report += f"\nLog Analysis:\n"
                report += f"  Errors: {log_analysis.get('error_count', 0)}\n"
                report += f"  Warnings: {log_analysis.get('warning_count', 0)}\n"
                
                if log_analysis.get('patterns'):
                    report += "  Pattern Matches:\n"
                    for pattern, count in log_analysis['patterns'].items():
                        report += f"    {pattern}: {count}\n"
            
            if latest.get('alerts'):
                report += f"\nActive Alerts ({len(latest['alerts'])}):\n"
                for alert in latest['alerts']:
                    report += f"  ⚠ {alert['message']}\n"
            
            return report
    
    # Example configuration
    monitor_config = {
        'urls': [
            {
                'url': 'https://myapp.example.com/health',
                'method': 'GET',
                'expected_status': 200,
                'expected_content': 'OK',
                'max_response_time': 2.0,
                'timeout': 10
            },
            {
                'url': 'https://myapp.example.com/api/status',
                'method': 'GET',
                'expected_status': 200,
                'max_response_time': 1.0
            }
        ],
        'servers': [
            {
                'hostname': 'web1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'app_processes': ['nginx', 'gunicorn', 'celery'],
                'app_ports': [80, 443, 8000],
                'app_logs': ['/var/log/myapp/app.log', '/var/log/nginx/error.log']
            }
        ],
        'log_analysis': {
            'servers': [
                {
                    'hostname': 'web1.example.com',
                    'username': 'admin',
                    'private_key': '/path/to/key',
                    'log_files': ['/var/log/myapp/app.log']
                }
            ],
            'patterns': {
                'database_errors': r'database.*error|connection.*failed',
                'authentication_failures': r'authentication.*failed|invalid.*credentials',
                'rate_limiting': r'rate.*limit|too.*many.*requests'
            },
            'max_errors': 10
        }
    }
    
    # Usage example
    if __name__ == "__main__":
        monitor = WebAppMonitor(monitor_config)
        
        # Run single monitoring cycle
        results = monitor.monitor_application()
        
        # Print report
        print(monitor.generate_report())
        
        # For continuous monitoring, you would run this in a loop
        # while True:
        #     results = monitor.monitor_application()
        #     time.sleep(60)  # Check every minute