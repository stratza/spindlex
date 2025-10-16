Logging API
===========

Logging Configuration
---------------------

.. automodule:: ssh_library.logging
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: ssh_library.logging.configure_logging

.. autofunction:: ssh_library.logging.get_logger

.. autofunction:: ssh_library.logging.set_log_level

Logger Classes
--------------

.. autoclass:: ssh_library.logging.SSHLogger
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.logging.SecureFormatter
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.logging.PerformanceLogger
   :members:
   :undoc-members:
   :show-inheritance:

Monitoring and Metrics
----------------------

.. automodule:: ssh_library.logging.monitoring
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.logging.monitoring.PerformanceMonitor
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.logging.monitoring.ConnectionMetrics
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic Logging Setup::

    from ssh_library.logging import configure_logging, get_logger
    
    # Configure logging
    configure_logging(
        level='INFO',
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        log_file='/var/log/ssh_library.log'
    )
    
    # Get logger
    logger = get_logger(__name__)
    
    # Log messages
    logger.info("Starting SSH connection")
    logger.debug("Detailed debug information")
    logger.warning("Potential security issue")
    logger.error("Connection failed")

Secure Logging::

    from ssh_library.logging import configure_logging
    
    # Configure with security features
    configure_logging(
        level='INFO',
        sanitize_secrets=True,  # Remove sensitive data
        max_log_size=10*1024*1024,  # 10MB
        backup_count=5,
        secure_permissions=True  # Set restrictive file permissions
    )
    
    logger = get_logger(__name__)
    
    # These will be automatically sanitized
    logger.info("Authentication attempt", extra={
        'username': 'user',
        'password': 'secret123',  # Will be redacted
        'hostname': 'server.com'
    })

Performance Monitoring::

    from ssh_library.logging.monitoring import PerformanceMonitor
    import time
    
    monitor = PerformanceMonitor()
    
    # Time operations
    with monitor.time_operation('ssh_connect'):
        client.connect('server.com', username='user', password='pass')
    
    # Record metrics
    monitor.record_metric('bytes_transferred', 1024)
    monitor.record_metric('connection_count', 1)
    
    # Get statistics
    stats = monitor.get_statistics()
    print(f"Average connect time: {stats['ssh_connect']['avg']:.2f}s")

Custom Logger::

    from ssh_library.logging import SSHLogger
    import logging
    
    class CustomSSHLogger(SSHLogger):
        def __init__(self, name):
            super().__init__(name)
            
        def log_connection_attempt(self, hostname, username):
            self.info("Connection attempt", extra={
                'event_type': 'connection_attempt',
                'hostname': hostname,
                'username': username,
                'timestamp': time.time()
            })
            
        def log_authentication_success(self, hostname, username, method):
            self.info("Authentication successful", extra={
                'event_type': 'auth_success',
                'hostname': hostname,
                'username': username,
                'auth_method': method
            })
            
        def log_security_event(self, event_type, details):
            self.warning("Security event", extra={
                'event_type': f'security_{event_type}',
                **details
            })
    
    # Usage
    logger = CustomSSHLogger(__name__)
    logger.log_connection_attempt('server.com', 'user')

Structured Logging::

    from ssh_library.logging import get_logger
    import json
    
    logger = get_logger(__name__)
    
    # Structured log entries
    connection_info = {
        'hostname': 'server.com',
        'port': 22,
        'username': 'user',
        'auth_method': 'publickey',
        'cipher': 'chacha20-poly1305@openssh.com',
        'mac': 'poly1305',
        'kex': 'curve25519-sha256'
    }
    
    logger.info("SSH connection established", extra=connection_info)
    
    # Performance metrics
    perf_data = {
        'operation': 'file_transfer',
        'bytes': 1048576,
        'duration': 2.5,
        'throughput': 419430.4
    }
    
    logger.info("File transfer completed", extra=perf_data)

Log Analysis::

    from ssh_library.logging.monitoring import LogAnalyzer
    
    analyzer = LogAnalyzer('/var/log/ssh_library.log')
    
    # Analyze connection patterns
    connections = analyzer.get_connection_stats()
    print(f"Total connections: {connections['total']}")
    print(f"Failed connections: {connections['failed']}")
    
    # Security analysis
    security_events = analyzer.get_security_events()
    for event in security_events:
        print(f"Security event: {event['type']} at {event['timestamp']}")
    
    # Performance analysis
    perf_stats = analyzer.get_performance_stats()
    print(f"Average connection time: {perf_stats['avg_connect_time']:.2f}s")

Integration with External Systems::

    import logging
    from ssh_library.logging import configure_logging
    
    # Syslog integration
    configure_logging(
        level='INFO',
        handlers=[
            {
                'type': 'syslog',
                'address': ('localhost', 514),
                'facility': 'daemon'
            }
        ]
    )
    
    # JSON logging for log aggregation
    configure_logging(
        level='INFO',
        format='json',
        handlers=[
            {
                'type': 'file',
                'filename': '/var/log/ssh_library.json',
                'formatter': 'json'
            }
        ]
    )
    
    # Multiple handlers
    configure_logging(
        level='DEBUG',
        handlers=[
            {'type': 'console', 'level': 'INFO'},
            {'type': 'file', 'filename': '/var/log/debug.log', 'level': 'DEBUG'},
            {'type': 'syslog', 'level': 'WARNING'}
        ]
    )