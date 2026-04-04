Logging API
===========

Logging Interface
-----------------

.. automodule:: spindlex.logging.logger
   :members:
   :undoc-members:
   :show-inheritance:

Formatters
----------

.. automodule:: spindlex.logging.formatters
   :members:
   :undoc-members:
   :show-inheritance:

Monitoring and Metrics
----------------------

.. automodule:: spindlex.logging.monitoring
   :members:
   :undoc-members:
   :show-inheritance:

Security Logging
----------------

.. automodule:: spindlex.logging.sanitizer
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Configure Logging::

    from spindlex.logging import configure_logging
    import logging
    
    # Simple configuration
    configure_logging(level=logging.DEBUG)
    
    # Detailed configuration
    configure_logging(
        level='INFO',
        output_file='spindlex.log',
        security_file='security.log',
        performance_file='perf.json',
        json_format=True
    )

Get Logger::

    from spindlex.logging import get_logger
    
    logger = get_logger(__name__)
    logger.info("Session started")
    logger.security_event("auth_success", "User authenticated", username="alice")

Monitoring::

    from spindlex.logging.monitoring import get_performance_monitor
    
    monitor = get_performance_monitor()
    metrics = monitor.get_connection_metrics(session_id)
    print(f"Bytes received: {metrics.bytes_received}")
