Transport API
=============

Transport Layer
---------------

.. automodule:: spindlex.transport.transport
   :members:
   :undoc-members:
   :show-inheritance:

Channel Management
------------------

.. automodule:: spindlex.transport.channel
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.client.ssh_client.ChannelFile
   :members:
   :undoc-members:
   :show-inheritance:

Key Exchange
------------

.. automodule:: spindlex.transport.kex
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic Transport Usage::

    import socket
    from spindlex.transport import Transport
    
    # Create socket connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('example.com', 22))
    
    # Create transport
    transport = Transport(sock)
    transport.start_client()
    
    # Authenticate (implementation details depend on version)
    
    # Open channel
    channel = transport.open_channel('session')
