Transport API
=============

Transport Layer
---------------

.. automodule:: ssh_library.transport.transport
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.transport.Transport
   :members:
   :undoc-members:
   :show-inheritance:

Channel Management
------------------

.. automodule:: ssh_library.transport.channel
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.channel.Channel
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.channel.ChannelFile
   :members:
   :undoc-members:
   :show-inheritance:

Key Exchange
------------

.. automodule:: ssh_library.transport.kex
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.kex.KexAlgorithm
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.kex.Curve25519KEX
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.kex.ECDHKEX
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.transport.kex.DiffieHellmanKEX
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic Transport Usage::

    import socket
    from ssh_library.transport import Transport
    
    # Create socket connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('example.com', 22))
    
    # Create transport
    transport = Transport(sock)
    transport.start_client()
    
    # Authenticate
    transport.auth_password('username', 'password')
    
    # Open channel
    channel = transport.open_channel('session')
    channel.exec_command('ls -la')
    
    # Read output
    output = channel.recv(1024)
    print(output.decode())
    
    # Cleanup
    channel.close()
    transport.close()

Channel Operations::

    # Execute command
    channel = transport.open_channel('session')
    channel.exec_command('uname -a')
    
    # Get exit status
    exit_status = channel.recv_exit_status()
    
    # Interactive shell
    shell_channel = transport.open_channel('session')
    shell_channel.invoke_shell()
    
    # Send commands
    shell_channel.send('ls\n')
    response = shell_channel.recv(1024)

Port Forwarding::

    # Local port forwarding
    local_channel = transport.open_channel(
        'direct-tcpip',
        dest_addr=('internal-server', 80),
        src_addr=('localhost', 0)
    )
    
    # Remote port forwarding
    transport.request_port_forward('', 8080, 'localhost', 80)