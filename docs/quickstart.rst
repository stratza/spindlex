Quick Start Guide
=================

This guide will help you get started with SSH Library quickly.

Installation
------------

Install SSH Library using pip:

.. code-block:: bash

   pip install ssh-library

For development features:

.. code-block:: bash

   pip install ssh-library[dev]

For async support:

.. code-block:: bash

   pip install ssh-library[async]

For GSSAPI authentication (Unix only):

.. code-block:: bash

   pip install ssh-library[gssapi]

Basic SSH Client
----------------

Here's a simple example of using the SSH client:

.. code-block:: python

   from ssh_library import SSHClient, AutoAddPolicy

   # Create and configure client
   client = SSHClient()
   client.set_missing_host_key_policy(AutoAddPolicy())

   try:
       # Connect to server
       client.connect(
           hostname='example.com',
           username='myuser',
           password='mypassword'
       )

       # Execute a command
       stdin, stdout, stderr = client.exec_command('uname -a')
       
       # Read the output
       output = stdout.read().decode('utf-8')
       print(f"Server info: {output}")

   finally:
       # Always close the connection
       client.close()

Using SSH Keys
--------------

For key-based authentication:

.. code-block:: python

   from ssh_library import SSHClient
   from ssh_library.crypto.pkey import Ed25519Key

   # Load private key
   private_key = Ed25519Key.from_private_key_file('/path/to/private_key')

   client = SSHClient()
   client.connect(
       hostname='example.com',
       username='myuser',
       pkey=private_key
   )

SFTP File Transfer
------------------

Transfer files using SFTP:

.. code-block:: python

   from ssh_library import SSHClient

   client = SSHClient()
   client.connect('example.com', username='user', password='pass')

   # Open SFTP session
   sftp = client.open_sftp()

   try:
       # Upload a file
       sftp.put('/local/file.txt', '/remote/file.txt')
       
       # Download a file
       sftp.get('/remote/data.csv', '/local/data.csv')
       
       # List directory contents
       files = sftp.listdir('/remote/directory')
       for filename in files:
           print(filename)

   finally:
       sftp.close()
       client.close()

Port Forwarding
---------------

Set up local port forwarding:

.. code-block:: python

   from ssh_library import SSHClient

   client = SSHClient()
   client.connect('jump-server.com', username='user', password='pass')

   # Forward local port 8080 to remote server port 80
   transport = client.get_transport()
   local_port = transport.request_port_forward('', 8080, 'internal-server', 80)

   print(f"Port forwarding active on port {local_port}")
   
   # Keep the connection alive
   input("Press Enter to stop forwarding...")
   
   client.close()

Context Manager
---------------

Use context managers for automatic cleanup:

.. code-block:: python

   from ssh_library import SSHClient

   with SSHClient() as client:
       client.connect('example.com', username='user', password='pass')
       
       stdin, stdout, stderr = client.exec_command('ls')
       print(stdout.read().decode())
       
       with client.open_sftp() as sftp:
           files = sftp.listdir('.')
           print(f"Files: {files}")

Error Handling
--------------

Handle common SSH errors:

.. code-block:: python

   from ssh_library import (
       SSHClient, 
       AuthenticationException, 
       BadHostKeyException,
       SSHException
   )

   client = SSHClient()

   try:
       client.connect('example.com', username='user', password='wrong')
   except AuthenticationException:
       print("Authentication failed - check credentials")
   except BadHostKeyException:
       print("Host key verification failed")
   except SSHException as e:
       print(f"SSH error: {e}")
   except Exception as e:
       print(f"Unexpected error: {e}")

Next Steps
----------

* Read the :doc:`user_guide/index` for detailed usage information
* Check out :doc:`examples/index` for more code examples
* Review :doc:`security` for security best practices
* See :doc:`api_reference/index` for complete API documentation