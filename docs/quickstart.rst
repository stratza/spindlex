Quick Start Guide
=================

This guide will help you get started with SpindleX quickly.

Installation
------------

Install SpindleX using pip:

.. code-block:: bash

   pip install spindlex

For development features:

.. code-block:: bash

   pip install spindlex[dev]

For GSSAPI authentication (Unix only):

.. code-block:: bash

   pip install spindlex[gssapi]

Basic SSH Client
----------------

Here's a simple example of using the SSH client:

.. code-block:: python

   from spindlex import SSHClient
   from spindlex.hostkeys.policy import AutoAddPolicy

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

       # Execute a command (returns stdin, stdout, stderr)
       stdin, stdout, stderr = client.exec_command('uname -a')
       
       # Read the output
       output = stdout.read().decode('utf-8')
       print(f"Server info: {output}")
       
       # Get exit status
       exit_status = stdout._channel.get_exit_status()
       print(f"Exit status: {exit_status}")

   finally:
       # Always close the connection
       client.close()

Using SSH Keys
--------------

For key-based authentication, you can use the `spindlex-keygen` tool or load existing keys:

.. code-block:: python

   from spindlex import SSHClient
   from spindlex.crypto.pkey import load_key_from_file

   # Load private key
   private_key = load_key_from_file('/path/to/private_key')

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

   from spindlex import SSHClient

   client = SSHClient()
   client.connect('example.com', username='user', password='pass')

   # Open SFTP session
   try:
       with client.open_sftp() as sftp:
           # Upload a file
           sftp.put('/local/file.txt', '/remote/file.txt')
           
           # Download a file
           sftp.get('/remote/data.csv', '/local/data.csv')
           
           # List directory contents
           files = sftp.listdir('/remote/directory')
           for filename in files:
               print(filename)
   finally:
       client.close()

Async Support
-------------

SpindleX provides native async support through `AsyncSSHClient` and `AsyncSFTPClient`:

.. code-block:: python

   import asyncio
   from spindlex import AsyncSSHClient

   async def run_command():
       async with AsyncSSHClient() as client:
           await client.connect('example.com', username='user')
           stdin, stdout, stderr = await client.exec_command('ls -la')
           print(await stdout.read())

   asyncio.run(run_command())

Context Manager
---------------

Use context managers for automatic cleanup:

.. code-block:: python

   from spindlex import SSHClient

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

   from spindlex import (
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
