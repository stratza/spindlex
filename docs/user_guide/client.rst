SSH Client
==========

The SSH client is the primary interface for connecting to SSH servers and executing remote operations.

Basic Usage
-----------

Creating and Configuring a Client
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from spindlex import SSHClient, AutoAddPolicy

   # Create client
   client = SSHClient()
   
   # Configure host key policy
   client.set_missing_host_key_policy(AutoAddPolicy())

Connection Methods
~~~~~~~~~~~~~~~~~~

Password Authentication
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   client.connect(
       hostname='example.com',
       port=22,
       username='myuser',
       password='mypassword',
       timeout=30
   )

Public Key Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   from spindlex.crypto.pkey import Ed25519Key

   # Load key from file
   private_key = Ed25519Key.from_private_key_file('/path/to/key')
   
   client.connect(
       hostname='example.com',
       username='myuser',
       pkey=private_key
   )

   # Or specify key file path
   client.connect(
       hostname='example.com',
       username='myuser',
       key_filename='/path/to/key'
   )

Keyboard-Interactive Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: python

   def auth_handler(title, instructions, prompt_list):
       """Handle interactive authentication prompts."""
       responses = []
       for prompt, echo in prompt_list:
           if 'password' in prompt.lower():
               responses.append('mypassword')
           else:
               responses.append(input(prompt))
       return responses

   client.connect(
       hostname='example.com',
       username='myuser',
       auth_handler=auth_handler
   )

Command Execution
-----------------

Simple Commands
~~~~~~~~~~~~~~~

.. code-block:: python

   # Execute a simple command
   stdin, stdout, stderr = client.exec_command('ls -la')
   
   # Read output
   output = stdout.read().decode('utf-8')
   error = stderr.read().decode('utf-8')
   exit_status = stdout.channel.recv_exit_status()
   
   print(f"Output: {output}")
   print(f"Error: {error}")
   print(f"Exit status: {exit_status}")

Commands with Input
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   stdin, stdout, stderr = client.exec_command('cat > /tmp/test.txt')
   
   # Send input to the command
   stdin.write('Hello, World!\n')
   stdin.flush()
   stdin.close()
   
   # Wait for command to complete
   exit_status = stdout.channel.recv_exit_status()

Interactive Shell
~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Start an interactive shell
   shell = client.invoke_shell()
   
   # Send commands
   shell.send('ls -la\n')
   
   # Read output (non-blocking)
   import time
   time.sleep(1)  # Wait for command to execute
   
   if shell.recv_ready():
       output = shell.recv(1024).decode('utf-8')
       print(output)
   
   # Close shell
   shell.close()

Advanced Features
-----------------

Connection Pooling
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   class SSHConnectionPool:
       def __init__(self, hostname, username, **kwargs):
           self.hostname = hostname
           self.username = username
           self.kwargs = kwargs
           self.connections = []
           self.max_connections = 5
       
       def get_connection(self):
           if self.connections:
               return self.connections.pop()
           
           if len(self.connections) < self.max_connections:
               client = SSHClient()
               client.connect(self.hostname, self.username, **self.kwargs)
               return client
           
           raise Exception("No available connections")
       
       def return_connection(self, client):
           if len(self.connections) < self.max_connections:
               self.connections.append(client)
           else:
               client.close()

Connection Persistence
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import time
   from spindlex.exceptions import SSHException

   class PersistentSSHClient:
       def __init__(self, **connect_kwargs):
           self.connect_kwargs = connect_kwargs
           self.client = None
       
       def _ensure_connected(self):
           if self.client is None or not self.client.get_transport().is_active():
               self.client = SSHClient()
               self.client.connect(**self.connect_kwargs)
       
       def exec_command(self, command, retries=3):
           for attempt in range(retries):
               try:
                   self._ensure_connected()
                   return self.client.exec_command(command)
               except SSHException:
                   if attempt == retries - 1:
                       raise
                   time.sleep(1)  # Wait before retry

Host Key Management
-------------------

Host Key Policies
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from spindlex.hostkeys.policy import (
       AutoAddPolicy, RejectPolicy, WarningPolicy
   )

   # Automatically add unknown host keys (not recommended for production)
   client.set_missing_host_key_policy(AutoAddPolicy())

   # Reject all unknown host keys (secure default)
   client.set_missing_host_key_policy(RejectPolicy())

   # Log warning but accept unknown host keys
   client.set_missing_host_key_policy(WarningPolicy())

Custom Host Key Policy
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from spindlex.hostkeys.policy import MissingHostKeyPolicy

   class CustomHostKeyPolicy(MissingHostKeyPolicy):
       def missing_host_key(self, client, hostname, key):
           # Custom logic for handling unknown host keys
           fingerprint = key.get_fingerprint()
           
           # Example: Check against a database or external service
           if self.is_key_trusted(hostname, fingerprint):
               # Accept the key
               client.get_host_keys().add(hostname, key.get_name(), key)
           else:
               # Reject the key
               raise Exception(f"Untrusted host key for {hostname}")
       
       def is_key_trusted(self, hostname, fingerprint):
           # Implement your trust verification logic
           return True

   client.set_missing_host_key_policy(CustomHostKeyPolicy())

Error Handling
--------------

Common Exceptions
~~~~~~~~~~~~~~~~~

.. code-block:: python

   from spindlex.exceptions import (
       SSHException,
       AuthenticationException,
       BadHostKeyException,
       ChannelException,
       TransportException
   )

   try:
       client.connect('example.com', username='user', password='pass')
   except AuthenticationException as e:
       print(f"Authentication failed: {e}")
   except BadHostKeyException as e:
       print(f"Host key verification failed: {e}")
   except TransportException as e:
       print(f"Transport error: {e}")
   except SSHException as e:
       print(f"General SSH error: {e}")

Timeout Handling
~~~~~~~~~~~~~~~~

.. code-block:: python

   import socket

   try:
       client.connect(
           hostname='example.com',
           username='user',
           password='pass',
           timeout=10  # 10 second timeout
       )
   except socket.timeout:
       print("Connection timed out")
   except Exception as e:
       print(f"Connection failed: {e}")

Best Practices
--------------

1. **Always close connections**: Use try/finally or context managers
2. **Use key-based authentication**: More secure than passwords
3. **Implement proper host key verification**: Don't use AutoAddPolicy in production
4. **Handle timeouts appropriately**: Set reasonable timeout values
5. **Use connection pooling**: For applications with many short-lived connections
6. **Implement retry logic**: For unreliable network connections
7. **Monitor connection health**: Check transport.is_active() periodically