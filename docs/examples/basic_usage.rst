Basic Usage Example
===================

This example demonstrates the basic usage of the SpindleX `SSHClient`.

.. code-block:: python

   from spindlex import SSHClient
   from spindlex.hostkeys.policy import AutoAddPolicy

   # Initialize the SSHClient
   with SSHClient() as client:
       # Set a policy for unknown host keys
       client.set_missing_host_key_policy(AutoAddPolicy())
       
       # Connect to the remote server
       client.connect('example.com', username='user', password='password')
       
       # Execute a command (returns stdin, stdout, stderr)
       stdin, stdout, stderr = client.exec_command('uptime')
       
       # Read output and error streams
       print(f"STDOUT: {stdout.read().decode().strip()}")
       print(f"STDERR: {stderr.read().decode().strip()}")
       
       # Get command exit status (using the underlying channel via _channel)
       exit_status = stdout._channel.get_exit_status()
       print(f"Exit Status: {exit_status}")
       
       # Open an SFTP session
       with client.open_sftp() as sftp:
           # List directory contents
           files = sftp.listdir('.')
           print(f"Remote files: {files}")
           
           # Upload a file
           sftp.put('local_file.txt', 'remote_file.txt')
           
           # Download a file
           sftp.get('remote_file.txt', 'local_file_backup.txt')
