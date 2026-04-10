File Transfer Example (SFTP)
============================

This example demonstrates how to transfer files securely using SFTP in SpindleX.

.. code-block:: python

   from spindlex import SSHClient
   from spindlex.hostkeys.policy import AutoAddPolicy

   # Initialize and connect the client
   client = SSHClient()
   client.set_missing_host_key_policy(AutoAddPolicy())
   client.connect('example.com', username='user', password='password')

   try:
       # Open an SFTP session
       with client.open_sftp() as sftp:
           # Upload a file
           sftp.put('local_file.txt', 'remote_file.txt')
           
           # Get remote file attributes
           attrs = sftp.stat('remote_file.txt')
           print(f"Remote file size: {attrs.st_size} bytes")
           
           # Change remote file permissions
           sftp.chmod('remote_file.txt', 0o644)
           
           # Download a file
           sftp.get('remote_file.txt', 'local_backup.txt')
           
           # List remote directory
           files = sftp.listdir('.')
           print(f"Files in remote home: {files}")
           
           # Rename a remote file
           sftp.rename('remote_file.txt', 'remote_file_v2.txt')
           
           # Delete a remote file
           sftp.remove('remote_file_v2.txt')
           
   finally:
       client.close()
