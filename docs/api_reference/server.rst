Server API
==========

SSH Server
----------

.. automodule:: spindlex.server.ssh_server
   :members:
   :undoc-members:
   :show-inheritance:

SFTP Server
-----------

.. automodule:: spindlex.server.sftp_server
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic SSH Server::

    from spindlex import SSHServer
    from spindlex.crypto.pkey import Ed25519Key
    
    class MySSHServer(SSHServer):
        def check_auth_password(self, username, password):
            # Return auth status
            return True
        
        def check_channel_request(self, kind, chanid):
            return 0 # OPEN_SUCCEEDED
    
    # Create server instance
    server = MySSHServer()

SFTP Server::

    from spindlex.server import SFTPServer
    import os
    
    class MyFileServer(SFTPServer):
        def list_folder(self, path):
            try:
                return os.listdir(path)
            except OSError:
                return []
