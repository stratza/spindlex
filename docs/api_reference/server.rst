Server API
==========

SSH Server
----------

.. automodule:: ssh_library.server.ssh_server
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.server.ssh_server.SSHServer
   :members:
   :undoc-members:
   :show-inheritance:

SFTP Server
-----------

.. automodule:: ssh_library.server.sftp_server
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.server.sftp_server.SFTPServer
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.server.sftp_server.SFTPHandle
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.server.sftp_server.SFTPAttributes
   :members:
   :undoc-members:
   :show-inheritance:

Server Interface
----------------

.. automodule:: ssh_library.server
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic SSH Server::

    from ssh_library import SSHServer
    from ssh_library.crypto.pkey import Ed25519Key
    
    class MySSHServer(SSHServer):
        def check_auth_password(self, username, password):
            if username == 'admin' and password == 'secret':
                return self.AUTH_SUCCESSFUL
            return self.AUTH_FAILED
        
        def check_channel_request(self, kind, chanid):
            return self.OPEN_SUCCEEDED
    
    # Create server with host key
    host_key = Ed25519Key.generate()
    server = MySSHServer()
    
    # Start server (implementation depends on transport setup)

SFTP Server::

    from ssh_library.server import SFTPServer
    import os
    
    class MyFileServer(SFTPServer):
        def list_folder(self, path):
            try:
                files = os.listdir(path)
                return [SFTPAttributes.from_stat(os.stat(os.path.join(path, f)), f) 
                        for f in files]
            except OSError:
                return []
        
        def stat(self, path):
            try:
                return SFTPAttributes.from_stat(os.stat(path))
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)