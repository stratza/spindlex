SSH Library Documentation
=========================

Welcome to SSH Library's documentation! SSH Library is a pure-Python SSHv2 client/server library that provides secure, high-performance SSH and SFTP operations without GPL/LGPL dependencies.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   user_guide/index
   api_reference/index
   examples/index
   security
   performance
   contributing
   changelog

Features
--------

* **Pure Python**: No C extensions or system dependencies
* **Modern Security**: Ed25519, ECDSA, ChaCha20-Poly1305, and other modern algorithms
* **Full SSH Support**: Client and server implementations with all major features
* **SFTP Support**: Complete SFTP client and server functionality
* **Async Support**: Optional asyncio support for high-performance applications
* **Comprehensive**: Port forwarding, authentication methods, host key policies
* **Well-Tested**: Extensive test suite with high code coverage
* **Type Hints**: Fully typed codebase for better development experience

Quick Start
-----------

Install SSH Library:

.. code-block:: bash

   pip install ssh-library

Basic SSH client usage:

.. code-block:: python

   from ssh_library import SSHClient

   # Create client and connect
   client = SSHClient()
   client.connect('example.com', username='user', password='password')

   # Execute a command
   stdin, stdout, stderr = client.exec_command('ls -la')
   print(stdout.read().decode())

   # Use SFTP
   sftp = client.open_sftp()
   sftp.get('/remote/file.txt', '/local/file.txt')
   sftp.close()

   # Clean up
   client.close()

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`