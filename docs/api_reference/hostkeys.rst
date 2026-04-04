Host Keys API
=============

Host Key Storage
----------------

.. automodule:: spindlex.hostkeys.storage
   :members:
   :undoc-members:
   :show-inheritance:

Host Key Policies
-----------------

.. automodule:: spindlex.hostkeys.policy
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Manage Host Keys::

    from spindlex.hostkeys.storage import HostKeyStorage
    from spindlex.hostkeys.policy import AutoAddPolicy
    
    # Load host keys
    storage = HostKeyStorage('~/.ssh/known_hosts')
    
    # Get host key for a host
    key = storage.get('example.com')
    
    # Use policy
    policy = AutoAddPolicy()
    # policy.missing_host_key(client, 'example.com', key)
