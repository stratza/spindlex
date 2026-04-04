Protocol API
============

Protocol Messages
-----------------

.. automodule:: spindlex.protocol.messages
   :members:
   :undoc-members:
   :show-inheritance:

Protocol Utilities
------------------

.. automodule:: spindlex.protocol.utils
   :members:
   :undoc-members:
   :show-inheritance:

Constants
---------

.. automodule:: spindlex.protocol.constants
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Message Packing and Unpacking::

    from spindlex.protocol.messages import ServiceRequestMessage, Message
    from spindlex.protocol.constants import MSG_SERVICE_REQUEST
    
    # Create and pack message
    msg = ServiceRequestMessage("ssh-userauth")
    packed_data = msg.pack()
    
    # Unpack message
    unpacked_msg = Message.unpack(packed_data)
    print(unpacked_msg.service_name)

Low-level Utils::

    from spindlex.protocol.utils import write_uint32, read_uint32
    
    # Write uint32
    data = write_uint32(42)
    
    # Read uint32
    val, offset = read_uint32(data, 0)
    assert val == 42
