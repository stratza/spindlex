Protocol API
============

Protocol Messages
-----------------

.. automodule:: ssh_library.protocol.messages
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.Message
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.DisconnectMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.ServiceRequestMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.ServiceAcceptMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.UserauthRequestMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.UserauthSuccessMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.UserauthFailureMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.ChannelOpenMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.ChannelOpenConfirmationMessage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.protocol.messages.ChannelDataMessage
   :members:
   :undoc-members:
   :show-inheritance:

Protocol Constants
------------------

.. automodule:: ssh_library.protocol.constants
   :members:
   :undoc-members:
   :show-inheritance:

Message Types::

    # Connection protocol
    MSG_DISCONNECT = 1
    MSG_IGNORE = 2
    MSG_UNIMPLEMENTED = 3
    MSG_DEBUG = 4
    MSG_SERVICE_REQUEST = 5
    MSG_SERVICE_ACCEPT = 6
    
    # Key exchange
    MSG_KEXINIT = 20
    MSG_NEWKEYS = 21
    
    # User authentication
    MSG_USERAUTH_REQUEST = 50
    MSG_USERAUTH_FAILURE = 51
    MSG_USERAUTH_SUCCESS = 52
    MSG_USERAUTH_BANNER = 53
    
    # Connection protocol
    MSG_GLOBAL_REQUEST = 80
    MSG_REQUEST_SUCCESS = 81
    MSG_REQUEST_FAILURE = 82
    MSG_CHANNEL_OPEN = 90
    MSG_CHANNEL_OPEN_CONFIRMATION = 91
    MSG_CHANNEL_OPEN_FAILURE = 92
    MSG_CHANNEL_WINDOW_ADJUST = 93
    MSG_CHANNEL_DATA = 94
    MSG_CHANNEL_EXTENDED_DATA = 95
    MSG_CHANNEL_EOF = 96
    MSG_CHANNEL_CLOSE = 97
    MSG_CHANNEL_REQUEST = 98
    MSG_CHANNEL_SUCCESS = 99
    MSG_CHANNEL_FAILURE = 100

Disconnect Reason Codes::

    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
    SSH_DISCONNECT_PROTOCOL_ERROR = 2
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3
    SSH_DISCONNECT_RESERVED = 4
    SSH_DISCONNECT_MAC_ERROR = 5
    SSH_DISCONNECT_COMPRESSION_ERROR = 6
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
    SSH_DISCONNECT_CONNECTION_LOST = 10
    SSH_DISCONNECT_BY_APPLICATION = 11
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15

Example Usage
-------------

Creating Protocol Messages::

    from ssh_library.protocol.messages import (
        ServiceRequestMessage, 
        UserauthRequestMessage,
        ChannelOpenMessage
    )
    
    # Service request
    service_msg = ServiceRequestMessage('ssh-userauth')
    packed_data = service_msg.pack()
    
    # Authentication request
    auth_msg = UserauthRequestMessage(
        username='user',
        service='ssh-connection',
        method='password',
        password='secret'
    )
    
    # Channel open
    channel_msg = ChannelOpenMessage(
        channel_type='session',
        sender_channel=0,
        initial_window_size=32768,
        maximum_packet_size=32768
    )

Parsing Protocol Messages::

    from ssh_library.protocol.messages import Message
    from ssh_library.protocol.constants import MSG_CHANNEL_DATA
    
    # Parse incoming message
    message_type, payload = Message.parse_message(raw_data)
    
    if message_type == MSG_CHANNEL_DATA:
        channel_data_msg = ChannelDataMessage.unpack(payload)
        print(f"Channel {channel_data_msg.recipient_channel}: {channel_data_msg.data}")

Protocol Utilities::

    from ssh_library.protocol.utils import (
        pack_string,
        unpack_string,
        pack_uint32,
        unpack_uint32,
        pack_boolean,
        unpack_boolean
    )
    
    # Pack data
    packed = pack_string(b"hello") + pack_uint32(42) + pack_boolean(True)
    
    # Unpack data
    offset = 0
    string_val, offset = unpack_string(packed, offset)
    uint_val, offset = unpack_uint32(packed, offset)
    bool_val, offset = unpack_boolean(packed, offset)