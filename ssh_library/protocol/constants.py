"""
SSH Protocol Constants

Defines SSH protocol constants, message types, and error codes
according to RFC 4251-4254 specifications.
"""

# SSH Protocol Version
SSH_VERSION = "SSH-2.0"

# SSH Message Types (RFC 4253)
MSG_DISCONNECT = 1
MSG_IGNORE = 2
MSG_UNIMPLEMENTED = 3
MSG_DEBUG = 4
MSG_SERVICE_REQUEST = 5
MSG_SERVICE_ACCEPT = 6

# Key Exchange Messages (RFC 4253)
MSG_KEXINIT = 20
MSG_NEWKEYS = 21

# Key Exchange Method Specific Messages (30-41)
MSG_KEXDH_INIT = 30
MSG_KEXDH_REPLY = 31

# User Authentication Messages (RFC 4252)
MSG_USERAUTH_REQUEST = 50
MSG_USERAUTH_FAILURE = 51
MSG_USERAUTH_SUCCESS = 52
MSG_USERAUTH_BANNER = 53

# User Authentication Method Specific Messages (60-79)
MSG_USERAUTH_PK_OK = 60
MSG_USERAUTH_PASSWD_CHANGEREQ = 60
MSG_USERAUTH_INFO_REQUEST = 60
MSG_USERAUTH_INFO_RESPONSE = 61
MSG_USERAUTH_GSSAPI_RESPONSE = 60
MSG_USERAUTH_GSSAPI_TOKEN = 61
MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63
MSG_USERAUTH_GSSAPI_ERROR = 64
MSG_USERAUTH_GSSAPI_ERRTOK = 65
MSG_USERAUTH_GSSAPI_MIC = 66

# Connection Protocol Messages (RFC 4254)
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

# Disconnect Reason Codes (RFC 4253)
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

# Channel Open Failure Reason Codes (RFC 4254)
SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
SSH_OPEN_CONNECT_FAILED = 2
SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3
SSH_OPEN_RESOURCE_SHORTAGE = 4

# Extended Data Type Codes (RFC 4254)
SSH_EXTENDED_DATA_STDERR = 1

# Authentication Method Names
AUTH_PASSWORD = "password"
AUTH_PUBLICKEY = "publickey"
AUTH_HOSTBASED = "hostbased"
AUTH_KEYBOARD_INTERACTIVE = "keyboard-interactive"
AUTH_GSSAPI_WITH_MIC = "gssapi-with-mic"

# Service Names
SERVICE_USERAUTH = "ssh-userauth"
SERVICE_CONNECTION = "ssh-connection"

# Channel Types
CHANNEL_SESSION = "session"
CHANNEL_DIRECT_TCPIP = "direct-tcpip"
CHANNEL_FORWARDED_TCPIP = "forwarded-tcpip"

# Default Values
DEFAULT_WINDOW_SIZE = 2097152  # 2MB
DEFAULT_MAX_PACKET_SIZE = 32768  # 32KB
DEFAULT_PORT = 22

# Algorithm Names
KEX_CURVE25519_SHA256 = "curve25519-sha256"
KEX_ECDH_SHA2_NISTP256 = "ecdh-sha2-nistp256"
KEX_DH_GROUP14_SHA256 = "diffie-hellman-group14-sha256"

HOSTKEY_ED25519 = "ssh-ed25519"
HOSTKEY_ECDSA_SHA2_NISTP256 = "ecdsa-sha2-nistp256"
HOSTKEY_RSA_SHA2_256 = "rsa-sha2-256"

CIPHER_CHACHA20_POLY1305 = "chacha20-poly1305@openssh.com"
CIPHER_AES256_GCM = "aes256-gcm@openssh.com"
CIPHER_AES128_GCM = "aes128-gcm@openssh.com"
CIPHER_AES256_CTR = "aes256-ctr"

MAC_HMAC_SHA2_256 = "hmac-sha2-256"
MAC_HMAC_SHA2_512 = "hmac-sha2-512"

COMPRESS_NONE = "none"
COMPRESS_ZLIB = "zlib@openssh.com"

# Protocol Version Information
SSH_PROTOCOL_VERSION_1 = "1.99"
SSH_PROTOCOL_VERSION_2 = "2.0"
SUPPORTED_PROTOCOL_VERSIONS = [SSH_PROTOCOL_VERSION_2]

# Maximum message and packet sizes
MAX_PACKET_SIZE = 35000  # RFC 4253 section 6.1
MAX_MESSAGE_SIZE = 262144  # 256KB

# Timeout values (in seconds)
DEFAULT_CONNECT_TIMEOUT = 30
DEFAULT_AUTH_TIMEOUT = 30
DEFAULT_BANNER_TIMEOUT = 15

# String encoding
SSH_STRING_ENCODING = "utf-8"

# Message validation constants
MIN_PACKET_SIZE = 16  # Minimum SSH packet size
PACKET_LENGTH_SIZE = 4  # Size of packet length field
PADDING_LENGTH_SIZE = 1  # Size of padding length field
MIN_PADDING_SIZE = 4  # Minimum padding size
MAX_PADDING_SIZE = 255  # Maximum padding size

# Key exchange specific constants
KEX_COOKIE_SIZE = 16  # Size of random cookie in KEXINIT

# Authentication constants
MAX_AUTH_ATTEMPTS = 6  # Maximum authentication attempts
AUTH_PARTIAL_SUCCESS = "partial success"

# Authentication result codes
AUTH_SUCCESSFUL = 0
AUTH_FAILED = 1
AUTH_PARTIAL = 2

# Channel constants
CHANNEL_WINDOW_ADJUST_SIZE = 1048576  # 1MB
MAX_CHANNELS = 100  # Maximum number of channels per connection

# SFTP constants (will be used in later tasks)
SFTP_VERSION = 3
SFTP_MAX_PACKET_SIZE = 32768

# Error message templates
ERROR_PROTOCOL_MISMATCH = "Protocol version mismatch"
ERROR_INVALID_MESSAGE = "Invalid message format"
ERROR_UNSUPPORTED_ALGORITHM = "Unsupported algorithm"
ERROR_AUTH_FAILED = "Authentication failed"
ERROR_CHANNEL_FAILED = "Channel operation failed"

def parse_version_string(version_line: str) -> tuple[str, str]:
    """
    Parse SSH version string.
    
    Args:
        version_line: SSH version line (e.g., "SSH-2.0-OpenSSH_8.0")
        
    Returns:
        Tuple of (protocol_version, software_version)
        
    Raises:
        ValueError: If version string is invalid
    """
    if not version_line.startswith("SSH-"):
        raise ValueError(f"Invalid SSH version string: {version_line}")
    
    parts = version_line.split("-", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid SSH version string format: {version_line}")
    
    protocol_version = parts[1]
    software_version = parts[2] if len(parts) > 2 else ""
    
    return protocol_version, software_version


def is_supported_version(protocol_version: str) -> bool:
    """
    Check if protocol version is supported.
    
    Args:
        protocol_version: Protocol version string (e.g., "2.0")
        
    Returns:
        True if version is supported, False otherwise
    """
    return protocol_version in SUPPORTED_PROTOCOL_VERSIONS


def create_version_string(software_name: str = "ssh_library", software_version: str = "1.0") -> str:
    """
    Create SSH version string for this implementation.
    
    Args:
        software_name: Name of SSH software
        software_version: Version of SSH software
        
    Returns:
        Complete SSH version string
    """
    return f"SSH-{SSH_PROTOCOL_VERSION_2}-{software_name}_{software_version}"


def validate_message_type(msg_type: int) -> bool:
    """
    Validate SSH message type.
    
    Args:
        msg_type: Message type code
        
    Returns:
        True if message type is valid, False otherwise
    """
    # Valid message type ranges according to RFC 4250
    return (
        (1 <= msg_type <= 19) or      # Transport layer generic
        (20 <= msg_type <= 29) or     # Algorithm negotiation
        (30 <= msg_type <= 41) or     # Key exchange method specific
        (50 <= msg_type <= 59) or     # User authentication generic
        (60 <= msg_type <= 79) or     # User authentication method specific
        (80 <= msg_type <= 89) or     # Connection protocol generic
        (90 <= msg_type <= 127) or    # Channel related messages
        (128 <= msg_type <= 191) or   # Reserved for client protocols
        (192 <= msg_type <= 255)      # Local extensions
    )


def get_message_name(msg_type: int) -> str:
    """
    Get human-readable name for message type.
    
    Args:
        msg_type: Message type code
        
    Returns:
        Message type name or "UNKNOWN" if not recognized
    """
    message_names = {
        MSG_DISCONNECT: "MSG_DISCONNECT",
        MSG_IGNORE: "MSG_IGNORE",
        MSG_UNIMPLEMENTED: "MSG_UNIMPLEMENTED",
        MSG_DEBUG: "MSG_DEBUG",
        MSG_SERVICE_REQUEST: "MSG_SERVICE_REQUEST",
        MSG_SERVICE_ACCEPT: "MSG_SERVICE_ACCEPT",
        MSG_KEXINIT: "MSG_KEXINIT",
        MSG_NEWKEYS: "MSG_NEWKEYS",
        MSG_KEXDH_INIT: "MSG_KEXDH_INIT",
        MSG_KEXDH_REPLY: "MSG_KEXDH_REPLY",
        MSG_USERAUTH_REQUEST: "MSG_USERAUTH_REQUEST",
        MSG_USERAUTH_FAILURE: "MSG_USERAUTH_FAILURE",
        MSG_USERAUTH_SUCCESS: "MSG_USERAUTH_SUCCESS",
        MSG_USERAUTH_BANNER: "MSG_USERAUTH_BANNER",
        MSG_USERAUTH_PK_OK: "MSG_USERAUTH_PK_OK",
        MSG_GLOBAL_REQUEST: "MSG_GLOBAL_REQUEST",
        MSG_REQUEST_SUCCESS: "MSG_REQUEST_SUCCESS",
        MSG_REQUEST_FAILURE: "MSG_REQUEST_FAILURE",
        MSG_CHANNEL_OPEN: "MSG_CHANNEL_OPEN",
        MSG_CHANNEL_OPEN_CONFIRMATION: "MSG_CHANNEL_OPEN_CONFIRMATION",
        MSG_CHANNEL_OPEN_FAILURE: "MSG_CHANNEL_OPEN_FAILURE",
        MSG_CHANNEL_WINDOW_ADJUST: "MSG_CHANNEL_WINDOW_ADJUST",
        MSG_CHANNEL_DATA: "MSG_CHANNEL_DATA",
        MSG_CHANNEL_EXTENDED_DATA: "MSG_CHANNEL_EXTENDED_DATA",
        MSG_CHANNEL_EOF: "MSG_CHANNEL_EOF",
        MSG_CHANNEL_CLOSE: "MSG_CHANNEL_CLOSE",
        MSG_CHANNEL_REQUEST: "MSG_CHANNEL_REQUEST",
        MSG_CHANNEL_SUCCESS: "MSG_CHANNEL_SUCCESS",
        MSG_CHANNEL_FAILURE: "MSG_CHANNEL_FAILURE",
    }
    
    return message_names.get(msg_type, f"UNKNOWN({msg_type})")