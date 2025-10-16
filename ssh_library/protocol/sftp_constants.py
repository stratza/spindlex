"""
SFTP Protocol Constants

Defines SFTP protocol constants, message types, and error codes
according to RFC 4254 and draft-ietf-secsh-filexfer specifications.
"""

# SFTP Protocol Version
SFTP_VERSION = 3

# SFTP Message Types
SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_SETSTAT = 9
SSH_FXP_FSETSTAT = 10
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_REMOVE = 13
SSH_FXP_MKDIR = 14
SSH_FXP_RMDIR = 15
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17
SSH_FXP_RENAME = 18
SSH_FXP_READLINK = 19
SSH_FXP_SYMLINK = 20

# SFTP Response Message Types
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

# SFTP Status Codes
SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4
SSH_FX_BAD_MESSAGE = 5
SSH_FX_NO_CONNECTION = 6
SSH_FX_CONNECTION_LOST = 7
SSH_FX_OP_UNSUPPORTED = 8

# SFTP File Open Flags
SSH_FXF_READ = 0x00000001
SSH_FXF_WRITE = 0x00000002
SSH_FXF_APPEND = 0x00000004
SSH_FXF_CREAT = 0x00000008
SSH_FXF_TRUNC = 0x00000010
SSH_FXF_EXCL = 0x00000020

# SFTP File Attribute Flags
SSH_FILEXFER_ATTR_SIZE = 0x00000001
SSH_FILEXFER_ATTR_UIDGID = 0x00000002
SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004
SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008
SSH_FILEXFER_ATTR_EXTENDED = 0x80000000

# SFTP File Types (from file permissions)
SSH_FILEXFER_TYPE_REGULAR = 0o100000
SSH_FILEXFER_TYPE_DIRECTORY = 0o040000
SSH_FILEXFER_TYPE_SYMLINK = 0o120000
SSH_FILEXFER_TYPE_SPECIAL = 0o060000
SSH_FILEXFER_TYPE_UNKNOWN = 0o000000

# Default Values
SFTP_MAX_PACKET_SIZE = 32768  # 32KB
SFTP_MAX_READ_SIZE = 32768    # 32KB per read request
SFTP_DEFAULT_BUFFER_SIZE = 32768

# SFTP Subsystem Name
SFTP_SUBSYSTEM = "sftp"

# Status Code Messages
SFTP_STATUS_MESSAGES = {
    SSH_FX_OK: "Success",
    SSH_FX_EOF: "End of file",
    SSH_FX_NO_SUCH_FILE: "No such file or directory",
    SSH_FX_PERMISSION_DENIED: "Permission denied",
    SSH_FX_FAILURE: "Failure",
    SSH_FX_BAD_MESSAGE: "Bad message",
    SSH_FX_NO_CONNECTION: "No connection",
    SSH_FX_CONNECTION_LOST: "Connection lost",
    SSH_FX_OP_UNSUPPORTED: "Operation unsupported",
}


def get_status_message(status_code: int) -> str:
    """
    Get human-readable message for SFTP status code.
    
    Args:
        status_code: SFTP status code
        
    Returns:
        Human-readable status message
    """
    return SFTP_STATUS_MESSAGES.get(status_code, f"Unknown status code: {status_code}")


def is_success_status(status_code: int) -> bool:
    """
    Check if SFTP status code indicates success.
    
    Args:
        status_code: SFTP status code
        
    Returns:
        True if status indicates success
    """
    return status_code == SSH_FX_OK


def validate_sftp_message_type(msg_type: int) -> bool:
    """
    Validate SFTP message type.
    
    Args:
        msg_type: SFTP message type code
        
    Returns:
        True if message type is valid
    """
    valid_types = {
        SSH_FXP_INIT, SSH_FXP_VERSION, SSH_FXP_OPEN, SSH_FXP_CLOSE,
        SSH_FXP_READ, SSH_FXP_WRITE, SSH_FXP_LSTAT, SSH_FXP_FSTAT,
        SSH_FXP_SETSTAT, SSH_FXP_FSETSTAT, SSH_FXP_OPENDIR, SSH_FXP_READDIR,
        SSH_FXP_REMOVE, SSH_FXP_MKDIR, SSH_FXP_RMDIR, SSH_FXP_REALPATH,
        SSH_FXP_STAT, SSH_FXP_RENAME, SSH_FXP_READLINK, SSH_FXP_SYMLINK,
        SSH_FXP_STATUS, SSH_FXP_HANDLE, SSH_FXP_DATA, SSH_FXP_NAME, SSH_FXP_ATTRS
    }
    return msg_type in valid_types


def get_message_name(msg_type: int) -> str:
    """
    Get human-readable name for SFTP message type.
    
    Args:
        msg_type: SFTP message type code
        
    Returns:
        Message type name or "UNKNOWN" if not recognized
    """
    message_names = {
        SSH_FXP_INIT: "SSH_FXP_INIT",
        SSH_FXP_VERSION: "SSH_FXP_VERSION",
        SSH_FXP_OPEN: "SSH_FXP_OPEN",
        SSH_FXP_CLOSE: "SSH_FXP_CLOSE",
        SSH_FXP_READ: "SSH_FXP_READ",
        SSH_FXP_WRITE: "SSH_FXP_WRITE",
        SSH_FXP_LSTAT: "SSH_FXP_LSTAT",
        SSH_FXP_FSTAT: "SSH_FXP_FSTAT",
        SSH_FXP_SETSTAT: "SSH_FXP_SETSTAT",
        SSH_FXP_FSETSTAT: "SSH_FXP_FSETSTAT",
        SSH_FXP_OPENDIR: "SSH_FXP_OPENDIR",
        SSH_FXP_READDIR: "SSH_FXP_READDIR",
        SSH_FXP_REMOVE: "SSH_FXP_REMOVE",
        SSH_FXP_MKDIR: "SSH_FXP_MKDIR",
        SSH_FXP_RMDIR: "SSH_FXP_RMDIR",
        SSH_FXP_REALPATH: "SSH_FXP_REALPATH",
        SSH_FXP_STAT: "SSH_FXP_STAT",
        SSH_FXP_RENAME: "SSH_FXP_RENAME",
        SSH_FXP_READLINK: "SSH_FXP_READLINK",
        SSH_FXP_SYMLINK: "SSH_FXP_SYMLINK",
        SSH_FXP_STATUS: "SSH_FXP_STATUS",
        SSH_FXP_HANDLE: "SSH_FXP_HANDLE",
        SSH_FXP_DATA: "SSH_FXP_DATA",
        SSH_FXP_NAME: "SSH_FXP_NAME",
        SSH_FXP_ATTRS: "SSH_FXP_ATTRS",
    }
    
    return message_names.get(msg_type, f"UNKNOWN({msg_type})")