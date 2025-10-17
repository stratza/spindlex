# 📖 API Reference

Complete API documentation for SpindleX classes and methods.

## 🔌 SSH Client Classes

### SSHClient
Main SSH client class for synchronous operations.

```python
from spindlex import SSHClient

client = SSHClient()
```

#### Methods

**connect(hostname, port=22, username=None, password=None, pkey=None, timeout=None)**
- Connect to SSH server
- Returns: None
- Raises: AuthenticationException, BadHostKeyException, SSHException

**exec_command(command, bufsize=-1)**
- Execute command on remote server
- Returns: (stdin, stdout, stderr) tuple
- Raises: SSHException

**invoke_shell(term='vt100', width=80, height=24)**
- Start interactive shell session
- Returns: Channel object
- Raises: SSHException

**open_sftp()**
- Open SFTP session
- Returns: SFTPClient object
- Raises: SSHException

**close()**
- Close SSH connection
- Returns: None

### AsyncSSHClient
Async version of SSH client.

```python
from spindlex import AsyncSSHClient

async with AsyncSSHClient() as client:
    await client.connect('server.com', username='user', password='pass')
```

## 📁 SFTP Classes

### SFTPClient
SFTP client for file operations.

#### Methods

**get(remotepath, localpath)**
- Download file from remote server
- Returns: None
- Raises: SFTPError

**put(localpath, remotepath)**
- Upload file to remote server
- Returns: None
- Raises: SFTPError

**listdir(path='.')**
- List directory contents
- Returns: List[str]
- Raises: SFTPError

**stat(path)**
- Get file/directory attributes
- Returns: SFTPAttributes
- Raises: SFTPError

**mkdir(path, mode=0o777)**
- Create directory
- Returns: None
- Raises: SFTPError

## 🔐 Cryptography Classes

### Ed25519Key
Ed25519 private key class.

```python
from spindlex.crypto.pkey import Ed25519Key

key = Ed25519Key.from_private_key_file('~/.ssh/id_ed25519')
```

### RSAKey
RSA private key class.

```python
from spindlex.crypto.pkey import RSAKey

key = RSAKey.from_private_key_file('~/.ssh/id_rsa')
```

## 🚨 Exception Classes

### SSHException
Base exception for all SSH-related errors.

### AuthenticationException
Raised when authentication fails.

### BadHostKeyException
Raised when host key verification fails.

### SFTPError
Raised when SFTP operations fail.

## 📚 Complete Documentation

For complete API documentation with all parameters and examples, visit:
- [Online Documentation](https://spindlex.readthedocs.io/en/latest/api_reference/)
- [Source Code](https://gitlab.com/daveops.world/development/python/spindlex)