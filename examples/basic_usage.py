#!/usr/bin/env python3
"""
Basic SpindleX Usage Examples

This module demonstrates fundamental SSH operations using SpindleX.

Security notes
--------------
All examples use the secure-by-default ``RejectPolicy`` host-key policy.
Before running these examples, make sure the target server's host key is
already recorded in your ``known_hosts`` file — e.g. by connecting once
with OpenSSH (``ssh user@host``) or by calling
``client.get_host_keys().load()``.

Do **not** replace the policy with ``AutoAddPolicy`` outside of short-lived
disposable test environments: it trusts every first-seen key and disables
MITM protection.
"""

from spindlex import SSHClient
from spindlex.crypto.pkey import PKey
from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    ChannelException,
    SSHException,
)
from spindlex.hostkeys.policy import RejectPolicy


def _configure_client(client: SSHClient) -> None:
    """
    Apply secure defaults to an SSHClient instance.

    The default policy is already ``RejectPolicy``; we set it explicitly to
    make the security posture obvious in the example, and we load the user's
    known_hosts file so verification can succeed.
    """
    client.set_missing_host_key_policy(RejectPolicy())
    # Populate storage from the user's ~/.ssh/known_hosts (best-effort: the
    # HostKeyStorage constructor already attempts this, but we trigger a
    # reload explicitly so failures surface as warnings, not silent gaps).
    try:
        client.get_host_keys().load()
    except SSHException as exc:
        # Not fatal — just means no known_hosts entries are available and
        # every connection will be rejected unless the caller adds one.
        print(f"Warning: could not load known_hosts: {exc}")


def basic_connection_example():
    """Demonstrate basic SSH connection and command execution."""
    print("=== Basic Connection Example ===")

    client = SSHClient()
    _configure_client(client)

    try:
        # Connect to server
        client.connect(
            hostname="example.com", username="demo", password="password", timeout=10
        )

        print("Connected successfully!")

        # Execute a simple command
        stdin, stdout, stderr = client.exec_command("uname -a")

        # Read and display output
        output = stdout.read().decode("utf-8").strip()
        error = stderr.read().decode("utf-8").strip()
        exit_code = stdout.channel.get_exit_status()

        print(f"Command output: {output}")
        if error:
            print(f"Command error: {error}")
        print(f"Exit code: {exit_code}")

    except AuthenticationException:
        print("Authentication failed - check your credentials")
    except BadHostKeyException as e:
        print(f"Host key verification failed: {e}")
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()
        print("Connection closed")


def key_based_authentication_example():
    """Demonstrate SSH key-based authentication."""
    print("\n=== Key-Based Authentication Example ===")

    # Generate a new key pair for demonstration
    private_key = PKey.generate("ed25519")

    # In practice, you would load an existing key:
    # private_key = PKey.from_private_key_file('/path/to/private_key')

    client = SSHClient()
    _configure_client(client)

    try:
        client.connect(hostname="example.com", username="demo", pkey=private_key)

        print("Connected with SSH key!")

        # Execute command
        stdin, stdout, stderr = client.exec_command("whoami")
        username = stdout.read().decode("utf-8").strip()
        print(f"Logged in as: {username}")

    except AuthenticationException:
        print("Key authentication failed")
    except BadHostKeyException as e:
        print(f"Host key verification failed: {e}")
    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def multiple_commands_example():
    """Demonstrate executing multiple commands on the same connection."""
    print("\n=== Multiple Commands Example ===")

    client = SSHClient()
    _configure_client(client)

    try:
        client.connect(hostname="example.com", username="demo", password="password")

        commands = ["date", "pwd", "ls -la", "df -h"]

        for cmd in commands:
            print(f"\nExecuting: {cmd}")
            stdin, stdout, stderr = client.exec_command(cmd)

            output = stdout.read().decode("utf-8").strip()
            print(f"Output: {output}")

    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def interactive_shell_example():
    """Demonstrate using an interactive shell."""
    print("\n=== Interactive Shell Example ===")

    client = SSHClient()
    _configure_client(client)

    try:
        client.connect(hostname="example.com", username="demo", password="password")

        # Start interactive shell
        shell = client.invoke_shell()
        shell.settimeout(1.0)  # Set a short timeout for reading

        # Send commands
        commands = ["ls\n", "pwd\n", "exit\n"]

        for cmd in commands:
            shell.send(cmd)

            # Wait for output
            import time

            time.sleep(1)

            # Read available output
            try:
                output = shell.recv(1024).decode("utf-8")
                print(f"Shell output: {output}")
            except (SSHException, ChannelException):
                # Timeout or other error, ignore
                pass

        shell.close()

    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def context_manager_example():
    """Demonstrate using SSH client as a context manager."""
    print("\n=== Context Manager Example ===")

    try:
        with SSHClient() as client:
            _configure_client(client)
            client.connect(hostname="example.com", username="demo", password="password")

            print("Connected using context manager")

            stdin, stdout, stderr = client.exec_command(
                'echo "Hello from context manager"'
            )
            output = stdout.read().decode("utf-8").strip()
            print(f"Output: {output}")

        print("Connection automatically closed")

    except SSHException as e:
        print(f"SSH error: {e}")


def error_handling_example():
    """Demonstrate proper error handling."""
    print("\n=== Error Handling Example ===")

    client = SSHClient()
    # Strict host key checking is the default; shown here to reinforce intent.
    client.set_missing_host_key_policy(RejectPolicy())

    try:
        # This will likely fail due to strict host key policy
        client.connect(
            hostname="unknown-host.example.com",
            username="demo",
            password="wrongpassword",
            timeout=5,
        )

    except AuthenticationException:
        print("Authentication failed - credentials are incorrect")
    except BadHostKeyException as e:
        print(f"Host key verification failed: {e}")
    except SSHException as e:
        print(f"SSH connection failed: {e}")
    finally:
        client.close()


def connection_info_example():
    """Demonstrate getting connection information."""
    print("\n=== Connection Information Example ===")

    client = SSHClient()
    _configure_client(client)

    try:
        client.connect(hostname="example.com", username="demo", password="password")

        # Get transport information
        transport = client.get_transport()
        if transport is None:
            print("No transport available")
            return

        print(f"Connected: {transport.active}")

        # Get host key information
        host_key = transport.get_server_host_key()
        if host_key is not None:
            print(f"Host key type: {host_key.get_name()}")
            print(f"Host key fingerprint: {host_key.get_fingerprint()}")

    except SSHException as e:
        print(f"SSH error: {e}")
    finally:
        client.close()


def main():
    """Run all examples."""
    print("SpindleX Basic Usage Examples")
    print("=" * 40)

    examples = [
        basic_connection_example,
        key_based_authentication_example,
        multiple_commands_example,
        interactive_shell_example,
        context_manager_example,
        error_handling_example,
        connection_info_example,
    ]

    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"Example failed: {e}")
        print()  # Add spacing between examples


if __name__ == "__main__":
    main()
