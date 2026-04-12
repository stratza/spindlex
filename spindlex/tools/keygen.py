#!/usr/bin/env python3
"""
SSH key generation tool.

A simple command-line tool for generating SSH key pairs (part of Spindle).
"""

import argparse
import sys
from pathlib import Path
from typing import Any, Optional

from ..crypto.pkey import ECDSAKey, Ed25519Key, RSAKey


def generate_key(
    key_type: str, bits: Optional[int] = None, comment: Optional[str] = None
) -> tuple[Any, Any]:
    """Generate a new SSH key pair."""
    from ..crypto.pkey import PKey

    key: PKey
    if key_type == "ed25519":
        key = Ed25519Key.generate()
    elif key_type == "ecdsa":
        key = ECDSAKey.generate()
    elif key_type == "rsa":
        key_size = bits or 2048
        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits")
        key = RSAKey.generate(bits=key_size)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

    return key, key.get_public_key()


def save_key_pair(
    private_key: Any, public_key: Any, filename: str, comment: Optional[str] = None
) -> None:
    """Save the key pair to files."""
    private_path = Path(filename)
    public_path = Path(f"{filename}.pub")

    # Save private key
    private_key.save_to_file(str(private_path))
    private_path.chmod(0o600)  # Secure permissions

    # Save public key
    public_key_str = public_key.get_openssh_string()
    if comment:
        public_key_str += f" {comment}"

    public_path.write_text(public_key_str + "\n")
    public_path.chmod(0o644)

    print(f"Private key saved to: {private_path}")
    print(f"Public key saved to: {public_path}")


def main() -> None:
    """Main entry point for ssh-keygen tool."""
    parser = argparse.ArgumentParser(
        description="Generate SSH key pairs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  spindle-keygen -t ed25519 -f ~/.ssh/id_ed25519
  spindle-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -C "user@example.com"
  spindle-keygen -t ecdsa -f ~/.ssh/id_ecdsa
        """,
    )

    parser.add_argument(
        "-t",
        "--type",
        choices=["ed25519", "ecdsa", "rsa"],
        default="ed25519",
        help="Key type to generate (default: ed25519)",
    )

    parser.add_argument(
        "-b", "--bits", type=int, help="Number of bits for RSA keys (minimum 2048)"
    )

    parser.add_argument(
        "-f", "--filename", required=True, help="Output filename for the private key"
    )

    parser.add_argument("-C", "--comment", help="Comment to add to the public key")

    parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing key files"
    )

    args = parser.parse_args()

    # Check if files already exist
    private_path = Path(args.filename)
    public_path = Path(f"{args.filename}.pub")

    if not args.overwrite:
        if private_path.exists():
            print(f"Error: Private key file already exists: {private_path}")
            sys.exit(1)
        if public_path.exists():
            print(f"Error: Public key file already exists: {public_path}")
            sys.exit(1)

    try:
        # Generate key pair
        print(f"Generating {args.type} key pair...")
        private_key, public_key = generate_key(args.type, args.bits, args.comment)

        # Save key pair
        save_key_pair(private_key, public_key, args.filename, args.comment)

        # Show fingerprint
        fingerprint = public_key.get_fingerprint()
        print(f"Key fingerprint: {fingerprint}")
        print("Generated with Spindle SSH key generator")

    except Exception as e:
        print(f"Error generating key: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
