"""
Log sanitization utilities for security-sensitive information.
"""

import re
from typing import Any, Pattern


class LogSanitizer:
    """Sanitizes log messages to prevent sensitive information leakage."""

    # Patterns for sensitive data that should be redacted
    SENSITIVE_PATTERNS: list[Pattern[str]] = [
        # Passwords and secrets (Captured prefix and value) - handles multiple separators
        re.compile(r'(?i)(password(?:\s+|[:=]|is\b)+)([^\s,"}]+)'),
        re.compile(r'(?i)(secret(?:\s+|[:=]|is\b)+)([^\s,"}]+)'),
        re.compile(r'(?i)(token(?:\s+|[:=]|is\b)+)([^\s,"}]+)'),
        re.compile(r'(?i)(key(?:\s+|[:=]|is\b)+)([^\s,"}]+)'),
        re.compile(r'(?i)(passphrase(?:\s+|[:=]|is\b)+)([^\s,"}]+)'),
        # SSH key material (base64 encoded)
        re.compile(r"AAAA[A-Za-z0-9+/]{20,}={0,2}"),
        # Private key headers/footers
        re.compile(
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
            re.DOTALL,
        ),
        # IP addresses (partial redaction)
        re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}"),
        # Hostnames (partial redaction for internal hosts)
        re.compile(r"([a-zA-Z0-9-]+\.)(internal|local|corp|lan)"),
    ]

    # Replacement patterns
    REPLACEMENTS = {
        "password": "[PASSWORD_REDACTED]",  # nosec
        "secret": "[SECRET_REDACTED]",  # nosec
        "token": "[TOKEN_REDACTED]",  # nosec
        "key": "[KEY_REDACTED]",  # nosec
        "passphrase": "[PASSPHRASE_REDACTED]",  # nosec
        "ssh_key": "[SSH_KEY_REDACTED]",  # nosec
        "private_key": "[PRIVATE_KEY_REDACTED]",  # nosec
        "ip_partial": r"\1***",
        "hostname_partial": r"\1[REDACTED]",
    }

    @classmethod
    def sanitize_message(cls, message: str) -> str:
        """
        Sanitize a log message by redacting sensitive information.

        Args:
            message: The log message to sanitize

        Returns:
            Sanitized message with sensitive data redacted
        """
        sanitized = message

        # Apply password/secret patterns using groups
        for pattern_type in ["password", "secret", "token", "key", "passphrase"]:
            pattern = next(
                p for p in cls.SENSITIVE_PATTERNS if pattern_type in p.pattern.lower()
            )

            def replace_with_group(match: re.Match[str]) -> str:
                return match.group(1) + cls.REPLACEMENTS[pattern_type]

            sanitized = pattern.sub(replace_with_group, sanitized)

        # SSH key material
        ssh_key_pattern = cls.SENSITIVE_PATTERNS[5]  # Adjusted index
        sanitized = ssh_key_pattern.sub(cls.REPLACEMENTS["ssh_key"], sanitized)

        # Private key blocks
        private_key_pattern = cls.SENSITIVE_PATTERNS[6]
        sanitized = private_key_pattern.sub(cls.REPLACEMENTS["private_key"], sanitized)

        # IP addresses (keep first 3 octets)
        ip_pattern = cls.SENSITIVE_PATTERNS[7]
        sanitized = ip_pattern.sub(cls.REPLACEMENTS["ip_partial"], sanitized)

        # Internal hostnames
        hostname_pattern = cls.SENSITIVE_PATTERNS[8]
        sanitized = hostname_pattern.sub(
            cls.REPLACEMENTS["hostname_partial"], sanitized
        )

        return sanitized

    @classmethod
    def sanitize_dict(cls, data: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize a dictionary by redacting sensitive keys and values.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary
        """
        sanitized: dict[str, Any] = {}
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "key",
            "private_key",
            "passphrase",
        }

        for key, value in data.items():
            if key.lower() in sensitive_keys:
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, str):
                sanitized[key] = cls.sanitize_message(value)
            elif isinstance(value, dict):
                sanitized[key] = cls.sanitize_dict(value)
            elif isinstance(value, (list, tuple)):
                sanitized_list: list[Any] = []
                for item in value:
                    if isinstance(item, str):
                        sanitized_list.append(cls.sanitize_message(item))
                    elif isinstance(item, dict):
                        sanitized_list.append(cls.sanitize_dict(item))
                    else:
                        sanitized_list.append(item)
                sanitized[key] = sanitized_list
            else:
                sanitized[key] = value

        return sanitized
