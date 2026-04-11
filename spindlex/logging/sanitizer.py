"""
Log sanitization utilities for security-sensitive information.
"""

import re
from typing import Any, Pattern


class LogSanitizer:
    """Sanitizes log messages to prevent sensitive information leakage."""

    # Patterns for sensitive data that should be redacted
    SENSITIVE_PATTERNS: list[Pattern[str]] = [
        # Passwords and secrets (with = or : or space)
        re.compile(r'password["\s]*[:=\s]["\s]*[^"\s,}]+', re.IGNORECASE),
        re.compile(r'secret["\s]*[:=\s]["\s]*[^"\s,}]+', re.IGNORECASE),
        re.compile(r'token["\s]*[:=\s]["\s]*[^"\s,}]+', re.IGNORECASE),
        re.compile(r'key["\s]*[:=\s]["\s]*[^"\s,}]+', re.IGNORECASE),
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
        "password": "[PASSWORD_REDACTED]",
        "secret": "[SECRET_REDACTED]",
        "token": "[TOKEN_REDACTED]",
        "key": "[KEY_REDACTED]",
        "ssh_key": "[SSH_KEY_REDACTED]",
        "private_key": "[PRIVATE_KEY_REDACTED]",
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

        # Apply password/secret patterns
        for pattern_type in ["password", "secret", "token", "key"]:
            pattern = next(
                p for p in cls.SENSITIVE_PATTERNS if pattern_type in p.pattern.lower()
            )

            def replace_sensitive(match):
                matched_text = match.group()
                if "=" in matched_text:
                    return (
                        matched_text.split("=")[0]
                        + "="
                        + cls.REPLACEMENTS[pattern_type]
                    )
                elif ":" in matched_text:
                    return (
                        matched_text.split(":")[0]
                        + ": "
                        + cls.REPLACEMENTS[pattern_type]
                    )
                else:
                    # Handle space-separated case like "password secret123"
                    parts = matched_text.split()
                    if len(parts) >= 2:
                        return parts[0] + " " + cls.REPLACEMENTS[pattern_type]
                    return cls.REPLACEMENTS[pattern_type]

            sanitized = pattern.sub(replace_sensitive, sanitized)

        # SSH key material
        ssh_key_pattern = cls.SENSITIVE_PATTERNS[4]  # AAAA pattern
        sanitized = ssh_key_pattern.sub(cls.REPLACEMENTS["ssh_key"], sanitized)

        # Private key blocks
        private_key_pattern = cls.SENSITIVE_PATTERNS[5]
        sanitized = private_key_pattern.sub(cls.REPLACEMENTS["private_key"], sanitized)

        # IP addresses (keep first 3 octets)
        ip_pattern = cls.SENSITIVE_PATTERNS[6]
        sanitized = ip_pattern.sub(cls.REPLACEMENTS["ip_partial"], sanitized)

        # Internal hostnames
        hostname_pattern = cls.SENSITIVE_PATTERNS[7]
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
        sanitized = {}
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
                sanitized[key] = [
                    (
                        cls.sanitize_message(item)
                        if isinstance(item, str)
                        else cls.sanitize_dict(item)
                        if isinstance(item, dict)
                        else item
                    )
                    for item in value
                ]
            else:
                sanitized[key] = value

        return sanitized
