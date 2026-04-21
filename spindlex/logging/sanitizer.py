"""
Log sanitization utilities for security-sensitive information.
"""

import logging
import re
from typing import Any, Pattern


class LogSanitizer:
    """Sanitizes log messages to prevent sensitive information leakage."""

    # Patterns for sensitive data that should be redacted
    SENSITIVE_PATTERNS: dict[str, Pattern[str]] = {
        # Passwords and secrets (Captured prefix and value) - handles multiple separators
        "password": re.compile(r'(?i)(\bpassword(?:[\s:=]|is\b)+)([^\s,"}]+)'),
        "secret": re.compile(r'(?i)(\bsecret(?:[\s:=]|is\b)+)([^\s,"}]+)'),
        "token": re.compile(r'(?i)(\btoken(?:[\s:=]|is\b)+)([^\s,"}]+)'),
        "key": re.compile(r'(?i)(\bkey(?:[\s:=]|is\b)+)([^\s,"}]+)'),
        "passphrase": re.compile(r'(?i)(\bpassphrase(?:[\s:=]|is\b)+)([^\s,"}]+)'),
        # SSH key material (base64 encoded)
        "ssh_key": re.compile(r"AAAA[A-Za-z0-9+/]{20,}={0,2}"),
        # Private key headers/footers
        "private_key": re.compile(
            r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
            re.DOTALL,
        ),
        # IP addresses (partial redaction)
        "ip": re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}"),
        # Hostnames (partial redaction for internal hosts)
        "hostname": re.compile(r"([a-zA-Z0-9-]+\.)(internal|local|corp|lan)"),
    }

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
            pattern = cls.SENSITIVE_PATTERNS[pattern_type]

            def replace_with_group(match: re.Match[str], pt: str = pattern_type) -> str:
                return match.group(1) + cls.REPLACEMENTS[pt]

            sanitized = pattern.sub(replace_with_group, sanitized)

        # SSH key material
        sanitized = cls.SENSITIVE_PATTERNS["ssh_key"].sub(
            cls.REPLACEMENTS["ssh_key"], sanitized
        )

        # Private key blocks
        sanitized = cls.SENSITIVE_PATTERNS["private_key"].sub(
            cls.REPLACEMENTS["private_key"], sanitized
        )

        # IP addresses (keep first 3 octets)
        sanitized = cls.SENSITIVE_PATTERNS["ip"].sub(
            cls.REPLACEMENTS["ip_partial"], sanitized
        )

        # Internal hostnames
        sanitized = cls.SENSITIVE_PATTERNS["hostname"].sub(
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


class SanitizingFilter(logging.Filter):
    """Logging filter that redacts sensitive information from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = LogSanitizer.sanitize_message(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = LogSanitizer.sanitize_dict(record.args)
            else:
                record.args = tuple(
                    LogSanitizer.sanitize_message(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        return True
