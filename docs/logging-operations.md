# Logging and Debug Observability

This page defines production-safe logging expectations for users and
maintainers.

## Logger Names

SpindleX loggers use the `spindlex` namespace. Module loggers should remain
under that namespace so sanitizing filters and application log configuration can
target the whole library.

Important categories:

- `spindlex.*` for runtime library events
- `spindlex.security` for security-relevant events
- `spindlex.performance` for timing and throughput metrics

## Levels

- `ERROR`: operation failed and the caller likely needs to handle it.
- `WARNING`: degraded behavior, unsafe user configuration, retryable issue, or
  compatibility warning.
- `INFO`: lifecycle events useful during normal operations.
- `DEBUG`: protocol diagnostics and detailed troubleshooting data.

## Redaction Guarantees

Sanitizers are expected to redact common passwords, tokens, private-key blocks,
and sensitive key/value fields. They are defense in depth, not permission to log
raw secrets.

Maintainers adding logs must avoid including:

- passwords
- private keys
- raw authorization tokens
- full known-host files
- unredacted environment dumps

## Safe Debug Fields

Safe diagnostic fields include:

- algorithm names
- packet/message type names
- byte counts
- channel identifiers
- elapsed time
- server version family when already visible on the wire

Avoid logging full payloads, command arguments that may contain secrets, or
private filesystem paths unless the caller explicitly controls the log.

## Incident Debugging

For production incidents:

1. Enable `DEBUG` only for the narrow process or logger needed.
2. Reproduce with sanitized logs.
3. Capture Python, SpindleX, OS, and SSH server versions.
4. Include correlation context from the application when available.
5. Remove logs after triage according to local retention policy.

## Metrics

Useful operational metrics include connect time, authentication time, command
latency, SFTP throughput, retry counts, error counts, and packet-level profiler
summaries when `SPINDLEX_PROFILE=1` is enabled.
