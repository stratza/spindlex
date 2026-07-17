# Canary Validation Runbook

This document covers canary validation for SpindleX releases: what a full canary
environment looks like, what tests to run, how to classify failures, and the
approved fallback policy when a canary environment is unavailable.

## Purpose

Docker loopback integration tests verify protocol correctness but do not catch
issues that appear only under real network latency, real OpenSSH configurations,
or specific server version combinations. Canary validation runs the same client
workflows against a real SSH server on real infrastructure before publishing a
release.

---

## Canary Environment (Target Setup)

A full canary environment consists of:

- One controlled Linux VM with OpenSSH (latest stable release).
- Optionally a second VM running an older OpenSSH version.
- Optionally a cloud VM with measurable round-trip latency (> 20 ms).

The canary host must be a dedicated test machine. Never use production systems
or shared personal SSH hosts.

**Credentials**: Store canary host address, username, key path, and port in
GitHub environment secrets (e.g., `CANARY_HOST`, `CANARY_USER`,
`CANARY_KEY_B64`, `CANARY_PORT`). Never commit credentials to the repository.
Use a locked-down canary user with no shell beyond the tests and rotate
credentials periodically.

---

## Canary Test Coverage

Run the following scenarios manually or via the canary workflow:

### Authentication
- [ ] Public-key authentication (Ed25519)
- [ ] Password authentication (if enabled on the test host)
- [ ] Host key verification with a pre-populated known_hosts entry

### SSH Command Execution
- [ ] `exec_command('echo hello')` - basic smoke test
- [ ] Multi-line stdout
- [ ] Non-zero exit status captured correctly
- [ ] Timeout behavior (connection timeout, command timeout)

### SFTP
- [ ] `listdir()` on a remote directory
- [ ] Upload a 1 MB file, verify checksum
- [ ] Download a 1 MB file, verify checksum
- [ ] Upload a 64 MB file (chunked write path)
- [ ] `mkdir()` / `rmdir()`
- [ ] `stat()` on a file
- [ ] `remove()` a file
- [ ] Recursive upload
- [ ] Recursive download

### Async
- [ ] Async SSH command via `AsyncSSHClient`
- [ ] Async SFTP upload/download via `AsyncSFTPClient`

### Failure Scenarios
- [ ] Connection to a non-existent host raises `TimeoutException`
- [ ] Wrong password raises `AuthenticationException`
- [ ] Unknown host key with `RejectPolicy` raises `BadHostKeyException`

---

## Running the Canary

```bash
# Export credentials from environment or GitHub secrets
export CANARY_HOST=canary.example.internal
export CANARY_PORT=22
export CANARY_USER=spindlex-canary
export CANARY_KEY=~/.ssh/spindlex_canary_ed25519

# Run canary tests (manual)
pytest tests/real_server/ -v -m real_server \
    --ssh-host "$CANARY_HOST" \
    --ssh-port "$CANARY_PORT" \
    --ssh-user "$CANARY_USER" \
    --ssh-key  "$CANARY_KEY"

# Run local benchmark baseline as a smoke check
python scripts/benchmark_local_baseline.py --output benchmark-results/canary-pre.json
```

---

## Classifying Failures

When a canary test fails, classify the failure before deciding whether to block
the release:

| Failure category | Action |
|---|---|
| **Code regression** - reproduces in Docker tests or unit tests | Block release; fix forward |
| **Environment issue** - canary host unreachable, misconfigured, or credentials rotated | Fix the environment; re-run canary |
| **Server version incompatibility** - not reproduced on Docker OpenSSH | Record in `docs/compatibility.md`; decide whether to fix or document |
| **Intermittent / flaky** - not reproducible on re-run | Re-run up to 3 times; if still present treat as code regression |

---

## Fallback Policy

**If the canary environment is unavailable**, a release may proceed without
canary validation when all of the following are true:

1. Docker integration tests (`tests/integration/`) pass cleanly.
2. No open compatibility issues have been reported against the version being
   released.
3. The release does not change transport, cipher, or host key handling code.
4. A maintainer explicitly approves the fallback in the release PR description,
   noting which condition(s) above are met.

Document the fallback approval in the release PR with a line such as:

```
Canary skipped: fallback approved. Integration tests pass; no open compatibility
issues; no transport/crypto changes in this release.
```

### v1.0.0 Canary Status

No dedicated canary environment is provisioned for the v1.0.0 release. The
fallback policy above applies:

- Docker integration tests (OpenSSH + Dropbear) are stable.
- No open compatibility issues.
- Transport and cipher code has been stable since 0.7.3 with zero regressions
  in 1761 unit tests and 53/53 production benchmark scenarios.
- Approved by maintainer: v1.0.0 may proceed under fallback.

Once a canary environment is provisioned post-1.0, add the secrets and wire up
the workflow before the next minor release.
