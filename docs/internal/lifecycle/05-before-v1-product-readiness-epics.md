# Before `1.0.0`: Product Readiness Epics

These epics cover the non-CI work required before SpindleX can be broadly usable.

## Epic 1: Developer Experience

Goal: help a new user succeed in under five minutes.

Required examples:

- Install.
- Sync SSH command.
- Async SSH command.
- Sync SFTP upload/download.
- Async SFTP upload/download.
- Key-based auth.
- Known-hosts handling.
- Error handling.
- Timeout handling.
- Context manager cleanup.

Implementation tasks:

- Keep quickstart short and copy-pasteable.
- Put safe host key behavior in the first examples.
- Move risky `AutoAddPolicy` usage into clearly marked test-only sections.
- Document:
  - authentication failure
  - host key failure
  - connection timeout
  - protocol/server failure
- Document CLI tools:
  - `spindlex-keygen`
  - `spindlex-benchmark`

Acceptance criteria:

- A user can install and run a first SSH command from docs alone.
- A user can run a first SFTP transfer from docs alone.
- Error examples use actual exception classes.
- CLI examples match actual entry points.

## Epic 2: Documentation Strategy

Goal: make docs complete enough for `1.0.0`.

Required before `1.0.0`:

- Quickstart.
- Installation.
- Sync client guide.
- Async client guide.
- SFTP guide.
- Authentication and host key guide.
- Error handling guide.
- Security model and threat model.
- Compatibility page.
- Performance benchmark methodology.
- Comparison page.
- Migration guide.
- API reference.
- Changelog.
- Contributing guide.

Recommended structure:

```text
docs/
  quickstart.md
  security.md
  compatibility.md
  performance.md
  comparison.md
  migration/
    index.md
    0.x-to-1.0.md
  user_guide/
    client.md
    sftp.md
    authentication.md
    server.md
  cookbook/
  api_reference/
```

Comparison page rules:

- Compare against Paramiko and AsyncSSH honestly.
- Include strengths and weaknesses.
- Include unsupported features.
- Compare use cases, not only speed.

Acceptance criteria:

- Docs match real API names.
- Docs avoid real secrets.
- Python support claims match metadata and CI.
- Docker docs do not imply an official image before one exists.

## Epic 3: Compatibility Strategy

Goal: state what SpindleX supports and what it does not.

Before `1.0.0`:

- Document tested Python versions: `3.9-3.13`.
- Treat Python `3.9` as legacy support because it is EOL upstream.
- Remove Python `3.14` classifier unless CI officially tests it.
- Document tested OpenSSH versions from Docker and real canary hosts.
- Keep compatibility claims conservative.

Create `docs/compatibility.md` with:

- Python support table.
- OS support table.
- OpenSSH support table.
- Dropbear support note.
- Known incompatibilities.
- Unsupported features.
- Behavior differences vs Paramiko and AsyncSSH.

Known incompatibility entry format:

```text
Server/version:
Feature:
Symptom:
Workaround:
Status:
```

Acceptance criteria:

- README links to compatibility docs.
- Users can understand support boundaries before adopting.
- New compatibility reports have a place to be recorded.

## Epic 4: Canary And Real Usage Validation

Goal: validate beyond Docker loopback tests.

Canary goals:

- Validate behavior against real OpenSSH servers.
- Validate behavior under non-local latency.
- Validate realistic authentication and SFTP workflows.
- Detect issues hidden by Docker loopback tests.

Canary environments:

- One controlled Linux VM with OpenSSH.
- Optional second host with older OpenSSH.
- Optional cloud VM with higher latency.
- No production customer systems.
- No shared personal SSH hosts.

Canary test coverage:

- Password auth if enabled on the test host.
- Public-key auth.
- Host key verification with known_hosts.
- SSH exec command.
- SFTP list/upload/download/remove.
- Large file transfer.
- Timeout behavior.
- Connection failure behavior.
- Async and sync client smoke tests.

Network condition validation:

- Use real network latency from cloud VM.
- Optionally use Linux `tc netem` on a controlled host for:
  - latency
  - jitter
  - packet loss
  - bandwidth limits

Canary fallback policy:

- If canary environment is unavailable, release may proceed only if:
  - integration tests are stable
  - no recent compatibility issues are reported
- Canary results are a strong signal but not a hard blocker in all cases.

Secrets:

- Store canary host, username, key, and port in GitHub environment secrets.
- Never put real SSH credentials in Codex cloud.
- Use a locked-down canary user with limited permissions.
- Rotate canary credentials periodically.

Acceptance criteria:

- Canary runbook exists.
- Canary tests can be run manually.
- Canary failures are classified as code-related or environment-related.

## Epic 5: Benchmark And Performance Validation

Goal: publish credible, reproducible performance data.

Benchmark goals:

- SSH handshake latency.
- Command execution latency.
- SFTP upload/download throughput.
- Concurrent connections.
- Large transfer memory behavior.
- Sync vs async behavior.

Benchmark entry point:

```bash
spindlex-benchmark --scenario basic --output results.json
```

Benchmark design:

- Pin versions of SpindleX, Paramiko, AsyncSSH, and OpenSSH.
- Record:
  - OS
  - CPU
  - Python version
  - server version
  - cipher/MAC/KEX
  - auth method
  - file size
  - concurrency
  - network conditions
- Warm up once.
- Run multiple iterations.
- Publish median, p95, min/max, and standard deviation.
- Separate loopback, LAN, and real-network results.

Compare against:

- Paramiko for sync workflows.
- AsyncSSH for async workflows.
- OpenSSH CLI/SFTP as practical baseline.

Publish results:

- `docs/performance.md`.
- JSON/CSV artifacts.
- Simple docs charts.
- Raw benchmark artifacts attached to releases when available.

Rules:

- Do not claim universal superiority.
- Always publish methodology.
- Keep comparison honest.
- Include library versions.

Acceptance criteria:

- Maintainers can reproduce baseline results with one command.
- Public benchmark numbers include environment and methodology.

## Epic 6: Distribution And Adoption

Goal: make discovery and first use easy.

Before `1.0.0`:

- Keep PyPI as the primary channel.
- Keep PyPI metadata complete.
- Add project URLs:
  - docs
  - changelog
  - security
  - source
  - issues
  - discussions
- Keep classifiers aligned with tested Python versions.
- Improve README positioning.
- Add GitHub topics.
- Add comparison docs.

After `1.0.0` readiness:

- Submit to conda-forge after PyPI release flow is stable.
- Add Docker Hub only after supported `spindlex-server` CLI exists.
- Consider GHCR as mirror later.

Example assets:

- Minimal sync client example.
- Minimal async client example.
- SFTP automation example.
- Backup automation example.
- Docker-based test environment example.
- Canary validation example for maintainers.

Acceptance criteria:

- A user can discover, install, and run SpindleX from PyPI/README/docs.
- README makes beta status clear.
- PyPI metadata points to docs, security, changelog, and source.
