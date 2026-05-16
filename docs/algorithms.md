# Algorithms

SpindleX supports a carefully chosen set of modern SSH cryptographic algorithms. Legacy and weak primitives are excluded by default — only algorithms that are actively implemented, negotiation-tested, and considered safe for current deployments are advertised to the server.

!!! info "Benchmark-verified"
    Every algorithm on this page is covered by the production readiness benchmark (`scripts/benchmark_production.py`), which verifies end-to-end negotiation and data integrity against a live server on every release.

---

## Key Exchange (KEX)

Key exchange establishes the shared session secret before any user data is sent. SpindleX advertises the following algorithms in preference order:

| Algorithm | RFC / Standard | Hash | Status |
|-----------|---------------|------|--------|
| `curve25519-sha256` | RFC 8731 | SHA-256 | **Preferred** |
| `ecdh-sha2-nistp256` | RFC 5656 | SHA-256 | Active |
| `ecdh-sha2-nistp384` | RFC 5656 | SHA-384 | Active |
| `ecdh-sha2-nistp521` | RFC 5656 | SHA-512 | Active |
| `diffie-hellman-group14-sha256` | RFC 4253, RFC 8268 | SHA-256 | Active |

### Notes

- **`curve25519-sha256`** is the preferred algorithm. It uses Curve25519 elliptic-curve Diffie-Hellman and is the modern default across OpenSSH and most current servers.
- **ECDH NIST curves** (P-256, P-384, P-521) are supported for compatibility with servers and clients that do not offer Curve25519.
- **`diffie-hellman-group14-sha256`** uses a 2048-bit Diffie-Hellman group and SHA-256. It is retained for compatibility with older servers.
- SHA-1 based KEX (`diffie-hellman-group14-sha1`, `diffie-hellman-group1-sha1`) is not implemented and will never be negotiated.

### Client signaling tokens

SpindleX appends `kex-strict-c-v00@openssh.com` and `ext-info-c` to the client's KEX list as capability signals per OpenSSH extension negotiation. These are **not** real algorithms — they are never selected as the negotiated KEX method and have no implementation behind them.

---

## Host Key (Server Authentication)

Host key algorithms determine how the server proves its identity. SpindleX advertises the following in preference order:

| Algorithm | Key Type | Signature Hash | Status |
|-----------|----------|---------------|--------|
| `ssh-ed25519` | Ed25519 | SHA-512 (internal) | **Preferred** |
| `ecdsa-sha2-nistp256` | ECDSA P-256 | SHA-256 | Active |
| `ecdsa-sha2-nistp384` | ECDSA P-384 | SHA-384 | Active |
| `ecdsa-sha2-nistp521` | ECDSA P-521 | SHA-512 | Active |
| `rsa-sha2-512` | RSA | SHA-512 | Active |
| `rsa-sha2-256` | RSA | SHA-256 | Active |

### Notes

- **`ssh-ed25519`** is the preferred host key type. It has the smallest key size, fastest verification, and strong security properties.
- **RSA** host keys are supported via the modern `rsa-sha2-256` and `rsa-sha2-512` signature algorithms (RFC 8332). Raw `ssh-rsa` (SHA-1 signatures) is not advertised and requires an explicit opt-in — see [Legacy Algorithms](#legacy-algorithms) below.
- The server's host key is verified against `~/.ssh/known_hosts` (or a custom `HostKeyStorage`) on every connection. See the [Security Guide](security.md) for host key policy details.

---

## Encryption (Cipher)

Encryption algorithms protect the data stream after key exchange. SpindleX advertises the following in preference order:

| Algorithm | Key Size | Mode | Status |
|-----------|----------|------|--------|
| `chacha20-poly1305@openssh.com` | 512-bit (2×256) | AEAD (ChaCha20+Poly1305) | **Preferred** |
| `aes256-ctr` | 256-bit | CTR | Active |
| `aes192-ctr` | 192-bit | CTR | Active |
| `aes128-ctr` | 128-bit | CTR | Active |

### Notes

- **`chacha20-poly1305@openssh.com`** is the preferred modern cipher. It is an AEAD (Authenticated Encryption with Associated Data) construction that bundles confidentiality and integrity into a single pass — no separate MAC is computed or verified when this cipher is active. It uses a 64-byte derived key split into two 32-byte halves: one to encrypt the packet length field, one to encrypt the body and derive the Poly1305 authentication tag.
- **AES-CTR ciphers** are retained for compatibility with servers that do not advertise `chacha20-poly1305@openssh.com`. They require a separate HMAC for packet authentication.
- All AES ciphers use **Counter (CTR) mode**, which is not vulnerable to padding oracle attacks.
- CBC mode ciphers (`aes128-cbc`, `aes256-cbc`, `3des-cbc`) are not implemented.

---

## Message Authentication Code (MAC)

MAC algorithms authenticate each packet and protect against tampering. SpindleX advertises the following in preference order:

| Algorithm | Hash | Tag Size | Status |
|-----------|------|----------|--------|
| `hmac-sha2-256` | SHA-256 | 32 bytes | **Preferred** |
| `hmac-sha2-512` | SHA-512 | 64 bytes | Active |

### Notes

- Both MACs use **HMAC** (RFC 2104) over SHA-2, which is the current standard for SSH packet authentication.
- **`hmac-sha2-256`** is preferred for its balance of security and performance.
- **`hmac-sha2-512`** provides a larger tag and is suitable for environments with stricter integrity requirements.
- Legacy MACs (`hmac-sha1`, `hmac-md5`, `hmac-sha1-96`) are not implemented and will never be negotiated.

---

## Compression

| Algorithm | Status |
|-----------|--------|
| `none` | Active (only supported method) |

Compression is not implemented. `none` is the only advertised compression method, which means the SSH transport sends data uncompressed. This is consistent with modern SSH deployments where compression provides limited benefit and can introduce security risks (e.g., CRIME-style attacks on compressed streams).

---

## Algorithm Negotiation

SpindleX follows **RFC 4253 §7.1** for algorithm negotiation:

1. Both client and server send a `KEXINIT` message listing their supported algorithms in preference order.
2. The first algorithm in the **client's** list that also appears in the **server's** list is selected.
3. If no overlap exists for any required category (KEX, cipher, MAC, host key), the connection fails with a `CryptoException`.

SpindleX never silently falls back to an unsupported algorithm. If you pin a single algorithm via `CipherSuite` and the server does not support it, the connection raises an `SSHException` subclass immediately.

### Preference order matters

The order of algorithms in `CipherSuite.KEX_ALGORITHMS`, `ENCRYPTION_ALGORITHMS`, `HOST_KEY_ALGORITHMS`, and `MAC_ALGORITHMS` determines which algorithm is selected when the server supports multiple options. The library defaults are ordered strongest-first.

---

## Advanced: Pinning Algorithms

For testing or strict compliance environments you can constrain the library to a single algorithm per category by temporarily overriding the `CipherSuite` class attributes:

```python
from spindlex.crypto.ciphers import CipherSuite

# Force a specific cipher for a single connection
saved = CipherSuite.ENCRYPTION_ALGORITHMS[:]
CipherSuite.ENCRYPTION_ALGORITHMS = ["aes128-ctr"]
try:
    client.connect(...)
finally:
    CipherSuite.ENCRYPTION_ALGORITHMS = saved
```

!!! warning
    Modifying `CipherSuite` class attributes is a global, process-wide change. It is not thread-safe and is intended for testing only. Do not use this pattern in production code.

---

## Legacy Algorithms

The following algorithms are available as opt-in legacy support only. They are **not** advertised during normal negotiation and require explicit configuration.

### `ssh-rsa` (SHA-1 signatures)

The original `ssh-rsa` host key algorithm uses SHA-1 for signatures. SHA-1 is cryptographically broken for collision resistance and is disabled by default in OpenSSH 8.8+.

SpindleX can load and verify `ssh-rsa` host keys for compatibility with very old servers, but it requires setting `allow_sha1 = True` on the key instance before signing or verifying. This path is intentionally gated and emits deprecation warnings.

**Recommendation:** Migrate servers to `rsa-sha2-256` or `rsa-sha2-512` (which reuse the same RSA key material) or switch to `ssh-ed25519`.

---

## What Is Not Supported

The following algorithms are deliberately excluded:

| Algorithm | Reason |
|-----------|--------|
| `diffie-hellman-group1-sha1` | 1024-bit DH group, SHA-1 — broken |
| `diffie-hellman-group14-sha1` | SHA-1 — deprecated |
| `hmac-sha1`, `hmac-md5` | SHA-1 / MD5 — deprecated |
| `arcfour`, `3des-cbc`, `blowfish-cbc` | Weak or broken ciphers |
| `aes*-cbc` | CBC mode — vulnerable to padding oracle attacks |
| `none` (cipher) | Plaintext — never negotiated |
| `zlib`, `zlib@openssh.com` | Not implemented |
