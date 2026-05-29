# Architecture and Security Boundaries

This page summarizes the major system boundaries for reviewers. API stability is
defined separately in [API stability](api-stability.md).

## Data Flow

1. Client code configures host keys, credentials, algorithms, and connection
   options.
2. Transport opens a TCP socket and performs SSH version exchange.
3. Key exchange negotiates KEX, host key, cipher, and MAC or AEAD behavior.
4. Host key policy verifies server identity.
5. Authentication establishes the user session.
6. Channels carry command execution, forwarding, and SFTP subsystem traffic.
7. SFTP clients and servers encode and decode file-operation messages.

## Trust Boundaries

- Remote SSH peers are untrusted until host key verification succeeds.
- Credentials and private keys are caller-owned secrets.
- Protocol bytes from the network are untrusted input.
- `cryptography` owns low-level primitive correctness.
- SpindleX owns SSH framing, negotiation, host key policy, authentication flow,
  channel behavior, and SFTP message handling.

## Host Key Verification

`RejectPolicy` is the safe default. `AutoAddPolicy` is for disposable tests and
controlled development only. Accepting unknown host keys in production changes
the trust model and can hide man-in-the-middle attacks.

## Sensitive Data Boundaries

Logging sanitizers redact common credentials, key material, and sensitive
fields. Callers should still avoid logging raw secrets, private keys, or full
environment dumps.

## Security-Sensitive Interfaces

Maintainer review is required for changes to:

- host key policies and storage
- authentication
- key exchange and algorithm negotiation
- packet framing, MAC, AEAD, and rekey behavior
- SFTP read/write integrity
- logging sanitizer rules
- release and artifact integrity workflows
