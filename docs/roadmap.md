# Public Roadmap

This roadmap summarizes public lifecycle expectations without exposing internal
planning noise or committing to exact timelines.

## Beta Stabilization

Current beta work focuses on:

- protocol correctness and malformed-input handling
- SFTP reliability and performance
- security documentation and release trust
- CI reliability on free GitHub-hosted runners
- conservative compatibility claims

## v1.0 Release Candidate

The `1.0.0` release candidate starts only after the readiness checklist is
complete or explicitly accepted by maintainers:

- public production usage, compatibility, and API stability docs
- release, artifact verification, and support policy docs
- CI/release checks that match the documented policy
- property tests and repeatable local benchmark baseline
- security and vulnerability response documentation

## After v1

After stable release, work shifts toward:

- SemVer discipline
- compatibility matrix maintenance
- repeated user reports becoming docs, tests, or compatibility entries
- benchmark history and release verification evidence
- focused protocol and SFTP improvements

## Future Ideas

The following are non-committed ideas:

- broader canary environments
- additional package distribution channels
- long-running fuzzing outside the normal PR gate
- expanded server-side API stability
- additional SSH server family compatibility targets

## How Feedback Becomes Work

User feedback is triaged into the smallest durable artifact:

- documentation update
- regression test
- compatibility entry
- benchmark scenario
- roadmap issue
- security advisory path when private handling is required
