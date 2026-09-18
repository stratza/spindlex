# Contributing to SpindleX

Thank you for your interest in contributing to SpindleX! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by the project's Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

### Development Environment Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/stratza/spindlex.git
   cd spindlex
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   pip install -e ".[dev,docs,test]"
   ```

4. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
# Run the fast local test suite
python -m pytest tests -m "not integration and not real_server and not slow and not performance"

# Run with coverage
python -m pytest --cov=spindlex --cov-report=html

# Run specific test categories
python -m pytest -m unit
python -m pytest -m integration
python -m pytest -m performance

# Run tests for specific modules
python -m pytest tests/protocol/test_protocol_utils.py
```

### Code Quality

```bash
# Lint code
ruff check spindlex tests

# Check formatting
ruff format --check spindlex tests

# Format code
ruff check --fix spindlex tests
ruff format spindlex tests

# Type checking
mypy spindlex

# Security scanning
bandit -r spindlex -c pyproject.toml

# Build docs
mkdocs build --strict
```

Coding style (line length, import sorting, docstring format) is enforced by
`ruff` and `mypy` per `pyproject.toml` - run the commands above rather than
following a separate style guide. Type hints are required on all public APIs,
and public APIs need docstrings that render cleanly under mkdocstrings.

## Contributing Guidelines

### Reporting Issues

When reporting issues, please include:

- **Clear Description**: What you expected vs. what happened
- **Reproduction Steps**: Minimal code to reproduce the issue
- **Environment**: Python version, OS, library version
- **Error Messages**: Full stack traces when applicable

Use the project's issue templates:
- Bug Report
- Feature Request
- Security Issue (use GitHub Security Advisory)

### Submitting Changes

The default development flow is:

1. Create a short-lived branch from an up-to-date `main`.
2. Open a pull request back to `main`.
3. Fill the PR template completely.
4. Select exactly one `Type of Change` token.
5. Wait for the required `quality-gate` check to pass.
6. Resolve review conversations before merge.

`main` is the protected integration branch. Maintainers should configure branch
protection to require pull requests, conversation resolution, and the
`quality-gate` status check before merge. Direct pushes to `main` should be
reserved for emergency recovery by repository administrators.

In the PR body, select one `Type of Change`:

- `bug`: patch release after merge
- `feature`: feature or stabilization work for the current beta minor line; patch release before `1.0.0`
- `feature-minor`: intentional beta minor-line feature; minor release before `1.0.0`
- `breaking`: breaking beta change; minor release before `1.0.0`
- `docs`: no release
- `refactor`: no release
- `test`: no release

Release-impact types (`bug`, `feature`, `breaking`) must include test
evidence in the PR body.

### Commit Message Format

I use conventional commits:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(client): add support for Ed25519 keys
fix(transport): handle connection timeout properly
docs(readme): update installation instructions
test(crypto): add tests for key generation
```

## Community

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and help
- **Security Issue**: Use the GitHub Security Advisory system for security-related concerns, not public issues

## Recognition

Contributors are recognized in:
- **CONTRIBUTORS.md**: List of all contributors
- **Release Notes**: Major contributions mentioned

## Legal

By contributing to SpindleX, you agree that:

1. Your contributions are your original work, or you have the right to submit them.
2. Your contributions are licensed under the project's MIT license.
3. New files include an MIT license header; existing copyright notices and third-party attributions are preserved.

## Thank You

Thank you for contributing to SpindleX! Your contributions help make secure SSH communication accessible to Python developers worldwide.

For questions about contributing, please open a GitHub Discussion.
