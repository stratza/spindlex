# Contributing to SpindleX

Thank you for your interest in contributing to SpindleX! This document provides guidelines and information for contributors.

## Code of Conduct

By participating in this project, you agree to abide by the project's Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

### Development Environment Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/spindlex.git
   cd spindlex
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   pip install -e .[dev]
   ```

4. **Install Pre-commit Hooks**
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=spindlex --cov-report=html

# Run specific test categories
python -m pytest -m unit
python -m pytest -m integration
python -m pytest -m performance

# Run tests for specific modules
python -m pytest tests/test_protocol_utils.py
```

### Code Quality

I maintain high code quality standards:

```bash
# Format code
black spindlex tests
isort spindlex tests

# Lint code
flake8 spindlex tests

# Type checking
mypy spindlex

# Security scanning
bandit -r spindlex -c pyproject.toml

# Run all quality checks
tox -e lint,type-check,security
```

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
- Security Issue (use di3z1e@proton.me for sensitive issues)

### Submitting Changes

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Follow coding standards (see below)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Changes**
   ```bash
   python -m pytest
   tox  # Test across multiple Python versions
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

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

## Coding Standards

### Python Style

I follow PEP 8 with some modifications:

- **Line Length**: 88 characters (Black default)
- **Imports**: Use isort for import sorting
- **Type Hints**: Required for all public APIs
- **Docstrings**: Google style docstrings

### Code Structure

```python
"""Module docstring describing the module's purpose."""

import standard_library
import third_party_library

from spindlex import local_imports


class ExampleClass:
    """Class docstring.
    
    Args:
        param1: Description of parameter.
        param2: Description of parameter.
    
    Attributes:
        attr1: Description of attribute.
    """
    
    def __init__(self, param1: str, param2: int) -> None:
        """Initialize the class.
        
        Args:
            param1: Description.
            param2: Description.
        """
        self.attr1 = param1
        self._private_attr = param2
    
    def public_method(self, arg: str) -> bool:
        """Public method with proper docstring.
        
        Args:
            arg: Description of argument.
            
        Returns:
            Description of return value.
            
        Raises:
            ValueError: When arg is invalid.
        """
        if not arg:
            raise ValueError("arg cannot be empty")
        return True
    
    def _private_method(self) -> None:
        """Private method (single underscore)."""
        pass
```

### Testing Standards

- **Test Coverage**: Aim for >90% coverage
- **Test Types**: Unit, integration, and performance tests
- **Test Structure**: Use pytest fixtures and parametrization
- **Mocking**: Use unittest.mock for external dependencies

```python
import pytest
from unittest.mock import Mock, patch

from spindlex.client.ssh_client import SSHClient


class TestSSHClient:
    """Test cases for SSHClient."""
    
    @pytest.fixture
    def client(self):
        """Provide a test client instance."""
        return SSHClient()
    
    def test_connect_success(self, client):
        """Test successful connection."""
        # Test implementation
        pass
    
    @pytest.mark.parametrize("username,password,expected", [
        ("user1", "pass1", True),
        ("user2", "pass2", False),
    ])
    def test_authentication(self, client, username, password, expected):
        """Test authentication with various credentials."""
        # Test implementation
        pass
    
    @patch('spindlex.transport.transport.socket')
    def test_connection_failure(self, mock_socket, client):
        """Test connection failure handling."""
        mock_socket.side_effect = ConnectionError("Connection failed")
        # Test implementation
        pass
```

### Documentation Standards

- **API Documentation**: All public APIs must have docstrings
- **Type Hints**: Required for all function signatures
- **Examples**: Include usage examples in docstrings
- **Sphinx**: Use Sphinx-compatible docstring format

```python
def connect(
    self,
    hostname: str,
    port: int = 22,
    username: Optional[str] = None,
    password: Optional[str] = None,
    pkey: Optional[PKey] = None,
    timeout: Optional[float] = None
) -> None:
    """Connect to SSH server.
    
    Establishes an SSH connection to the specified server with the given
    authentication credentials.
    
    Args:
        hostname: Server hostname or IP address.
        port: SSH port number (default: 22).
        username: Username for authentication.
        password: Password for authentication (if using password auth).
        pkey: Private key for authentication (if using key auth).
        timeout: Connection timeout in seconds.
    
    Raises:
        AuthenticationException: If authentication fails.
        TransportException: If connection cannot be established.
        
    Example:
        >>> client = SSHClient()
        >>> client.connect('example.com', username='user', password='pass')
        >>> # Use the connection
        >>> client.close()
    """
```

## Security Guidelines

### Security-First Development

- **Input Validation**: Validate all inputs
- **Constant-Time Operations**: Use constant-time comparisons for secrets
- **Memory Safety**: Clear sensitive data from memory
- **Logging**: Never log sensitive information

### Cryptographic Standards

- **Modern Algorithms**: Use only modern, secure algorithms
- **Key Sizes**: Enforce minimum key sizes
- **Random Generation**: Use cryptographically secure random generators
- **Timing Attacks**: Protect against timing-based attacks

### Security Review Process

1. **Self Review**: Check your code for security issues
2. **Automated Scanning**: Run bandit and other security tools
3. **Peer Review**: Have security-conscious developers review
4. **Security Team Review**: For cryptographic or security-critical changes

## Performance Guidelines

### Performance Considerations

- **Efficiency**: Optimize hot paths and frequently called functions
- **Memory Usage**: Minimize memory allocations and leaks
- **Async Support**: Consider async alternatives for I/O operations
- **Benchmarking**: Add benchmarks for performance-critical code

### Benchmarking

```python
import time
from spindlex.crypto.pkey import Ed25519Key

def benchmark_key_generation():
    """Benchmark key generation performance."""
    iterations = 100
    start_time = time.perf_counter()
    
    for _ in range(iterations):
        Ed25519Key.generate()
    
    end_time = time.perf_counter()
    avg_time = (end_time - start_time) / iterations
    
    print(f"Average key generation time: {avg_time:.4f}s")
    assert avg_time < 0.1  # Should be fast
```

## Documentation

### Types of Documentation

1. **API Documentation**: Auto-generated from docstrings
2. **User Guide**: How-to guides and tutorials
3. **Examples**: Practical code examples
4. **Security Guide**: Security best practices

### Building Documentation

```bash
# Install documentation dependencies
pip install -e .[docs]

# Build documentation
cd docs
make html

# View documentation
open _build/html/index.html
```

### Writing Documentation

- **Clear Language**: Use simple, clear language
- **Code Examples**: Include working code examples
- **Cross-References**: Link to related documentation
- **Updates**: Keep documentation in sync with code changes

## Release Process

### Version Management

I use semantic versioning (SemVer):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

1. **Update Version**: Update version in `_version.py`
2. **Update Changelog**: Document all changes
3. **Run Tests**: Ensure all tests pass
4. **Build Documentation**: Update and build docs
5. **Create Release**: Tag and create GitHub release
6. **Publish Package**: Upload to PyPI

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Email**: di3z1e@proton.me for security issues

### Getting Help

- **Documentation**: Check the documentation first
- **Search Issues**: Look for existing issues
- **Ask Questions**: Use GitHub Discussions for questions
- **Stack Overflow**: Tag questions with `spindlex`

## Recognition

Contributors are recognized in:
- **CONTRIBUTORS.md**: List of all contributors
- **Release Notes**: Major contributions mentioned
- **Documentation**: Author attribution where appropriate

## Legal

### Contributor License Agreement

By contributing to SpindleX, you agree that:

1. Your contributions are your original work
2. You have the right to submit the contributions
3. Your contributions are licensed under the MIT license
4. You grant the project creator the right to use your contributions

### Copyright

- **New Files**: Include MIT license header
- **Existing Files**: Maintain existing copyright notices
- **Third-Party Code**: Clearly mark and attribute third-party code

## Thank You

Thank you for contributing to SpindleX! Your contributions help make secure SSH communication accessible to Python developers worldwide.

For questions about contributing, please open a GitHub Discussion or contact me.