Contributing Guide
==================

I welcome contributions to SpindleX! This guide will help you get started with contributing code, documentation, bug reports, and feature requests.

Getting Started
---------------

Development Environment Setup
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Fork and Clone the Repository**::

    git clone https://gitlab.com/daveops.world/development/python/spindle.git
    cd spindlex

2. **Set Up Development Environment**::

    # Create virtual environment
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    
    # Install development dependencies
    pip install -e ".[dev,test,docs]"
    
    # Install pre-commit hooks
    pre-commit install

3. **Verify Installation**::

    # Run tests to ensure everything works
    pytest
    
    # Check code style
    flake8 spindlex/
    
    # Build documentation
    cd docs
    make html

Development Workflow
~~~~~~~~~~~~~~~~~~~~

1. **Create a Feature Branch**::

    git checkout -b feature/your-feature-name
    # or
    git checkout -b bugfix/issue-number

2. **Make Your Changes**
   - Write code following the style guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Test Your Changes**::

    # Run full test suite
    pytest
    
    # Run specific test categories
    pytest tests/unit/
    pytest tests/integration/
    
    # Check code coverage
    pytest --cov=spindlex --cov-report=html

4. **Commit Your Changes**::

    git add .
    git commit -m "feat: add new authentication method"
    
    # Follow conventional commit format:
    # feat: new feature
    # fix: bug fix
    # docs: documentation changes
    # style: formatting changes
    # refactor: code refactoring
    # test: adding tests
    # chore: maintenance tasks

5. **Push and Create Pull Request**::

    git push origin feature/your-feature-name
    
    # Create merge request on GitLab

Code Style and Standards
------------------------

Python Code Style
~~~~~~~~~~~~~~~~~

I follow PEP 8 with some modifications:

- **Line Length**: 88 characters (Black default)
- **Imports**: Use isort for import sorting
- **Type Hints**: Required for all public APIs
- **Docstrings**: Google-style docstrings

Example code style::

    from typing import Dict, List, Optional, Union
    import logging
    
    from spindlex.exceptions import SSHException
    
    
    class ExampleClass:
        """Example class demonstrating code style.
        
        This class shows the preferred code style for SpindleX.
        
        Args:
            hostname: The hostname to connect to.
            port: The port number (default: 22).
            timeout: Connection timeout in seconds.
        
        Raises:
            SSHException: If connection fails.
        """
        
        def __init__(
            self,
            hostname: str,
            port: int = 22,
            timeout: Optional[float] = None,
        ) -> None:
            self.hostname = hostname
            self.port = port
            self.timeout = timeout
            self._logger = logging.getLogger(__name__)
        
        def connect(self, username: str, **kwargs) -> bool:
            """Connect to the SSH server.
            
            Args:
                username: Username for authentication.
                **kwargs: Additional connection parameters.
            
            Returns:
                True if connection successful, False otherwise.
            
            Raises:
                SSHException: If connection fails.
            """
            try:
                self._logger.info(f"Connecting to {self.hostname}:{self.port}")
                # Implementation here
                return True
            except Exception as e:
                raise SSHException(f"Connection failed: {e}") from e

Code Formatting Tools
~~~~~~~~~~~~~~~~~~~~~

I use automated tools for code formatting:

**Black** for code formatting::

    black spindlex/ tests/

**isort** for import sorting::

    isort spindlex/ tests/

**flake8** for linting::

    flake8 spindlex/ tests/

**mypy** for type checking::

    mypy spindlex/

Pre-commit Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

The `.pre-commit-config.yaml`::

    repos:
      - repo: https://github.com/pre-commit/pre-commit-hooks
        rev: v4.4.0
        hooks:
          - id: trailing-whitespace
          - id: end-of-file-fixer
          - id: check-yaml
          - id: check-added-large-files
      
      - repo: https://github.com/psf/black
        rev: 23.3.0
        hooks:
          - id: black
      
      - repo: https://github.com/pycqa/isort
        rev: 5.12.0
        hooks:
          - id: isort
      
      - repo: https://github.com/pycqa/flake8
        rev: 6.0.0
        hooks:
          - id: flake8
      
      - repo: https://github.com/pre-commit/mirrors-mypy
        rev: v1.3.0
        hooks:
          - id: mypy
            additional_dependencies: [types-all]

Testing Guidelines
------------------

Test Structure
~~~~~~~~~~~~~~

Tests are organized into categories:

- **Unit Tests** (`tests/unit/`): Test individual components in isolation
- **Integration Tests** (`tests/integration/`): Test component interactions
- **Performance Tests** (`tests/performance/`): Benchmark and performance tests
- **Security Tests** (`tests/security/`): Security-focused tests

Writing Tests
~~~~~~~~~~~~~

Example unit test::

    import pytest
    from unittest.mock import Mock, patch
    
    from spindlex.client.ssh_client import SSHClient
    from spindlex.exceptions import AuthenticationException
    
    
    class TestSSHClient:
        """Test cases for SSHClient class."""
        
        def setup_method(self):
            """Set up test fixtures."""
            self.client = SSHClient()
        
        def teardown_method(self):
            """Clean up after tests."""
            if self.client:
                self.client.close()
        
        def test_connect_success(self):
            """Test successful connection."""
            with patch('spindlex.transport.Transport') as mock_transport:
                mock_transport.return_value.is_active.return_value = True
                
                result = self.client.connect(
                    hostname='test.example.com',
                    username='testuser',
                    password='testpass'
                )
                
                assert result is True
                mock_transport.assert_called_once()
        
        def test_connect_authentication_failure(self):
            """Test authentication failure."""
            with patch('spindlex.transport.Transport') as mock_transport:
                mock_transport.return_value.auth_password.side_effect = AuthenticationException("Auth failed")
                
                with pytest.raises(AuthenticationException):
                    self.client.connect(
                        hostname='test.example.com',
                        username='testuser',
                        password='wrongpass'
                    )
        
        @pytest.mark.parametrize("hostname,port,expected", [
            ("example.com", 22, "example.com:22"),
            ("192.168.1.1", 2222, "192.168.1.1:2222"),
            ("localhost", 22, "localhost:22"),
        ])
        def test_connection_string_format(self, hostname, port, expected):
            """Test connection string formatting."""
            result = self.client._format_connection_string(hostname, port)
            assert result == expected

Integration Test Example::

    import pytest
    import tempfile
    import os
    
    from spindlex import SSHClient
    from spindlex.crypto.pkey import Ed25519Key
    
    
    @pytest.mark.integration
    class TestSSHIntegration:
        """Integration tests requiring real SSH server."""
        
        @pytest.fixture(scope="class")
        def ssh_server_config(self):
            """SSH server configuration for testing."""
            return {
                'hostname': os.environ.get('TEST_SSH_HOST', 'localhost'),
                'port': int(os.environ.get('TEST_SSH_PORT', '22')),
                'username': os.environ.get('TEST_SSH_USER', 'testuser'),
                'password': os.environ.get('TEST_SSH_PASS'),
                'private_key_path': os.environ.get('TEST_SSH_KEY'),
            }
        
        @pytest.fixture
        def ssh_client(self, ssh_server_config):
            """Create SSH client for testing."""
            client = SSHClient()
            
            # Connect using available authentication method
            if ssh_server_config['private_key_path']:
                private_key = Ed25519Key.from_private_key_file(
                    ssh_server_config['private_key_path']
                )
                client.connect(
                    hostname=ssh_server_config['hostname'],
                    port=ssh_server_config['port'],
                    username=ssh_server_config['username'],
                    pkey=private_key
                )
            elif ssh_server_config['password']:
                client.connect(
                    hostname=ssh_server_config['hostname'],
                    port=ssh_server_config['port'],
                    username=ssh_server_config['username'],
                    password=ssh_server_config['password']
                )
            else:
                pytest.skip("No authentication method configured")
            
            yield client
            client.close()
        
        def test_command_execution(self, ssh_client):
            """Test command execution."""
            stdin, stdout, stderr = ssh_client.exec_command('echo "Hello, World!"')
            
            output = stdout.read().decode().strip()
            assert output == "Hello, World!"
            
            error = stderr.read().decode().strip()
            assert error == ""
        
        def test_file_transfer(self, ssh_client):
            """Test SFTP file transfer."""
            test_content = b"Test file content for SFTP transfer"
            
            with tempfile.NamedTemporaryFile(delete=False) as local_file:
                local_file.write(test_content)
                local_path = local_file.name
            
            try:
                remote_path = f'/tmp/test_file_{os.getpid()}'
                
                # Upload file
                sftp = ssh_client.open_sftp()
                sftp.put(local_path, remote_path)
                
                # Download file
                download_path = local_path + '_download'
                sftp.get(remote_path, download_path)
                
                # Verify content
                with open(download_path, 'rb') as f:
                    downloaded_content = f.read()
                
                assert downloaded_content == test_content
                
                # Cleanup
                sftp.remove(remote_path)
                sftp.close()
                os.unlink(download_path)
                
            finally:
                os.unlink(local_path)

Test Configuration
~~~~~~~~~~~~~~~~~~

Configure tests with `pytest.ini`::

    [tool:pytest]
    testpaths = tests
    python_files = test_*.py
    python_classes = Test*
    python_functions = test_*
    addopts = 
        --strict-markers
        --disable-warnings
        --tb=short
    markers =
        unit: Unit tests
        integration: Integration tests requiring external services
        performance: Performance and benchmark tests
        security: Security-focused tests
        slow: Tests that take a long time to run

Running Tests
~~~~~~~~~~~~~

Run different test categories::

    # All tests
    pytest
    
    # Unit tests only
    pytest -m unit
    
    # Integration tests (requires SSH server)
    pytest -m integration
    
    # Performance tests
    pytest -m performance
    
    # Skip slow tests
    pytest -m "not slow"
    
    # Run with coverage
    pytest --cov=spindlex --cov-report=html
    
    # Parallel execution
    pytest -n auto

Documentation Guidelines
------------------------

Documentation Structure
~~~~~~~~~~~~~~~~~~~~~~~

Documentation is built with Sphinx and includes:

- **API Reference**: Auto-generated from docstrings
- **User Guide**: Comprehensive usage documentation
- **Examples**: Practical code examples
- **Security Guide**: Security best practices

Writing Documentation
~~~~~~~~~~~~~~~~~~~~~

**Docstring Format** (Google Style)::

    def connect(
        self,
        hostname: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        pkey: Optional[PKey] = None,
        timeout: Optional[float] = None,
    ) -> None:
        """Connect to SSH server.
        
        Establishes an SSH connection to the specified server using the
        provided authentication credentials.
        
        Args:
            hostname: The hostname or IP address of the SSH server.
            port: The port number to connect to. Defaults to 22.
            username: Username for authentication. If None, will attempt
                to use current user's username.
            password: Password for authentication. Cannot be used with pkey.
            pkey: Private key for public key authentication. Cannot be
                used with password.
            timeout: Connection timeout in seconds. If None, uses default
                timeout.
        
        Raises:
            AuthenticationException: If authentication fails.
            ConnectionError: If connection cannot be established.
            ValueError: If invalid parameters are provided.
        
        Example:
            Basic password authentication::
            
                client = SSHClient()
                client.connect(
                    hostname='server.example.com',
                    username='user',
                    password='password'
                )
            
            Public key authentication::
            
                from spindlex.crypto.pkey import Ed25519Key
                
                private_key = Ed25519Key.from_private_key_file('/path/to/key')
                client = SSHClient()
                client.connect(
                    hostname='server.example.com',
                    username='user',
                    pkey=private_key
                )
        
        Note:
            The connection will be automatically closed when the client
            object is destroyed or when close() is called explicitly.
        """

**RST Documentation**::

    SSH Client Usage
    ================
    
    The SSH client provides a high-level interface for SSH operations.
    
    Basic Connection
    ----------------
    
    Connect to an SSH server::
    
        from spindlex import SSHClient
        
        client = SSHClient()
        client.connect('server.example.com', username='user', password='pass')
    
    .. note::
       Always close connections when finished to free resources.
    
    .. warning::
       Password authentication is less secure than key-based authentication.

Building Documentation
~~~~~~~~~~~~~~~~~~~~~~

Build documentation locally::

    cd docs
    
    # Build HTML documentation
    make html
    
    # Build PDF documentation
    make latexpdf
    
    # Clean build files
    make clean
    
    # Live reload during development
    sphinx-autobuild . _build/html

Security Guidelines
-------------------

Security Review Process
~~~~~~~~~~~~~~~~~~~~~~~

All security-related changes require:

1. **Security Review**: Code review by security-focused maintainer
2. **Threat Modeling**: Analysis of potential security implications
3. **Testing**: Comprehensive security testing
4. **Documentation**: Security implications documented

Secure Coding Practices
~~~~~~~~~~~~~~~~~~~~~~~~

1. **Input Validation**::

    def validate_hostname(hostname: str) -> str:
        """Validate hostname to prevent injection attacks."""
        if not hostname or len(hostname) > 255:
            raise ValueError("Invalid hostname length")
        
        # Check for valid characters
        import re
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            raise ValueError("Invalid hostname characters")
        
        return hostname

2. **Secure Random Generation**::

    import secrets
    
    def generate_session_id() -> str:
        """Generate cryptographically secure session ID."""
        return secrets.token_hex(32)

3. **Constant-Time Comparisons**::

    import hmac
    
    def secure_compare(a: bytes, b: bytes) -> bool:
        """Compare bytes in constant time to prevent timing attacks."""
        return hmac.compare_digest(a, b)

4. **Memory Clearing**::

    def clear_sensitive_data(data: bytearray) -> None:
        """Clear sensitive data from memory."""
        if isinstance(data, bytearray):
            data[:] = b'\x00' * len(data)

Vulnerability Reporting
~~~~~~~~~~~~~~~~~~~~~~~

If you discover a security vulnerability:

1. **Do NOT** create a public issue
2. **Email** di3z1e@proton.me with details
3. **Include** steps to reproduce the vulnerability
4. **Wait** for acknowledgment before public disclosure

Bug Reports and Feature Requests
---------------------------------

Bug Report Template
~~~~~~~~~~~~~~~~~~~

When reporting bugs, please include:

**Environment Information**:
- SpindleX version
- Python version
- Operating system
- SSH server type and version

**Bug Description**:
- Clear description of the issue
- Expected behavior
- Actual behavior
- Steps to reproduce

**Code Example**::

    # Minimal code example that reproduces the bug
    from spindlex import SSHClient
    
    client = SSHClient()
    # ... code that demonstrates the issue

**Error Messages**:
- Full error traceback
- Log messages (with sensitive data removed)

Feature Request Template
~~~~~~~~~~~~~~~~~~~~~~~~

When requesting features, please include:

**Use Case**:
- Description of the problem you're trying to solve
- Why existing functionality doesn't meet your needs

**Proposed Solution**:
- Detailed description of the desired feature
- API design suggestions
- Examples of how it would be used

**Alternatives**:
- Alternative solutions you've considered
- Workarounds you're currently using

Release Process
---------------

Version Numbering
~~~~~~~~~~~~~~~~~

I follow Semantic Versioning (SemVer):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

Examples:
- `1.0.0` → `1.0.1` (bug fix)
- `1.0.1` → `1.1.0` (new feature)
- `1.1.0` → `2.0.0` (breaking change)

Release Checklist
~~~~~~~~~~~~~~~~~

Before releasing a new version:

1. **Update Version Numbers**
   - `spindlex/_version.py`
   - `pyproject.toml`
   - `docs/conf.py`

2. **Update Documentation**
   - `CHANGELOG.md`
   - Release notes
   - API documentation

3. **Run Full Test Suite**
   - Unit tests
   - Integration tests
   - Performance tests
   - Security tests

4. **Build and Test Package**::

    # Build package
    python -m build
    
    # Test installation
    pip install dist/spindlex-*.whl
    
    # Test basic functionality
    python -c "import spindlex; print(spindlex.__version__)"

5. **Create Release**
   - Tag release: `git tag v1.0.0`
   - Push tag: `git push origin v1.0.0`
   - Create GitLab release
   - Upload to PyPI

Community Guidelines
--------------------

Code of Conduct
~~~~~~~~~~~~~~~

I am committed to providing a welcoming and inclusive environment:

1. **Be Respectful**: Treat all community members with respect
2. **Be Inclusive**: Welcome people of all backgrounds and identities
3. **Be Collaborative**: Work together constructively
4. **Be Patient**: Help others learn and grow
5. **Be Mindful**: Consider the impact of your words and actions

Communication Channels
~~~~~~~~~~~~~~~~~~~~~~

- **GitLab Issues**: Bug reports and feature requests
- **GitLab Discussions**: General questions and discussions
- **Email**: di3z1e@proton.me for security issues
- **Documentation**: Comprehensive guides and API reference

Getting Help
~~~~~~~~~~~~

If you need help contributing:

1. **Read the Documentation**: Start with this contributing guide
2. **Search Existing Issues**: Your question might already be answered
3. **Ask Questions**: Create a GitLab discussion for general questions
4. **Join the Community**: Participate in code reviews and discussions

Recognition
~~~~~~~~~~~

Contributors are recognized in:

- `CONTRIBUTORS.md` file
- Release notes
- GitLab contributors page
- Special recognition for significant contributions

Thank you for contributing to SpindleX! Your contributions help make secure SSH operations accessible to Python developers worldwide.