# Contributing Guide

We welcome contributions to SpindleX! This guide will help you get started with contributing code, documentation, bug reports, and feature requests.

## Getting Started

### Development Environment Setup

1.  **Fork and Clone the Repository**:
    ```bash
    git clone https://github.com/Di3Z1E/spindlex.git
    cd spindlex
    ```

2.  **Set Up Development Environment**:
    ```bash
    # Create virtual environment
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    
    # Install development dependencies
    pip install -e ".[dev,test,docs]"
    
    # Install pre-commit hooks
    pre-commit install
    ```

3.  **Verify Installation**:
    ```bash
    # Run tests to ensure everything works
    pytest
    
    # Check code style
    flake8 spindlex/
    ```

### Development Workflow

1.  **Create a Feature Branch**:
    ```bash
    git checkout -b feature/your-feature-name
    ```

2.  **Make Your Changes**:
    *   Write code following the style guidelines.
    *   Add tests for new functionality.
    *   Update documentation as needed.

3.  **Test Your Changes**:
    ```bash
    # Run full test suite
    pytest
    
    # Check code coverage
    pytest --cov=spindlex --cov-report=term
    ```

4.  **Commit Your Changes**:
    Use [Conventional Commits](https://www.conventionalcommits.org/):
    *   `feat`: New feature
    *   `fix`: Bug fix
    *   `docs`: Documentation changes
    *   `style`: Formatting changes
    *   `refactor`: Code refactoring
    *   `test`: Adding tests
    *   `chore`: Maintenance tasks

5.  **Push and Create Pull Request**:
    ```bash
    git push origin feature/your-feature-name
    ```

## Code Style and Standards

### Python Code Style

We follow PEP 8 with these tools:

*   **Line Length**: 88 characters (Black default).
*   **Imports**: Sorted with `isort`.
*   **Type Hints**: Required for all public APIs.
*   **Docstrings**: Google-style docstrings.

### Code Formatting Tools

```bash
# Black for formatting
black spindlex/ tests/

# isort for imports
isort spindlex/ tests/

# flake8 for linting
flake8 spindlex/ tests/

# mypy for type checking
mypy spindlex/
```

## Testing Guidelines

### Test Structure

*   **Unit Tests** (`tests/`): Test individual components.
*   **Integration Tests**: Requiring real SSH servers (marked with `@pytest.mark.integration`).
*   **Performance Tests**: Benchmarks (marked with `@pytest.mark.performance`).

### Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest -m unit

# Skip slow tests
pytest -m "not slow"

# Run with coverage
pytest --cov=spindlex --cov-report=html
```

## Documentation Guidelines

Documentation is built with **MkDocs** and **Material for MkDocs**.

### Writing Documentation

*   Use Markdown for all documentation files.
*   Follow the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html) for docstrings.
*   Use `mkdocstrings` for API reference generation.

### Building Documentation

```bash
# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build
```

## Security Guidelines

If you discover a security vulnerability:

1.  **Do NOT** create a public issue.
2.  **Use GitHub Security Advisory** to report it privately.
3.  **Include** steps to reproduce the vulnerability.
4.  **Wait** for acknowledgment before public disclosure.

---

Thank you for contributing to SpindleX! Your contributions help make secure SSH operations accessible to Python developers worldwide.
