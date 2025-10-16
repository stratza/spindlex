# Makefile for SSH Library development tasks

.PHONY: help install install-dev test test-all lint format type-check security clean build docs serve-docs release

# Default target
help:
	@echo "SSH Library Development Commands"
	@echo "================================"
	@echo ""
	@echo "Setup:"
	@echo "  install      Install package in current environment"
	@echo "  install-dev  Install package with development dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test         Run tests with pytest"
	@echo "  test-all     Run tests across all supported Python versions with tox"
	@echo "  test-cov     Run tests with coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint         Run all linting tools"
	@echo "  format       Format code with black and isort"
	@echo "  type-check   Run type checking with mypy"
	@echo "  security     Run security scanning with bandit"
	@echo ""
	@echo "Documentation:"
	@echo "  docs         Build documentation"
	@echo "  serve-docs   Serve documentation locally"
	@echo ""
	@echo "Build & Release:"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build wheel and source distribution"
	@echo "  release      Build and upload to PyPI (requires credentials)"
	@echo ""
	@echo "Utilities:"
	@echo "  benchmark    Run performance benchmarks"
	@echo "  keygen       Generate test SSH keys"

# Installation
install:
	pip install -e .

install-dev:
	pip install -e .[dev,docs,async,gssapi]
	pre-commit install

# Testing
test:
	pytest tests/ -v

test-all:
	tox

test-cov:
	pytest tests/ -v --cov=ssh_library --cov-report=html --cov-report=term

test-integration:
	pytest tests/ -v -m integration

test-unit:
	pytest tests/ -v -m unit

test-performance:
	pytest tests/ -v -m performance

# Code Quality
lint: format type-check security
	flake8 ssh_library tests

format:
	black ssh_library tests
	isort ssh_library tests

type-check:
	mypy ssh_library

security:
	bandit -r ssh_library -f json -o bandit-report.json
	bandit -r ssh_library

# Documentation
docs:
	cd docs && make html

serve-docs:
	cd docs/_build/html && python -m http.server 8000

docs-clean:
	cd docs && make clean

# Build & Release
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .tox/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	python -m build

release: build
	python -m twine check dist/*
	python -m twine upload dist/*

# Development utilities
benchmark:
	python -m ssh_library.tools.benchmark --crypto-only

keygen:
	python -m ssh_library.tools.keygen -t ed25519 -f test_keys/test_ed25519
	python -m ssh_library.tools.keygen -t rsa -b 2048 -f test_keys/test_rsa

# Pre-commit hooks
pre-commit:
	pre-commit run --all-files

# Docker support (if needed)
docker-build:
	docker build -t ssh-library .

docker-test:
	docker run --rm ssh-library pytest

# CI/CD helpers
ci-install:
	pip install --upgrade pip
	pip install -e .[dev]

ci-test:
	pytest tests/ -v --cov=ssh_library --cov-report=xml

ci-lint:
	black --check ssh_library tests
	isort --check-only ssh_library tests
	flake8 ssh_library tests
	mypy ssh_library
	bandit -r ssh_library

# Version management
version-patch:
	python scripts/release.py patch

version-minor:
	python scripts/release.py minor

version-major:
	python scripts/release.py major

# Database/cache cleanup
clean-cache:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/

# Development server (for testing)
dev-server:
	python examples/ssh_server_example.py

# Install git hooks
hooks:
	pre-commit install
	pre-commit install --hook-type commit-msg

# Check dependencies for security vulnerabilities
check-deps:
	safety check
	pip-audit

# Generate requirements files
requirements:
	pip-compile pyproject.toml --output-file requirements.txt
	pip-compile pyproject.toml --extra dev --output-file requirements-dev.txt

# Update dependencies
update-deps:
	pip-compile --upgrade pyproject.toml --output-file requirements.txt
	pip-compile --upgrade pyproject.toml --extra dev --output-file requirements-dev.txt