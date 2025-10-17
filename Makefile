# Makefile for SpindleX development tasks

.PHONY: help install install-dev test test-all lint format type-check security clean build docs serve-docs release

# Default target
help:
	@echo "SpindleX Development Commands"
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
	@echo "  setup-ci     Setup GitLab CI variables for PyPI deployment"
	@echo "  release-patch Create a patch release (0.0.X)"
	@echo "  release-minor Create a minor release (0.X.0)"
	@echo "  release-major Create a major release (X.0.0)"
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
	pytest tests/ -v --cov=spindlex --cov-report=html --cov-report=term

test-integration:
	pytest tests/ -v -m integration

test-unit:
	pytest tests/ -v -m unit

test-performance:
	pytest tests/ -v -m performance

# Code Quality
lint: format type-check security
	flake8 spindlex tests

format:
	black spindlex tests
	isort spindlex tests

type-check:
	mypy spindlex

security:
	bandit -r spindlex -f json -o bandit-report.json
	bandit -r spindlex

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
	python -m spindlex.tools.benchmark --crypto-only

keygen:
	python -m spindlex.tools.keygen -t ed25519 -f test_keys/test_ed25519
	python -m spindlex.tools.keygen -t rsa -b 2048 -f test_keys/test_rsa

# Pre-commit hooks
pre-commit:
	pre-commit run --all-files

# Docker support (if needed)
docker-build:
	docker build -t spindlex .

docker-test:
	docker run --rm spindlex pytest

# CI/CD helpers
ci-install:
	pip install --upgrade pip
	pip install -e .[dev]

ci-test:
	pytest tests/ -v --cov=spindlex --cov-report=xml

ci-lint:
	black --check spindlex tests
	isort --check-only spindlex tests
	flake8 spindlex tests
	mypy spindlex
	bandit -r spindlex

# CI/CD Setup
setup-ci:
	python scripts/setup-ci-variables.py

# Release management
release-patch:
	@echo "Creating patch release..."
	@read -p "Enter patch version (e.g., 0.2.1): " version; \
	python scripts/release.py --version $$version --type patch

release-minor:
	@echo "Creating minor release..."
	@read -p "Enter minor version (e.g., 0.3.0): " version; \
	python scripts/release.py --version $$version --type minor

release-major:
	@echo "Creating major release..."
	@read -p "Enter major version (e.g., 1.0.0): " version; \
	python scripts/release.py --version $$version --type major

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