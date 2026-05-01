.PHONY: help setup test lint format docs build clean docker-test

PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest

help:
	@echo "SpindleX Development Makefile"
	@echo ""
	@echo "Available commands:"
	@echo "  setup       Install development dependencies"
	@echo "  test        Run all tests"
	@echo "  docker-test Run Docker-backed integration tests"
	@echo "  lint        Run linting checks (ruff, mypy)"
	@echo "  format      Auto-format code with Ruff"
	@echo "  docs        Build documentation locally"
	@echo "  build       Build package distribution"
	@echo "  clean       Remove build and test artifacts"

setup:
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev,test,docs]
	pre-commit install

test:
	$(PYTEST) tests/ -v --cov=spindlex

docker-test:
	$(PYTEST) tests/integration tests/real_server tests/misc/test_functional_integration.py \
		-v -m "integration or real_server" --tb=short --timeout=120

lint:
	ruff check spindlex tests
	ruff format --check spindlex tests
	mypy spindlex

format:
	ruff check --fix spindlex tests
	ruff format spindlex tests

docs:
	mkdocs build --strict
	@echo "Docs built in site/"

build:
	$(PYTHON) -m build

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/ .mypy_cache docs/_build/ site/
	find . -type d -name "__pycache__" -exec rm -rf {} +
