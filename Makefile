.PHONY: help setup test lint format docs build clean docker-test

PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest

help:
	@echo "🛠️ SpindleX Development Makefile"
	@echo ""
	@echo "Available commands:"
	@echo "  setup       Install development dependencies"
	@echo "  test        Run all tests"
	@echo "  docker-test Run integration tests using docker-compose"
	@echo "  lint        Run linting checks (black, isort, flake8, mypy)"
	@echo "  format      Auto-format code (black, isort)"
	@echo "  docs        Build documentation locally"
	@echo "  build       Build package distribution"
	@echo "  clean       Remove build and test artifacts"

setup:
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev,test,async,docs]
	pre-commit install

test:
	$(PYTEST) tests/ -v --cov=spindlex

docker-test:
	docker-compose up --build --exit-code-from tests

lint:
	black --check spindlex tests
	isort --check-only spindlex tests
	pflake8 spindlex tests
	mypy spindlex

format:
	black spindlex tests
	isort spindlex tests

docs:
	sphinx-build -b html docs/ docs/_build/html
	@echo "📖 Docs built at docs/_build/html/index.html"

build:
	$(PYTHON) -m build

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/ .mypy_cache docs/_build/
	find . -type d -name "__pycache__" -exec rm -rf {} +
