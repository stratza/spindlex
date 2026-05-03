.PHONY: help setup lint test integration docs build clean

PYTHON ?= python
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest

help:
	@echo "SpindleX development commands"
	@echo ""
	@echo "  setup        Install development, test, and docs dependencies"
	@echo "  lint         Run Ruff and mypy checks"
	@echo "  test         Run the fast unit test suite"
	@echo "  integration  Run Docker-backed integration tests"
	@echo "  docs         Build MkDocs documentation"
	@echo "  build        Build wheel and source distribution"
	@echo "  clean        Remove local build/test artifacts"

setup:
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,test,docs]"
	pre-commit install

lint:
	ruff check spindlex tests
	ruff format --check spindlex tests
	mypy spindlex

test:
	$(PYTEST) tests -m "not integration and not real_server and not slow and not performance"

integration:
	$(PYTEST) tests/integration tests/real_server tests/misc/test_functional_integration.py \
		-m "integration or real_server" \
		--tb=short \
		--timeout=120 \
		--timeout-method=thread

docs:
	mkdocs build --strict

build:
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .coverage htmlcov/ .mypy_cache site/
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
