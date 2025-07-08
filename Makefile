# BSV HD Wallet Key Derivation Tool - Development Tools

.PHONY: help install format lint check test test-cov clean all run-cli

# Default target
help:
	@echo "Available commands:"
	@echo "  install   - Install dependencies in virtual environment"
	@echo "  format    - Format code with black and isort"
	@echo "  lint      - Run all linters (flake8, pylint, mypy)"
	@echo "  check     - Run format check without making changes"
	@echo "  test      - Run unit tests with pytest"
	@echo "  test-cov  - Run tests with coverage report"
	@echo "  clean     - Clean up cache files"
	@echo "  run-cli   - Run the CLI application"
	@echo "  all       - Run format, lint, and test"

# Install dependencies
install:
	@echo "🔧 Setting up virtual environment and installing dependencies..."
	python3 -m venv venv
	./venv/bin/pip install --upgrade pip
	./venv/bin/pip install -r requirements.txt
	./venv/bin/pip install -r requirements-dev.txt
	./venv/bin/pip install -e .
	@echo "✅ Installation complete! Use 'make run-cli' to start the application"

# Format code
format:
	@echo "🎨 Formatting code with black..."
	./venv/bin/black . --exclude venv
	@echo "📦 Sorting imports with isort..."
	./venv/bin/isort . --skip venv
	@echo "✅ Formatting complete!"

# Check formatting without making changes
check:
	@echo "🔍 Checking code format..."
	./venv/bin/black --check --diff . --exclude venv
	./venv/bin/isort --check-only --diff . --skip venv

# Run linters
lint:
	@echo "🔎 Running flake8..."
	./venv/bin/flake8 . --exclude=venv
	@echo "🔍 Running pylint..."
	./venv/bin/pylint xprv_gen tests --ignore=venv
	@echo "🎯 Running mypy..."
	./venv/bin/mypy xprv_gen tests --exclude venv
	@echo "✅ Linting complete!"

# Run unit tests
test:
	@echo "🧪 Running unit tests..."
	./venv/bin/pytest tests/ -v
	@echo "✅ Tests complete!"

# Run tests with coverage
test-cov:
	@echo "🧪 Running tests with coverage..."
	./venv/bin/pytest tests/ -v --cov=xprv_gen --cov-report=term-missing --cov-report=html
	@echo "📊 Coverage report generated in htmlcov/"
	@echo "✅ Tests with coverage complete!"

# Clean cache files
clean:
	@echo "🧹 Cleaning cache files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ 2>/dev/null || true
	rm -rf .coverage 2>/dev/null || true
	@echo "✅ Cleanup complete!"

# Run everything
all: format lint test
	@echo "🎉 All checks passed!"

# Run the CLI application
run-cli:
	@echo "🚀 Running BSV HD Wallet Key Derivation Tool..."
	./venv/bin/python -m xprv_gen.cli

# Run the legacy test mode (for backwards compatibility)
run-test-mode:
	@echo "🧪 Running legacy test mode..."
	./venv/bin/python -m xprv_gen.cli test 