# CrypTek Makefile
# Simple commands for development and building

.PHONY: help install install-dev test clean build build-cli build-gui run lint format

# Default target
help:
	@echo "CrypTek Development Commands:"
	@echo ""
	@echo "  install     Install core dependencies"
	@echo "  install-dev Install development dependencies"
	@echo "  test        Run test suite"
	@echo "  clean       Clean build artifacts"
	@echo "  build       Build all executables"
	@echo "  build-cli   Build CLI executable only"
	@echo "  build-gui   Build GUI executable only"
	@echo "  run         Run CLI with --help"
	@echo "  run-gui     Launch GUI application"
	@echo "  lint        Run code linting"
	@echo "  format      Format code with black"
	@echo ""

# Install core dependencies
install:
	pip install -r requirements.txt

# Install with development dependencies
install-dev:
	pip install -e ".[dev]"

# Run tests
test:
	python -m pytest tests/ -v

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.spec
	find . -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -delete

# Build all executables
build:
	python scripts/build_new.py

# Build CLI only
build-cli:
	python scripts/build_new.py --cli-only

# Build GUI only
build-gui:
	python scripts/build_new.py --gui-only

# Run CLI help
run:
	python cryptek.py --help

# Launch GUI
run-gui:
	python cryptek_gui.py

# Run linting (if tools are installed)
lint:
	@command -v flake8 >/dev/null 2>&1 && flake8 src/ || echo "flake8 not installed"
	@command -v mypy >/dev/null 2>&1 && mypy src/ || echo "mypy not installed"

# Format code (if black is installed)
format:
	@command -v black >/dev/null 2>&1 && black src/ tests/ || echo "black not installed"
	@command -v isort >/dev/null 2>&1 && isort src/ tests/ || echo "isort not installed"