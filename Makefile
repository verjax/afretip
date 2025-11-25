# Threat Intelligence Pipeline Makefile

.PHONY: help install install-dev test lint format clean run docker-build docker-run

help:  ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $1, $2}'

install:  ## Install production dependencies
	pip install -r requirements.txt
	pip install -e .

install-dev:  ## Install development dependencies
	pip install -r requirements-dev.txt
	pip install -e .
	pre-commit install

test:  ## Run tests
	pytest tests/ -v --cov=src/threat_intel --cov-report=html

lint:  ## Run linting
	ruff check src/ tests/
	mypy src/

format:  ## Format code
	ruff format src/ tests/
	ruff check --fix src/ tests/

clean:  ## Clean build artifacts
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -delete

run:  ## Run the pipeline
	python -m src.threat_intel.main

docker-build:  ## Build Docker image
	docker build -t threat-intel-pipeline .

docker-run:  ## Run with Docker Compose
	docker-compose up --build

setup-config:  ## Setup configuration from example
	cp config/config.yaml.example config/config.yaml
	@echo "Edit config/config.yaml with your settings"
