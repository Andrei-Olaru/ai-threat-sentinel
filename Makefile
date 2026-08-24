.PHONY: help install dev test lint format check docker-up docker-down run clean

help: ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Setup ---
install: ## Install production dependencies
	pip install -e .

dev: ## Install all dependencies (production + dev tools)
	pip install -e ".[dev]"

# --- Quality ---
test: ## Run test suite
	python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	python -m pytest tests/ -v --tb=short --cov=sentinel --cov-report=term-missing

lint: ## Run linter (ruff)
	python -m ruff check src/ tests/

format: ## Auto-format code (ruff)
	python -m ruff format src/ tests/
	python -m ruff check --fix src/ tests/

typecheck: ## Run static type checker (mypy)
	python -m mypy src/sentinel/

check: lint typecheck test ## Run all quality checks (lint + types + tests)

# --- Run ---
run: ## Start dev server with hot-reload
	python -m uvicorn sentinel.main:app --host 127.0.0.1 --port 8000 --reload

# --- Docker ---
docker-up: ## Start all services (PostgreSQL, Redis, App)
	docker compose -f docker/docker-compose.yml up -d

docker-down: ## Stop all services and remove volumes
	docker compose -f docker/docker-compose.yml down -v

docker-build: ## Build Docker image
	docker build -f docker/Dockerfile -t sentinel:latest .

docker-logs: ## Tail logs from all containers
	docker compose -f docker/docker-compose.yml logs -f

# --- Database ---
db-migrate: ## Run database migrations
	python -m alembic upgrade head

db-revision: ## Create new migration (usage: make db-revision msg="add alerts table")
	python -m alembic revision --autogenerate -m "$(msg)"

# --- Cleanup ---
clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf dist/ build/ *.egg-info
