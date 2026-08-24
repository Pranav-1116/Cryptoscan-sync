.PHONY: help setup build up down logs test lint migrate seed scan verify

SHELL := /bin/bash
PYTHON := python3
DOCKER_COMPOSE := docker compose

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Bootstrap local development environment
	@bash scripts/dev_setup.sh

build: ## Build all Docker images
	$(DOCKER_COMPOSE) build

up: ## Start all services
	$(DOCKER_COMPOSE) up -d
	@echo "Services started. Dashboard: http://localhost:3000 | API: http://localhost:8000"

down: ## Stop all services
	$(DOCKER_COMPOSE) down

logs: ## Tail logs for all services
	$(DOCKER_COMPOSE) logs -f

logs-api: ## Tail API logs
	$(DOCKER_COMPOSE) logs -f api

logs-worker: ## Tail worker logs
	$(DOCKER_COMPOSE) logs -f worker

migrate: ## Run database migrations
	@bash scripts/run_migrations.sh

seed: ## Seed test data into development database
	@bash scripts/seed_test_data.sh

test: ## Run all tests
	@echo "Running scanner tests..."
	cd services/scanner && python -m pytest tests/ -v --tb=short
	@echo "Running evidence tests..."
	cd services/evidence && python -m pytest tests/ -v --tb=short
	@echo "Running database tests..."
	cd services/database && python -m pytest tests/ -v --tb=short
	@echo "Running normalization tests..."
	cd services/normalization && python -m pytest tests/ -v --tb=short
	@echo "Running policy tests..."
	cd services/policy && python -m pytest tests/ -v --tb=short
	@echo "Running drift tests..."
	cd services/drift && python -m pytest tests/ -v --tb=short
	@echo "Running API tests..."
	cd services/api && python -m pytest tests/ -v --tb=short

test-scanner: ## Run scanner tests only
	cd services/scanner && python -m pytest tests/ -v --tb=short

test-evidence: ## Run evidence tests only
	cd services/evidence && python -m pytest tests/ -v --tb=short

test-api: ## Run API tests only
	cd services/api && python -m pytest tests/ -v --tb=short

lint: ## Run linting across all Python services
	@for service in scanner evidence database normalization policy drift api worker; do \
		echo "Linting services/$$service..."; \
		cd services/$$service && ruff check . && cd ../..; \
	done

format: ## Auto-format all Python code
	@for service in scanner evidence database normalization policy drift api worker; do \
		echo "Formatting services/$$service..."; \
		cd services/$$service && ruff format . && cd ../..; \
	done

scan: ## Trigger a manual scan (usage: make scan REPO=https://github.com/org/repo)
	@$(PYTHON) scripts/trigger_scan.py --repo "$(REPO)"

approve-baseline: ## Approve a scan as baseline (usage: make approve-baseline SCAN_ID=uuid)
	@$(PYTHON) scripts/approve_baseline.py --scan-id "$(SCAN_ID)"

verify: ## Verify evidence integrity (usage: make verify SCAN_ID=uuid)
	@$(PYTHON) scripts/verify_evidence.py --scan-id "$(SCAN_ID)"

export: ## Export findings (usage: make export SCAN_ID=uuid FORMAT=json)
	@$(PYTHON) scripts/export_findings.py --scan-id "$(SCAN_ID)" --format "$(FORMAT)"

clean: ## Remove all containers, volumes, and temp files
	$(DOCKER_COMPOSE) down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete