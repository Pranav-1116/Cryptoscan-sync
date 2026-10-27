.PHONY: help setup api worker test test-serial test-live test-frontend test-all scan verify

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
# Prefer the repo-standard .venv created by `make setup`; fall back to a venv/
# (used in environments where .venv is not writable/persisted).
PY := $(shell if [ -x "$(ROOT)/.venv/bin/python" ]; then echo "$(ROOT)/.venv/bin/python"; elif [ -x "$(ROOT)/venv/bin/python" ]; then echo "$(ROOT)/venv/bin/python"; else echo "$(ROOT)/.venv/bin/python"; fi)
export CRYPTOSCAN_ROOT := $(ROOT)
# Auto-discover every service/shared package so the path never goes stale when
# a new microservice is added (previously a hardcoded list that omits 16 dirs).
# This mirrors the Docker image, which registers all packages via a generated
# .pth file. The PATH is also populated by .venv/lib/python*/site-packages/
# cryptoscan.pth when the venv is created via `make setup`.
export PYTHONPATH := $(shell find $(ROOT)/services $(ROOT)/shared -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')

help:
	@echo "make setup  - create venv and install deps"
	@echo "make api    - run the API on :8010 (frontend: cd frontend && npm run dev → :3003)"
	@echo "make test   - run unit/integration tests"
	@echo "make scan REPO=<authorized repository or local path>"

setup:
	python3 -m venv $(ROOT)/.venv
	$(PY) -m pip install -U pip
	$(PY) -m pip install -r $(ROOT)/requirements.txt

api:
	$(PY) -m uvicorn api.main:app --host 0.0.0.0 --port 8010 --proxy-headers --forwarded-allow-ips='*'

worker:
	$(PY) -m worker.main

lock:
	@echo "# Pinning to the exact versions the test gate ran against"; 	$(PY) -m pip freeze --exclude-editable | grep -vE '^(pip|setuptools|wheel)==' > requirements.lock.txt; 	echo "wrote requirements.lock.txt ($$(wc -l < requirements.lock.txt) pins)"

# Every suite in one hermetic, parallel pytest run (xdist across all CPUs;
# pytest-socket blocks any non-loopback network call). ~4 min on 2 cores,
# was ~25+ min serial. `make test-serial` keeps the old one-suite-at-a-time
# loop for bisecting; `make test-live` opts into the network-dependent tests.
TEST_DIRS := $(shell find $(ROOT)/services $(ROOT)/shared -type d -name tests -not -path '*/node_modules/*' | sed 's|$(ROOT)/||' | sort)
JOBS ?= auto

test:
	$(PY) -m pytest -q -n $(JOBS) --dist loadfile $(TEST_DIRS)

test-serial:
	@for d in $(TEST_DIRS); do \
		echo "===== $$d ====="; \
		$(PY) -m pytest -q -p no:xdist $$d || exit 1; \
	done

test-frontend:
	cd $(ROOT)/frontend && npm run typecheck && npm test

test-all: test test-frontend

test-live:
	$(PY) -m pytest -q -n $(JOBS) -m live --override-ini='addopts=--import-mode=importlib' $(TEST_DIRS)

monitor:
	$(PY) $(ROOT)/scripts/run_monitor.py

monitor-once:
	$(PY) $(ROOT)/scripts/run_monitor.py --once

load-test: ## $(make load-test URL=… USERS=20 DURATION=60 PASSWORD=…)
	$(PY) $(ROOT)/scripts/load_test.py --url $(or $(URL),http://localhost:8010) --users $(or $(USERS),10) --duration $(or $(DURATION),30) --password '$(PASSWORD)'

scan:
	@test -n "$(REPO)" || (echo "REPO is required; provide an authorized repository or local path" >&2; exit 2)
	$(PY) $(ROOT)/scripts/trigger_scan.py "$(REPO)" --inline

verify:
	$(PY) $(ROOT)/scripts/verify_evidence.py $(SCAN_ID)

verify-pack:
	$(PY) $(ROOT)/scripts/verify_pack.py $(PACK) $(if $(SECRET),--secret $(SECRET),)

gate:
	$(PY) $(ROOT)/scripts/ci_gate.py --scan-id "$(SCAN_ID)"

# ── Docker / Compose ─────────────────────────────────────────────────
# Full stack: postgres + redis + neo4j + api + worker + monitor + frontend + nginx.
#   make docker-build     build all images (no cache problems: layers cached)
#   make docker-up        build (if needed) and start the stack detached
#   make docker-down      stop and remove containers (keeps volumes/data)
#   make docker-purge     stop and remove containers AND volumes (wipe data)
#   make docker-logs      tail logs for the whole stack
#   make docker-rebuild   force a clean rebuild of the images
COMPOSE ?= docker compose

docker-build:
	$(COMPOSE) build

docker-up:
	$(COMPOSE) up --build -d

docker-down:
	$(COMPOSE) down

docker-purge:
	$(COMPOSE) down -v

docker-rebuild:
	$(COMPOSE) build --no-cache

docker-logs:
	$(COMPOSE) logs -f --tail=200

docker-ps:
	$(COMPOSE) ps

# production stack (uses .env with strong secrets; see docker-compose.prod.yml)
docker-up-prod:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml up --build -d

docker-down-prod:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml down

up: docker-up
down: docker-down

.PHONY: smoke security-scan sbom backup help-prod

# ---- production operations -------------------------------------------------
help-prod: ## production operations
	@echo "make release-check - release gate: VERSION/tag/changelog/migrations/prod-guard"
	@echo "make smoke         - post-deploy smoke test (BASE, SMOKE_USER, SMOKE_PASSWORD environment)"
	@echo "make security-scan - pip-audit + ruff gate + secret hygiene (release gate)"
	@echo "make sbom          - generate the platform's own CycloneDX SBOM"
	@echo "make backup        - database backup via scripts/db_backup.sh"
	@echo "make docker-up-prod-tls - production stack with the TLS overlay"

release-check:
	$(PY) $(ROOT)/scripts/release_check.py

smoke:
	BASE=$(or $(BASE),http://localhost:8080) SMOKE_USER='$(or $(SMOKE_USER),admin)' bash $(ROOT)/scripts/smoke_test.sh

security-scan:
	bash $(ROOT)/scripts/security_scan.sh

sbom:
	$(PY) $(ROOT)/scripts/generate_own_sbom.py

backup:
	bash $(ROOT)/scripts/db_backup.sh

docker-up-prod-tls:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.tls.yml up --build -d
