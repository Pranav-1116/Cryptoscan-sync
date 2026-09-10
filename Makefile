.PHONY: help setup seed api worker test scan verify

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
	@echo "make seed   - scan demo/vulnerable-app into SQLite"
	@echo "make api    - run the API on :8010 (frontend: cd frontend && npm run dev → :3003)"
	@echo "make test   - run unit/integration tests"
	@echo "make scan REPO=local://demo/vulnerable-app"

setup:
	python3 -m venv $(ROOT)/.venv
	$(PY) -m pip install -U pip
	$(PY) -m pip install -r $(ROOT)/requirements.txt

seed:
	$(PY) $(ROOT)/scripts/seed_demo.py

api:
	$(PY) -m uvicorn api.main:app --host 0.0.0.0 --port 8010 --proxy-headers --forwarded-allow-ips='*'

worker:
	$(PY) -m worker.main

lock:
	@echo "# Pinning to the exact versions the test gate ran against"; 	$(PY) -m pip freeze --exclude-editable | grep -vE '^(pip|setuptools|wheel)==' > requirements.lock.txt; 	echo "wrote requirements.lock.txt ($$(wc -l < requirements.lock.txt) pins)"

test:
	@for d in services/policy/tests services/evidence/tests services/normalization/tests services/scanner/tests services/database/tests/unit services/drift/tests services/worker/tests/unit services/api/tests/unit services/api/tests/integration services/deduplication/tests services/cbom/tests services/container_scanner/tests services/network_scanner/tests services/cloud_scanner/tests services/runtime/tests services/graph_engine/tests services/business_context/tests services/quantum/tests services/remediation/tests services/reporting/tests services/ot_scanner/tests services/vendor_intel/tests services/agility/tests services/payment_crypto/tests services/universal_vendor/tests services/universal_crypto/tests services/universal_platform/tests services/sector_profiles/tests shared/shared_models/tests; do \
		echo "===== $$d ====="; \
		$(PY) -m pytest -q $$d || exit 1; \
	done

monitor:
	$(PY) $(ROOT)/scripts/run_monitor.py

monitor-once:
	$(PY) $(ROOT)/scripts/run_monitor.py --once

load-test: ## $(make load-test URL=… USERS=20 DURATION=60 PASSWORD=…)
	$(PY) $(ROOT)/scripts/load_test.py --url $(or $(URL),http://localhost:8010) --users $(or $(USERS),10) --duration $(or $(DURATION),30) --password '$(PASSWORD)'

scan:
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
	@echo "make smoke         - post-deploy smoke test (BASE=… USER=… PASSWORD=…)"
	@echo "make security-scan - pip-audit + ruff gate + secret hygiene (release gate)"
	@echo "make sbom          - generate the platform's own CycloneDX SBOM"
	@echo "make backup        - database backup via scripts/db_backup.sh"
	@echo "make docker-up-prod-tls - production stack with the TLS overlay"

release-check:
	$(PY) $(ROOT)/scripts/release_check.py

smoke:
	BASE=$(or $(BASE),http://localhost:8080) USER='$(or $(USER),admin)' PASSWORD='$(or $(PASSWORD),cryptoscan)' bash $(ROOT)/scripts/smoke_test.sh

security-scan:
	bash $(ROOT)/scripts/security_scan.sh

sbom:
	$(PY) $(ROOT)/scripts/generate_own_sbom.py

backup:
	bash $(ROOT)/scripts/db_backup.sh

docker-up-prod-tls:
	$(COMPOSE) -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.tls.yml up --build -d
