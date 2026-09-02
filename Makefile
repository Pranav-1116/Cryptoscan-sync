.PHONY: help setup seed api worker test scan verify

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PY := $(ROOT)/.venv/bin/python
export CRYPTOSCAN_ROOT := $(ROOT)
export PYTHONPATH := $(ROOT)/services/universal_crypto:$(ROOT)/services/universal_vendor:$(ROOT)/shared/shared_config:$(ROOT)/shared/shared_logging:$(ROOT)/shared/shared_models:$(ROOT)/services/api:$(ROOT)/services/database:$(ROOT)/services/scanner:$(ROOT)/services/evidence:$(ROOT)/services/normalization:$(ROOT)/services/policy:$(ROOT)/services/drift:$(ROOT)/services/worker:$(ROOT)/services/deduplication:$(ROOT)/services/cbom:$(ROOT)/services/container_scanner:$(ROOT)/services/network_scanner:$(ROOT)/services/cloud_scanner:$(ROOT)/services/runtime:$(ROOT)/services/graph_engine:$(ROOT)/services/business_context:$(ROOT)/services/quantum:$(ROOT)/services/remediation:$(ROOT)/services/reporting:$(ROOT)/services/ot_scanner:$(ROOT)/services/vendor_intel:$(ROOT)/services/agility:$(ROOT)/services/payment_crypto:$(ROOT)/services/universal_platform

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

up:
	docker compose up --build -d

down:
	docker compose down
