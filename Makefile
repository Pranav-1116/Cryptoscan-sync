.PHONY: help setup seed api worker test scan verify

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PY := $(ROOT)/.venv/bin/python
export CRYPTOSCAN_ROOT := $(ROOT)
export PYTHONPATH := $(ROOT)/shared/shared_config:$(ROOT)/shared/shared_logging:$(ROOT)/shared/shared_models:$(ROOT)/services/api:$(ROOT)/services/database:$(ROOT)/services/scanner:$(ROOT)/services/evidence:$(ROOT)/services/normalization:$(ROOT)/services/policy:$(ROOT)/services/drift:$(ROOT)/services/worker:$(ROOT)/services/deduplication:$(ROOT)/services/cbom:$(ROOT)/services/container_scanner

help:
	@echo "make setup  - create venv and install deps"
	@echo "make seed   - scan demo/vulnerable-app into SQLite"
	@echo "make api    - run the API + dashboard on :8000"
	@echo "make test   - run unit/integration tests"
	@echo "make scan REPO=local://demo/vulnerable-app"

setup:
	python3 -m venv $(ROOT)/.venv
	$(PY) -m pip install -U pip
	$(PY) -m pip install -r $(ROOT)/requirements.txt

seed:
	$(PY) $(ROOT)/scripts/seed_demo.py

api:
	$(PY) -m uvicorn api.main:app --host 0.0.0.0 --port 8000

worker:
	$(PY) -m worker.main

test:
	@for d in services/policy/tests services/evidence/tests services/normalization/tests services/scanner/tests services/database/tests/unit services/drift/tests services/worker/tests/unit services/api/tests/unit services/api/tests/integration services/deduplication/tests services/cbom/tests services/container_scanner/tests; do \
		echo "===== $$d ====="; \
		$(PY) -m pytest -q $$d || exit 1; \
	done

scan:
	$(PY) $(ROOT)/scripts/trigger_scan.py "$(REPO)" --inline

verify:
	$(PY) $(ROOT)/scripts/verify_evidence.py $(SCAN_ID)

up:
	docker compose up --build -d

down:
	docker compose down
