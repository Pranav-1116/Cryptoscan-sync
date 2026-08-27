# CryptoScan Scanner — service-local developer targets.
#
# The repo-root Makefile orchestrates the whole platform (venv, seed, api,
# full test suite). Use this one for scanner-only inner loops.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
PROJECT_ROOT := $(abspath $(ROOT)/../..)
PY := $(if $(wildcard $(PROJECT_ROOT)/.venv/bin/python),$(PROJECT_ROOT)/.venv/bin/python,python3)

export CRYPTOSCAN_ROOT := $(PROJECT_ROOT)
export PYTHONPATH := $(ROOT):$(PROJECT_ROOT)/shared/shared_config:$(PROJECT_ROOT)/shared/shared_logging:$(PROJECT_ROOT)/shared/shared_models

.PHONY: help test unit integration lint scan schema build clean

help:
	@echo "make test         - run the full scanner test suite"
	@echo "make unit         - unit tests only"
	@echo "make integration  - integration tests (incl. full pipeline scan)"
	@echo "make lint         - ruff check (F401,F811,F821,E9 gate)"
	@echo "make scan REPO=path|url   - scan a repository via the CLI"
	@echo "make schema       - regenerate scanner/output/schema/scan_result_schema.json"
	@echo "make build        - build the cryptoscan-scanner wheel"

test:
	$(PY) -m pytest -q $(ROOT)/tests

unit:
	$(PY) -m pytest -q $(ROOT)/tests/unit

integration:
	$(PY) -m pytest -q $(ROOT)/tests/integration

lint:
	$(PY) -m ruff check $(ROOT)/scanner $(ROOT)/tests --select F401,F811,F821,E9

scan:
	$(PY) -m scanner.main scan "$(REPO)" --output json

schema:
	$(PY) -c "import json,pathlib;from scanner.models.scan_result import ScanResult;p=pathlib.Path('$(ROOT)/scanner/output/schema/scan_result_schema.json');p.write_text(json.dumps(ScanResult.model_json_schema(),indent=2,sort_keys=True)+'\n');print('wrote',p)"

build:
	$(PY) -m pip wheel --no-deps -w $(ROOT)/dist $(ROOT)

clean:
	rm -rf $(ROOT)/dist $(ROOT)/.pytest_cache
	find $(ROOT) -name __pycache__ -type d -exec rm -rf {} +
