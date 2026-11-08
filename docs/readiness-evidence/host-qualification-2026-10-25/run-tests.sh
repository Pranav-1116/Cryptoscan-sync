#!/usr/bin/env bash
# From repository root, approved validation Python on PATH. No CI/customer use.
set -euo pipefail
export PYTHONPATH=".:scripts:shared/shared_models:services/inventory:services/cbom${PYTHONPATH:+:$PYTHONPATH}"
python -m pytest shared/shared_models/tests \
 services/inventory/tests/test_host.py services/inventory/tests/test_host_windows.py \
 services/inventory/tests/test_linux_runtime.py services/inventory/tests/test_windows_runtime.py \
 services/inventory/tests/test_isolated_host.py services/inventory/tests/test_collector_release.py \
 services/inventory/tests/test_native_profile_runner.py services/inventory/tests/test_rpm_metadata.py \
 services/inventory/tests/test_collection_linux.py services/inventory/tests/test_qualification_protocol_cli.py -q "$@"
