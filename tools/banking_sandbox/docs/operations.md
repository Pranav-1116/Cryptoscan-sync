# Operator exercises and honest results

All commands run from the repository root. Select fresh output directories outside Git. Do not use real targets or secrets.

## Drift, failures and normalized result comparison

```bash
.venv/bin/python -m tools.banking_sandbox.cli drift \
  --root /home/user/.cache/my-bank-lab --output /home/user/.cache/my-bank-drift
.venv/bin/python -m tools.banking_sandbox.cli validate \
  --root /home/user/.cache/my-bank-drift --full-schemas
.venv/bin/python -m tools.banking_sandbox.cli failures \
  --output /home/user/.cache/my-bank-failures
.venv/bin/python -m tools.banking_sandbox.cli modes
.venv/bin/python -m tools.banking_sandbox.cli compare-facts \
  --root /home/user/.cache/my-bank-lab --results /path/to/actual-normalized-facts.jsonl \
  --output /home/user/.cache/actual-comparison.json
```

Drift copies a snapshot, changes configured protocol/cipher/certificate-algorithm fields at deterministic simulated time, retains old/new values, dependency/app/CBOM/PQC impact references, and chains the previous manifest hash. **It does not rotate a running service certificate or execute a migration.** The failure command actually rejects malformed SBOM, malformed CBOM and tampered evidence. Missing source/runtime exports are materialized visibility gaps. Other cluster/DB/Redis/HSM/KMS outage scenarios are declared fixtures, not injected infrastructure outages.

Each supplied normalized observation needs `case_id`, `bank_id`, `subject`, `layer`; optional evaluated fields are `algorithm`, `key_size`, `owner`, `system_id`, `evidence_type`, `conflict`, `runtime_used`, `pqc_status`. Missing fields and null truth remain missing/unknown, not incorrect zeroes or inferred successes. Duplicate cases, cross-bank/system/layer mismatches, failed/partial/unknown → absence and UNKNOWN → SAFE are rejected. **Do not copy expected results into observations**; that only tests the scorer and is not a product measurement.

## Reproducible bounded scale benchmark

```bash
.venv/bin/python -m tools.banking_sandbox.benchmark \
  --banks 10 50 100 150 --scale small --output /home/user/.cache/new-bank-scale
.venv/bin/pytest -q tools/banking_sandbox/test_sandbox.py
.venv/bin/ruff check generate_sandbox.py tools/banking_sandbox
```

The benchmark measures sequential generator plus real static library calls, CPU, child peak RSS, public storage, family accuracy and throughput. Generator RSS is a **cumulative process high-water mark**, not independent per-estate RSS. Parent collection wall time covers child launch/collection; integrity/staging precede it and are not included. This is not end-to-end job latency. No queue, DB, Redis, API concurrency, worker-fleet saturation, full CBOM generation or correlation engine capacity is measured. Those fields are null with an explanation, never invented zeroes. No accuracy floor was agreed; observed misses are retained and disclosed. It is invalid to extrapolate these figures to production 24/7 banking workloads.

Each scan result includes `metrics.json`, actual raw findings, collector log and accuracy. Check the actual filenames in the result directory; a failed import or guard setup is not a passing collection. The first attempted scale run failed due to a lab module named `operator.py` shadowing Python's stdlib. It was retained as failed and superseded by the corrected `operations.py` run, not silently rewritten as success. The first live guest also failed on missing OpenSSL configuration; the explicit-config run is separately identified.

## Optional isolated VM API

The VM path reuses the existing disposable TBF build utilities, not host network privileges. `tools.banking_sandbox.live_vm.build.assemble(output, kernel, config, qemu_root, loader)` takes a fresh output and preverified local native assets. The returned SHA-256 commits to its `bundle.json`. Run with `tools.banking_sandbox.live_vm.runner.run(bundle, expected_sha256, fresh_output)`. There is deliberately **no arbitrary guest target/IP/QEMU-argument option**. Verify pinned asset integrity, production source hashes and local toolchain first; see `assets.lock.json`, `kernel.config` and the existing `tools/disposable_tbf/` build documentation. Do not use private routed-authority material or publish native bundles/keys. The shipped measurement receipt is evidence of one execution, not independent source authenticity or a deployment SLA.

## Dashboard and optional Compose

Serve **only `estate/public`**, never the estate root, control, raw VM filesystem or results. The CLI server disables directory listings, rejects traversal/escaping symlinks, uses same-origin fetches and no external scripts/fonts. Bind `0.0.0.0` for the Arena preview; browser requests remain relative. Binding a preview makes synthetic public fixtures accessible to the preview audience, so never substitute sensitive inputs.

Compose is optional and untested in this workspace. Preload the base image, build from `tools/banking_sandbox/compose/` with networking disabled, and set `SYNTHETIC_PUBLIC` to the **exact generated public directory**. Never mount the parent estate. No protocol service, host scanner, Kubernetes deploy or real cloud account is started by this recipe.

## Next acceptance work (not completed by fixture breadth)

Agree explicit accuracy targets before changing detectors. Investigate misses by language/scenario without feeding oracle data to collectors. Add separately authorized, isolated protocol/runtime/HSM witnesses using normal collectors; exercise actual BOM imports/correlation and attributable end-to-end outputs; then measure queue/database/API/worker limits on the same workload. Independent review, upstream license review and operator approval remain required. UNKNOWN is not SAFE; configured is not executed; installed is not used; supported is not negotiated.
