# Replay worker-pool lifecycle evidence

Use a reviewed Python 3.11 environment, repository dependency requirements/locks
and authorized disposable backends only. Do not supply customer database URLs.
No dependency, service, migration or workflow was added by this increment.

## Current regression selection

```bash
# Approved interpreter on PATH; source/bootstrap discovers local packages.
bash docs/readiness-evidence/worker-dispatch-2026-10-24/run-regression.sh \
  --junitxml=/external/pool-regression.xml

python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  services/worker/tests/unit/test_worker_pool_retention.py \
  services/worker/tests/unit/test_worker_pool.py \
  services/worker/tests/unit/test_interruption_accounting.py \
  services/worker/tests/unit/test_worker_lease_lifecycle.py \
  -q --junitxml=/external/pool-focused.xml
```

The broad selection includes CBOM, evidence, selected database/API assurance
contracts, worker units and execution-control/recovery tests. It is not every
repository test or all CI workflows. PostgreSQL-specific cases use existing test
helpers when pgserver or an explicitly owned test server is available.

Weak-reference tests isolate pool retention from pytest's external logging
capture, which intentionally holds exception traceback frames. That test-only
logging isolation is not a production logging change or an authority/gate bypass.

## Historical baseline (expected failure)

```bash
python docs/readiness-evidence/worker-pool-2026-10-24/baseline-repro.py
# EXPECT exit 1 and six failures against the previous published implementation.
```

This loads only `pool.py` from commit
`2f9551b02a2601affd100e558c7a4b1afbdba184` in a separate test process and runs
six current regressions. It requires that local Git object; it never fetches,
checks out, resets or overwrites source. Do not mistake `baseline.txt` for the
final implementation's gate. Other new tests are not run against the historical
implementation, avoiding known cancellation-stall cases in that old pool.

## Synthetic lifecycle witness — not a scanner capacity benchmark

```bash
python scripts/worker_pool_soak.py --report /external/lifecycle.json
```

Default: one pool, 24 batches × 512 local synthetic jobs, two workers and the
existing default 100-slot queue. It mixes immediate/asynchronous completion and
explicit synthetic refusals, samples public-Future counts/weak references, waits
for terminal callbacks and shuts down the pool. No scanner, SQL, Redis, tenant or
deployment is contacted. Its observations are not RSS, measured memory-pressure
behaviour, throughput, p95/p99 or the agreed paired 20% performance qualification.

## Real API/Redis/PostgreSQL/worker recheck

```bash
python scripts/worker_dispatch_drill.py \
  --redis-server /approved/redis-server \
  --report /external/dispatch.json \
  --acknowledge-local-synthetic
```

The existing harness owns fresh local Unix-socket services, migrates through
0107 and uses actual password/session authentication, ASGI routes and fresh
worker processes. This increment reruns it with the current pool. The successful
case is **one development scan**, not the synthetic witness's 12,288 jobs.
Controlled jobs validate their grant but correctly refuse the unprovisioned
container profile; no preflight, claim, collector or policy double makes them
look successful. The original harness's [scope and cleanup instructions](../worker-dispatch-2026-10-24/README.md)
still apply, including intentional Redis outage logs and transport-only SIGKILL.

Source/binary hashes for the locally rebuilt Redis executable are in
`redis-source.json`. The binary/archive/build tree and owned private runtime data
are not committed. Normal completion stops owned services and removes their
private directory; verify the retained cleanup records. A validation interpreter
is a local tool, not a newly deployed service.

Text artifacts strip trailing whitespace/terminal formatting; JSON/XML are
retained unchanged. The manifest records source/artifact SHA256 hashes, not an
independent signature or bank approval. No frontend/browser, successful controlled
container execution, representative scanner load or paired performance claim is
made by this run.
