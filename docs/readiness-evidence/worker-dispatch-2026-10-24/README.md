# Replay: owned worker dispatch and lifecycle checks

These are local synthetic engineering checks, not deployment or bank acceptance.
Use a reviewed Python 3.11 environment with repository dependency locks, test
requirements and optional `pgserver`. Use only authorized disposable services.
Do not pass customer database URLs or production credentials to test runners.

## Regression and reproduced failures

```bash
# Put the approved environment's Python on PATH first.
bash docs/readiness-evidence/worker-dispatch-2026-10-24/run-regression.sh \
  --junitxml=/external/worker-regression.xml

python docs/readiness-evidence/quality-usability-release-operations-2026-10-23/run-tests.py \
  services/worker/tests/unit/test_worker_lease_lifecycle.py \
  services/worker/tests/unit/test_script_bootstrap.py \
  services/worker/tests/unit/test_interruption_accounting.py::test_configured_redis_publish_helper_never_accepts_a_memory_delivery \
  services/api/tests/unit/test_execution_recovery_integrity.py::test_api_publisher_does_not_commit_outbox_on_redis_memory_fallback \
  -q --junitxml=/external/worker-focused.xml
```

`lease-before.txt` and `outbox-before.txt` are intentionally failing reproductions
against the pre-fix implementation. They are not failures in the final run.
The broad selection includes the previous 1,185-test selection plus the other
worker unit files and execution-control/recovery contracts. It is **not** the
entire repository suite. Embedded PostgreSQL cases use their normal test helpers;
unavailable backends must be reported as skipped, not described as executed.

## Actual owned PostgreSQL/Redis/worker drill

Provide a locally built or reviewed Redis executable. `redis-source.json` records
the exact archive and binary hashes used for this run; no binary/source archive
or private runtime directory is checked in. This invocation requires no Docker
runtime and verifies that controlled parsing is refused—not bypassed.

```bash
python scripts/worker_dispatch_drill.py \
  --redis-server /approved/redis-server \
  --report /external/worker-dispatch-result.json \
  --acknowledge-local-synthetic
```

The harness owns a fresh temporary directory under `/home/user`, Unix-socket
Redis and pgserver PostgreSQL, a migrated synthetic database, password/session
principals and source files. It uses the real API routes through ASGI TestClient
and fresh `python -m worker.main` processes. It accepts **no deployment URL**.
SQL jobs/scans/evidence are created by the actual admission/pipeline, not seeded.

The first scan deliberately uses development inline parsing. Then the harness
enables controlled mode and validates a current durable grant; the real
isolation preflight refuses the unprovisioned profile. The same worker boundary
refuses queued controlled work. A real Redis stop/restart tests SQL outbox
republication. Control-plane stop is exercised through the development control
API before controlled cases, not by bypassing a controlled-surface restriction.
Transport-only draining/SIGKILL checks have their own synthetic hints and are not
collector execution evidence.

Normal completion closes clients, exits owned children, stops PostgreSQL and
removes the private source/database/socket/log directory. Inspect the resulting
cleanup flags. Abruptly killing the harness itself is not a qualified cleanup or
site-recovery scenario. Test dependencies and the validation interpreter are
not deployed application services.

The retained transcript includes expected Redis-unavailable error logs during
the intentional outage. A subsequent PASS is valid only with the associated
pending-outbox/republication assertions and cleanup, not from logs alone.
There is no browser/frontend rerun, successful controlled container execution,
production TLS/ACL/HA or performance/independent acceptance claim.
