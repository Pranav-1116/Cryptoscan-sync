# Actual disposable PostgreSQL workflow and recovery — 2026-10-23 UTC

## Environment and safety contract

Companion to the [ninth increment](quality-workflow-qualification-2026-10-23.md).
This is an **executed native PostgreSQL 16.14** exercise, not SQLite emulation,
a mocked dialect or a skipped marker. Matching 16.14 `pg_dump`/`pg_restore` were
built externally; no server/client binaries or datasets enter the repository.
Python/client versions and final input hashes are in the companion and
[results JSON](quality-workflow-results-2026-10-23.json).

Retained implementation: `services/api/tests/unit/test_workflow_postgres.py`.
Execution requires **both** `-m live` and explicit
`CRYPTOSCAN_QUALITY_PG_OPT_IN=disposable-local-only`. Missing opt-in skips and
**does not qualify PostgreSQL**. The admin URL must target database `postgres`
on a validated loopback host or explicit private Unix socket. Query overrides
are restricted to host/port; remote/multi-host/service overrides are refused.
Only fresh UUID-named `cs_quality_*` databases are created, migrated and dropped.
The input administrative database is not migrated. Failed cases still dispose
connections and drop their generated databases. This is not an authorization to
use a bank instance: operators must supply a genuinely disposable local cluster.
No production `DATABASE_URL` is accepted as the target selector.

Actual private cluster: socket `/home/user/quality-pg-socket`, port 55439;
role `quality_operator`, no bank data, no network/TLS qualification. Each fresh
clone comes from a test-created database migrated normally to 0106. Missing and
behind startup/migration cases use separate empty databases. SQL waits are
bounded (statement 15 s, lock 10 s); barriers/futures also have explicit limits.

## Sixteen executed native cases

| Native case group | Count | Asserted property |
|---|---:|---|
| Competing assurance revision writers | 1 | Revision uniqueness/CAS: one revision 1 and one HTTP409 conflict. |
| Duplicate queue/job claims | 1 | Exactly one claim winner, one RUNNING job/attempt and one held reservation per budget. No double admission from duplicate descriptor. |
| UNKNOWN reconciliation | 1 | Uncertain effect retains budget and cannot be declared successful from worker exit; authorized reconciliation follows existing transactional contract. |
| Failure after reservation writes, before claim commit | 1 | Inject a real SQL-path exception; job remains QUEUED, no attempt persists, budgets remain zero; ordinary later claim succeeds without manual repair. |
| Concurrent withdrawal against positive proof | 4 | Original, another captured before member, selected replacement and another captured after member. The withdrawing backend is actually lock-waiting while proof holds the sorted union; proof commits before withdrawal. Later current interpretation is false. |
| Competing approval writers | 1 | One approved revision and one conflict, not two successful approvals. |
| Signed-in actual source/parser journeys | 2 | MD5→SHA256 yields VERIFIED, MD5→SHA384 is INCONCLUSIVE for SHA256. Owner report remains distinct from independent proof; original export preserves MD5/FAIL and integrity PASS. |
| Populated 0105→0106 | 1 | Existing job status/version/progress preserved. Native UNKNOWN accepted; downgrade refused with UNKNOWN and version stays 0106; arbitrary ASSUMED_SUCCESS rejected by native enum. |
| Native logical dump/restore and damaged archive | 1 | Restored proof history, UNKNOWN attempt/budget fences and duplicate denial; normal authorized reconciliation once, second attempt409. Truncated archive leaves no public tables under single-transaction restore. |
| Exact private read/residency contract | 2 | With/without optional tenant middleware: A/B/NULL boundaries, foreign records, narrow allowed GETs, forbidden unqualified routes, region mismatch409 without target disclosure. Platform NULL read is explicitly exercised with middleware. |
| Runtime migration gate | 1 | Native unstamped/behind startup refuses without metadata repair; genuinely migrated clone startup emits no DDL/DML. Deliberately damaged legacy fixture is never forged-current or used as a successful journey. |

**Final: 16 passed, no failures/errors/skips, 17 warnings, 45.41 s.** Individual
case names and timings are retained in JSON. Warnings include Alembic configuration
and Pydantic deprecations. The separate broader default library run retains its
old pg_virtualenv-only skip and eight live deselections; these are not silently
promoted by this result.

## Migration and rollback contract

`0106_allow_unknown_job_outcomes.py` adds UNKNOWN, DEFERRED and CANCELLED to the
native PostgreSQL `scanjobstatus` enum using additive idempotent DDL. They are
existing repository/projection identities, not new product outcomes or grants.
CANCELLED label insertion is in the migration, but a standalone CANCELLED
execution scenario is **not** claimed by these tests.

The fix is required because a Python enum model change does not extend an already
created native PostgreSQL enum. A failed/uncertain effect must be representable
without converting it to success/failure or releasing its held budget. No existing
row, assurance payload, approval or evidence observation is rewritten.

PostgreSQL downgrade refuses while any UNKNOWN row remains. Even when allowed,
additive enum labels remain: removing enum labels requires replacing the type and
locking/rewriting the job table. This rollback is not byte-for-byte enum restoration
or approval to restart old binaries. Prefer reviewed compatible fix-forward;
reconcile actual effects through authorized controls before considering downgrade.
The guard does not block SQLite index-only rollback: SQLite already retained these
strings before 0106, and its unrelated unsettled-job/history preservation test
remains valid. 0105's long-event-type downgrade guard remains independently in force.

Package preflight now expects head0106. Rebuild/review the coordinated operator
package/application images; do not run runtime pods with schema-owner credentials
or assume source publication upgraded a bank. Review the
[operator recovery runbook](../runbooks/operator-install-upgrade-recover.md).

## Recovery exercise: what it does and does not prove

The test runs matching native `pg_dump` custom-format and `pg_restore` with
single-transaction behavior into a fresh generated database. It restores real
source-proof history plus an intentionally uncertain attempt with held capacity.
API/worker/session bindings are cut over to that isolated restored database in the
fixture; rows are not repaired by SQL to obtain a green journey. Duplicate work is
still refused until the normal authorized reconciliation action, which succeeds
once. Damaged-archive restore is isolated and leaves no public-table partial state.

This is local **logical SQL recovery**, not full DB-plus-blob backup, external
evidence object retention, encryption/KMS, TLS, WAL archive/PITR, replica/HA failover,
Redis persistence, Kubernetes cutover, site RPO/RTO or DR owner sign-off. Those
requirements remain in the [DR documentation](backup-disaster-recovery-documentation-2026-10-23.md).

## Reproduce on an approved disposable local cluster

Install the repository's test dependencies in a separate environment. From the
repository root, the executed environment used:

```bash
export CRYPTOSCAN_QUALITY_PG_OPT_IN=disposable-local-only
export CRYPTOSCAN_QUALITY_PG_URL='postgresql+psycopg2://quality_operator@/postgres?host=/home/user/quality-pg-socket&port=55439'
export CRYPTOSCAN_QUALITY_PG_BIN=/home/user/quality-pg-client-source/postgres-REL_16_14/src/bin/pg_dump
# Needed by these externally compiled clients, not necessarily packaged clients:
export LD_LIBRARY_PATH=/home/user/quality-pg-client-source/postgres-REL_16_14/src/interfaces/libpq
/home/user/recovery-venv/bin/python /home/user/run-quality-pytest.py \
  services/api/tests/unit/test_workflow_postgres.py -m live -q
```

`CRYPTOSCAN_QUALITY_PG_BIN` is the directory containing **both** matching clients.
Use your own approved disposable paths/role rather than assuming these workspace
paths exist. The external bootstrap above is equivalent to this root invocation;
its exported PYTHONPATH is important for real process-recovery child tests:

```bash
python - services/api/tests/unit/test_workflow_postgres.py -m live -q <<'PY'
import os, sys
from pathlib import Path
root = Path.cwd()
sys.path.insert(0, str(root / "scripts"))
from _bootstrap import bootstrap
bootstrap()
for folder in ("services", "shared"):
    for child in (root / folder).iterdir():
        if child.is_dir():
            sys.path.insert(0, str(child))
sys.path.insert(0, str(root / "services/api/tests/unit"))
os.environ["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p.startswith(str(root)))
import pytest
raise SystemExit(pytest.main(sys.argv[1:]))
PY
```

## Remaining database qualification

This does not complete every supported PostgreSQL version/isolation setting,
TLS/CA path, high-contention/long-running lock scenario, simultaneous grant/policy
mutation, clock skew, deployment upgrade matrix, storage outage or full recovery
cutover. Sorted evidence locks establish the tested withdrawal ordering, not
serializability of all external mutable authorities. Existing read-time current
checks and conservative UNKNOWN handling remain necessary. No bank-site or
independent security approval is inferred from this disposable exercise.
