# Engineering evidence — parser startup, cancellation and cleanup boundaries

**Date:** 2026-10-23 UTC

**Branch:** `arena/bb4b80dd-cryproscan`

**Scope:** fifth bounded quality increment, following the [execution-recovery increment](quality-execution-recovery-2026-10-23.md). No new API/collector/service/profile, schema migration, dependency lock or native binary is introduced. Source publication is not a signed operator release, bank installation or production qualification.

[Implementation ledger](../product-improvement/IMPLEMENTATION-STATUS.md) · [Parser runtime contract](../dev/scanner-isolation.md)

## 1. Source and publication boundary

The previously published branch tip was `30c083ee2566f7b3b99da078f08d267ae8291795`; its underlying quality implementation was `2fd8fc8f` with later documentation updates. The fourth increment was still uncommitted at this task's start.

Before this increment, an alternate Git index was used to compare the supplied working tree to that remote tip. The diff was exactly the fourth increment's 15 files, not thousands of new unrelated edits. The local branch/index was then reconciled to the **same** remote branch without checking out or modifying working files. SHA256 checks verified that **all 3,819 tracked/non-ignored working files stayed byte-identical** through reconciliation. No branch was created/switched, and no main/workflow edit was made.

The user requested the next bounded implementation **and publication of all pending work**. The publication therefore bundles increments four and five on the existing PR branch with `[skip ci]`. The containing Git commit and PR publication comment identify the pushed source; the hashes in each dated record identify the tested content without inventing a self-referential future commit SHA. No Actions passing verdict is inferred.

## 2. Baseline and reproduced defects

The existing parser-isolation and controlled-staging suites passed **72 tests**, **3.21 s**, exit 0 before changing the parser runtime.

The first new runtime set reproduced **9 failed / 5 passed**, **0.69 s**, exit 1. This was a 14-case paired check; initially passing cases remain compatibility/control checks.

| Boundary | Observed pre-fix behavior | Correction |
|---|---|---|
| CLI creation fails | OSError/PermissionError/FileNotFoundError escaped before the exchange's handler, retaining raw diagnostic text | Own process creation within the protected scope; return the existing safe communication-failure category with suppressed public context |
| Selector construction fails after spawn | The child had already started outside the protected setup boundary; no guaranteed kill/wait or pipe cleanup occurred | Own the child before the next allocation and finalize whatever resources were actually allocated |
| Process cleanup fails | Kill/wait failure replaced the public failure with raw OSError/TimeoutExpired and skipped selector/pipe cleanup | Try remaining cleanup independently; report cleanup could not be confirmed and never return a successful result |
| Selector cleanup fails | A failed selector close skipped all subsequent pipe closes | Continue closing all three owned pipes and refuse with safe cleanup-uncertain category |
| Cancellation types | Confirmed container removal preserved KeyboardInterrupt/SystemExit but converted CancelledError/GeneratorExit to a generic normal exception | Preserve original non-Exception BaseExceptions after confirmed container cleanup |

The changes are confined to `static_scan_isolation.py`. The current digest pinning, no-network/no-secret parser command, source marker, deadline checks, output bounds and no-inline-fallback production policy remain intact. A failed cleanup does not prove a CLI, container or external effect stopped.

## 3. What was actually exercised

### Real local child processes

The new worker module uses real Python CLI children to check selector/nonblocking setup faults, success and handle closure. Faults in process termination/wait and selector close are injected explicitly. The test harness has a separate kill/wait/close safety net for intentionally uncertain cleanup and for the pre-fix leaked-child reproduction.

- Startup errors emit no synthetic private runtime/path canary in the public exception text.
- Allocated stdin/stdout/stderr pipes are closed after the tested setup failures.
- Confirmed termination waits/reaps the actual child; cleanup uncertainty is **not** asserted to mean the child stopped.
- Cleanup failures cannot produce successful output, even where another cleanup succeeds.
- Named daemon cleanup is mocked for cancellation checks. Original cancellation identity is retained when that mocked cleanup confirms success.
- Successful local CLI exchange preserves bounded output and closes its handles.

These are not real Docker daemon deletion/absence checks. They do not qualify container escape resistance, host/daemon fencing, orphan survival, production timeout bounds or bank infrastructure.

### Real-SQL integration with the controlled executor

Four additional API-suite cases use the existing admitted job/approval/session/estate fixture and actual SQL. They exercise launch failure, invalid parser result, unconfirmed daemon cleanup and cancellation through `JobExecutor` → `scan_static` → interrupted finalization.

The daemon and selected runtime faults are doubles. Every case retains job and attempt **UNKNOWN**, holds both execution reservations, records no fabricated scan ID, clears the local execution ContextVar and refuses later duplicate delivery without invoking the parser again. Source binding markers are removed. The reservation contract is separate from local file-descriptor cleanup.

**No production database or bank source is used.** Runtime failure text can contain a synthetic canary internally; only the public error string is checked here. This is not a complete traceback, logging or exception-channel privacy audit.

## 4. Actual local results

| Run | Result | Scope |
|---|---|---|
| Existing boundary baseline | **72 passed**, 3.21 s | Before parser change |
| Initial adverse runtime set | **9 failed / 5 passed**, 0.69 s | Expected exit 1; no application change yet |
| Existing boundary + initial new runtime checks | **86 passed**, 3.24 s | Exit 0 after correction |
| Complete new fifth-increment set | **18 passed**, 4 warnings, **3.55 s** | 14 runtime cases + 4 SQL integration cases; exit 0 |
| Final worker/execution publication run | **1,070 passed / 16 skipped / 1 deselected**, 17 warnings, **291.06 s**, exit 0 | Full default worker collection plus selected execution/API/database suites; includes both increments' new tests |
| Final authorization compatibility run | **113 passed**, 10 warnings, **23.86 s**, exit 0 | Fresh auth/account/RBAC/API-key/role-store/health compatibility checks |

Final `ruff check services scripts shared` and `pip check` passed. Documentation
validation checked **493 Markdown files / 1,828 local links**, with zero missing
targets or unresolved heading anchors, **9 increment Markdown files / 5 shell
examples**, and **21 recorded source/input hash values** matching across the two
inventories (which overlap). **53 external links** were not fetched. Shell
examples were syntax checked, not used to deploy anything. Patch whitespace passes. Focused tests overlap the broader run; do not add counts together or relabel historical tests as fresh runs. No frontend tests/build were needed or rerun for these backend-only corrections.

### Remaining qualification gaps

- PostgreSQL parity/locking/estate cases require a disposable approved test server; skipped cases are not passed or waived.
- The live Docker parser test remains outside the default hermetic selection. Mocked cleanup calls are not witnessed deletion or daemon-loss evidence.
- Existing warning categories are retained: Pydantic/field-shadowing, Starlette/httpx/422 deprecations, blocked external socket attempts in old worker fixtures and Alembic path-separator deprecation.
- Original UNKNOWN remains an unresolved external outcome. A free thread, closed pipe, dead CLI or empty queue does not authorize releasing estate/provider reservations.
- Exact-site PostgreSQL/TLS Redis/parser/daemon/fence/orphan/restore/capacity/browser/operator acceptance and independent review remain open. No SLA, HA/zero-downtime, bank readiness or runtime kill bound is claimed.

## 5. Reproduction and retained local artifacts

Use the existing dependency inputs and synthetic test settings, never bank credentials:

```bash
export PYTHONPATH="$PWD/services/api/tests/unit:$(find "$PWD/services" "$PWD/shared" -mindepth 1 -maxdepth 1 -type d | tr '\n' ':')"
export ENVIRONMENT=test
export SECRET_KEY=test-secret-key-for-sessions-min-32-chars
export GITHUB_WEBHOOK_SECRET=test-webhook-secret-abc123
PYTHON=/home/user/recovery-venv/bin/python

"$PYTHON" -m pytest -q -p no:xdist \
  services/worker/tests/unit/test_parser_runtime_failures.py \
  services/api/tests/unit/test_parser_failure_execution_contract.py

"$PYTHON" -m pytest -q -p no:xdist \
  services/worker/tests \
  services/database/tests/unit/test_execution_budget_concurrency.py \
  services/database/tests/unit/test_execution_control_migration.py \
  services/api/tests/unit/test_execution_controls.py \
  services/api/tests/unit/test_queue_authority_contract.py \
  services/api/tests/unit/test_execution_recovery_integrity.py \
  services/api/tests/unit/test_execution_process_recovery.py \
  services/api/tests/unit/test_parser_failure_execution_contract.py
```

The separate authorization command is the nine-file compatibility set documented in the fourth increment, rerun for this publication. Test environment: Python 3.11.2, pytest 9.1.1, existing requirements/lock, no repository dependency changes.

Local artifacts are outside Git and are not a bank-controlled evidence store:

- `/home/user/parser-boundary-baseline.log`
- `/home/user/parser-boundary-red.log` and `.xml`
- `/home/user/parser-boundary-green.log` and `.xml`
- `/home/user/parser-boundary-focused.log` and `.xml`
- `/home/user/publish-recovery-worker.log` and `.xml`
- `/home/user/publish-recovery-auth.log` and `.xml`

## 6. Tested source/input identities

```text
services/worker/worker/core/static_scan_isolation.py
29f0d87ce5cdb480a22757617fb094bfe8717f352672c024416be9ec71a354d7

services/worker/tests/unit/test_parser_runtime_failures.py
1209d908096e1dc04da09825c2db02ca5a776d2d89dc4161f050b21f0de742ea

services/api/tests/unit/test_parser_failure_execution_contract.py
a925af35bafd691fbb90fb4a1ab31add78fe4dc94387ea93e09d23c7fb5aaf0d

services/worker/worker/core/job_executor.py
20a7e65cbdb7db342d765a2711df321c343a6d99d6158b9bc9a431d5b5eddbe6

services/worker/worker/core/pool.py
bf17a60f15e390c99e9b84f2b6f2d4783c962f3682f3d530fde349d2a401bd7b

services/database/db/repositories/execution_control.py
5e5e51465e72f3c39139b860a385a752a3989c02498fb1212a3da77d80b5cddd

services/database/db/repositories/execution_outbox.py
faf656335fc01f9d94d7377f14ace96dfbc43e4bf33cf26eb58029c333835ea0

requirements.txt
15c2c7d4ceacf2bde509b4bf5ac635923cc470986d13047a3cdc42a8214c8bb1

requirements.lock.txt
1b935cfe5230ea6f37affaab45044617ce402ecd1037f4c62b22404da4cedf2b

```

## 7. Upgrade and operational handoff

Rebuild coordinated reviewed application/worker/parser/frontend release artifacts, verify real immutable digests and use the existing externally signed full operator-package contract. No new migration is introduced; head remains 0105. Source publication alone performs no bank update or native-binary conversion.

A safe communication error does not mean the parser was never started. A cleanup-uncertain error must be investigated under the controlled UNKNOWN procedure. Restore approved dependencies/runtime and establish actual external state before the current authorized human reconciles and releases reservations. Never reset the old job, rewrite receipts or enable production memory/inline fallback to clear an incident.

The next work is independent review and exact-site fault/restore qualification, plus further **observed-defect-first** six-BOM/authority privacy regressions. No new collector/service/feature is authorized by this record.
