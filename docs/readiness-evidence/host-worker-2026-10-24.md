# Verified-source local host worker — execution evidence, 2026-10-24

**Status: implemented development candidate, not production/Phase 4 clearance.**
This is the next increment after the published `0e0e3ecb` signed-handoff/file-stage work. Earlier reports remain historical; the logs below belong to this increment's source. [Operator guide 66](../bank-environment/66-verified-local-host-worker.md) explains the executable workflow and residual trust.

## Delivered behavior

1. External Ed25519 source-lock verification, exact approved lock digest, bounded checked source reads and a private verified stage copy. Public source-lock/binding schemas and an exclusive-create lock helper are included. The supervisor, dependencies, loader and same-UID/host integrity are not attested; interpreter **file** measurement is not a measured-execution chain.
2. Existing tenant target/job ledger now supports explicitly approved local-worker enqueue/cancel. Typed user/session incarnation, current credential/role/membership/tenant, current target/approval/environment/window and matching policy stops/exclusions are re-admitted. No caller-supplied role, command, source root, node key or binding is queue authority.
3. Exclusive durable claims, no stale takeover, fresh-session checkpoints, child kill/reap on checkpoint refusal, parent-death SIGKILL before stage imports, final admission under the target mutex, and atomic result/blob/audit publication. These controls do not qualify full worker availability, OS containment, DB timeout behavior, abrupt-parent temporary-directory cleanup, key custody or independent bank acceptance.
4. Actual Linux Landlock/seccomp now supports explicit proc/sysfs leaves and pinned read-only approved TCP/TCP6 capabilities without broad `/proc` access. Existing byte accounting, source digests, PID identity checks and failure receipts remain. Systemd and Windows isolated execution still refuse; absent DMI/TPM are not positive passes.
5. Worker output is a bounded public metadata artifact, not imported Scan evidence. It still needs the approved external snapshot-envelope signer and original host-evidence intake. A valid approved key cannot substitute a different snapshot for the committed worker result. One intake projects NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM without invented runtime use/coverage/edges.

## Final gates

| Final gate | Result |
|---|---|
| Selected Python regression | **1,696 passed, 3 native Windows skipped**, 12 warnings, 262.52 s; no failures/errors |
| Owned PostgreSQL 16.2 | **116 passed**, 6 warnings, 199.55 s; no failures/errors/skips |
| Frontend TypeScript / production build | **PASS / PASS**, fresh build 1.74 s; frontend unit suite not rerun |
| Ruff / pip consistency / public schemas / whitespace | **PASS** |
| Independent acceptance / host attestation / production execution | **NOT QUALIFIED / false / false** |

Machine-readable totals and JUnit timings: [validation.json](host-worker-2026-10-24/validation.json). Source/artifact commitments: [manifest.json](host-worker-2026-10-24/manifest.json).

- Python regression: [log](host-worker-2026-10-24/python.txt), [JUnit](host-worker-2026-10-24/python.xml). Includes native policy-denial tests, actual checked stage execution, source-lock signature/path/digest/duplicate-JSON failures, worker lifecycle and all existing selected host/evidence/CBOM/model/assurance regressions. Native Windows skips are not passes.
- Owned PostgreSQL 16.2: [log](host-worker-2026-10-24/postgres.txt), [JUnit](host-worker-2026-10-24/postgres.xml). Includes original host/association/foundation cases plus actual worker claim races, cancellation/finalization serialization, result/audit rollback and exact signer/result admission.
- Frontend compatibility: [fresh TypeScript/build log](host-worker-2026-10-24/frontend-compatibility.txt). Frontend source is unchanged; the previous 620-test result is historical, **not rerun or claimed as a new result here**.
- [Ruff](host-worker-2026-10-24/ruff.txt), [pip consistency](host-worker-2026-10-24/pip-check.txt), checked public JSON schemas and whitespace/source-scope checks. No workflows, migrations, package manifests or customer deployments were changed.

Warnings are retained: existing Pydantic/FastAPI/Alembic warnings and nonfatal pgserver closed-stream shutdown logging, if emitted. Test success does not suppress them or turn local exercises into independent acceptance. PostgreSQL is an owned disposable local backend; cleanup is checked separately, not inferred from a passing test count. [Cleanup audit](host-worker-2026-10-24/cleanup.json) found no remaining owned PostgreSQL/stage processes or owned temporary directories. Initial supervisor-SIGKILL probes deliberately demonstrated the documented temporary-cwd limitation: three identified empty owned directories were explicitly removed. The final replay records and removes its own crash cwd after reaping; this is test cleanup, not a claim that a SIGKILLed worker executes its Python finalizers.

## Real native and executable witnesses

[Native replay](host-worker-2026-10-24/run-native-witness.py) and [actual output](host-worker-2026-10-24/native-witness.json):

- Actual child process metadata, mapped-library paths, cpu0 topology and an already owned TCP listening socket parse under real Landlock ABI 2 plus seccomp. Counts can change with the interpreter/kernel/runtime; they are not an estate coverage percentage.
- The pinned-net negative unit witness reads approved TCP while `/proc/self/environ`, `/proc/self/cmdline`, UDP, unapproved maps and `/etc/passwd` stay denied. Existing write/truncate/unlink/socket/fork/exec/io_uring/prlimit denials remain tested.
- A dedicated native subreaper witness kills the supervisor of an owned sleeping test stage. The kernel SIGKILLs the child and the witness reaps it. The sleeping stage tests launcher cleanup only; it is not a collector/native-profile success.
- Separate explicitly unisolated diagnostic calls of the existing fixed native interfaces report **systemd UNAVAILABLE/INTERFACE_UNAVAILABLE; DMI and TPM0 UNAVAILABLE/NOT_FOUND, all zero facts** on this host. This is a diagnostic, never a worker fallback or positive qualification.
- The expected-truth CLI now supports `--isolated`. A scoped OS-file fixture can pass actual isolation; nonexistent TPM999 produces exit 2/gaps. Unsupported isolated interfaces or invalid scope/output refuse with exit 64. These are not genuine positive TPM/systemd/Windows evidence or independent review.

[CLI witness](host-worker-2026-10-24/cli-witness.json): source-lock creation exits 0, overwrite exits 64, output is 0600, worker help exits 0, and both public schemas match the models and validate as JSON Schema. [Development lock](host-worker-2026-10-24/development-source-lock.json) records the actual source/interpreter-file measurements; **it has no supplied external signature or approval and is not an approved release**. Real signature/staged-run tests use disposable in-memory keys. No private key or credential is persisted in the evidence bundle.

## Negative controls and recoverability

- Revoked target, elapsed window, changed role/membership, suspended tenant, disabled user, revoked/expired enqueue session, changed system environment, active global or environment-scoped stop and asset exclusions prevent execution.
- Wrong tenant/target/system/host/binding/release/public key/signature cannot consume the approved claim. Reader, cross-estate, stale-revision, unbound and duplicate enqueue/cancel requests fail.
- Two real PostgreSQL claim transactions yield exactly one accepted attempt. Cancel and result publication share the real target mutex. No automatic crash retry or claim takeover is supplied.
- Cancellation and authority changes during collection refuse publication; final policy stop refuses publication; child failure leaves no successful result. A failed result-audit transaction rolls back its blob and revision together.
- QUEUED/RUNNING/CANCELLED/REFUSED and a different AWAITING_EVIDENCE snapshot cannot be bypassed even by a valid trusted envelope signature.
- The exact result is committed to existing scoped `AssuranceBlob` storage before CLI file output. Recovery retains existing admin/CISO raw-download privileges, tenant predicates and `Cache-Control: no-store`; analysts do not receive new raw-blob rights. File-output failure is not permission to rerun acquisition.

## Replay and source closure

From the repository root with the approved validation environment:

```bash
PATH=/home/user/validation-venv/bin:$PATH \
  bash docs/readiness-evidence/host-worker-2026-10-24/run-tests.sh \
  --junitxml=/home/user/host-worker-replay.xml
PATH=/home/user/validation-venv/bin:$PATH \
  python scripts/validate_host_evidence.py --acknowledge-local-synthetic \
  --include-associations --include-foundation --include-worker \
  --junitxml /home/user/host-worker-pg-replay.xml
/home/user/validation-venv/bin/python \
  docs/readiness-evidence/host-worker-2026-10-24/run-native-witness.py
```

The optional pgserver dependency is validation tooling, not a new production dependency. Do not supply a customer database or execute native probes outside their explicit approved scope. Source-lock verification measures stage files; the bundle manifest additionally commits selected controller, tests, guides and evidence sources. Neither hash set authenticates this report or establishes bank acceptance.

## Still open — do not relabel these as complete

Positive ordinary-user native systemd/DMI/TPM and Windows matrices, actual hardware identity/TPM quote or equivalent attestation design, protected signer custody/revocation, boot/executable/dependency/clock trust, independently qualified full worker/control-plane/OS/cleanup behavior and bank sign-off remain required. Production/Windows/host-attestation flags stay false. No full-bank inventory, availability/SLA, performance/p95/p99 improvement, deployed TLS/ACL/HA, key-use/PQC invocation, or customer acceptance is claimed. This increment advances executable controls without manufacturing the external evidence needed to close those gates.
