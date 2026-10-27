# Executed worker dispatch repair — 2026-10-24

**Outcome: two reproduced correctness gaps repaired; actual API-created job
executed through Redis and a fresh worker into PostgreSQL. Not production or
independent bank acceptance.** No collector, dashboard, service, database
migration or customer deployment was added or changed.

## Implementation and reproductions

1. The API's queue helper previously allowed memory fallback even with a Redis
   URL. An actual API-publisher regression reproduced an outbox state of
   `PUBLISHED` after a failed Redis write instead of the required `PENDING`.
   Configured Redis publication now raises rather than accepting a process-local
   delivery; the committed outbox can be republished by worker maintenance.
2. Worker lease renewal previously depended on polling. A graceful-shutdown
   regression reproduced lease expiry while an executor was still draining.
   Renewal now has an independent lifecycle that stays open until pool shutdown
   completes, then joins the keeper thread. It does not replace SQL fencing.
3. A fresh-process drill exposed a stale canonical script import list. Bootstrap
   now matches existing shell/container shared/service discovery; a clean
   subprocess imports the current API and worker without inherited PYTHONPATH.

The two [pre-fix](worker-dispatch-2026-10-24/lease-before.txt)
[reproductions](worker-dispatch-2026-10-24/outbox-before.txt) are intentional
failures against the old implementation, not final-run failures.
[Behaviour, compatibility and limits](../operations/worker-dispatch-boundaries.md).

## Final validation

| Execution | Observed result | Retained evidence |
|---|---|---|
| Selected broad Python regression: previous CBOM/evidence selection plus other worker units and execution control/recovery contracts | **2,198 passed**, 8 warnings, 478.54 s; process exit 0 | [Transcript](worker-dispatch-2026-10-24/regression.txt), [JUnit](worker-dispatch-2026-10-24/regression.xml) |
| Focused new regressions: lease lifecycle, fresh imports, helper startup/publish failures, actual API publisher | **7 passed**, 4 warnings, 14.63 s | [Transcript](worker-dispatch-2026-10-24/focused.txt), [JUnit](worker-dispatch-2026-10-24/focused.xml) |
| Owned real PostgreSQL/Redis/API/worker drill | **9 checks passed**; PostgreSQL **16.2**, schema **0107**, Redis **8.2.4** | [Result](worker-dispatch-2026-10-24/dispatch.json), [Transcript](worker-dispatch-2026-10-24/dispatch.txt) |
| Ruff on changed Python, pip dependency consistency, diff whitespace | Passed | [Quality](worker-dispatch-2026-10-24/quality.txt) |
| Owned service/source/runtime cleanup | Children exited without forced kill; PostgreSQL stopped; private source/database/socket/log directories removed | [Drill flags](worker-dispatch-2026-10-24/dispatch.json), [Additional cleanup](worker-dispatch-2026-10-24/cleanup.json) |

The broad run is a **selected regression**, not the entire repository or all CI
workflows. Its eight warnings include existing Pydantic/field-shadowing/Starlette
warnings, a blocked external socket attempt in an existing worker test and the
pgserver runtime-directory warning. A pgserver exit-time log attempted to write
to a closed stream **after** the passing summary. That logging error is retained,
not hidden; the process exited 0 and its owned PostgreSQL process was confirmed
stopped before removing the known test data directory. No warning fix is claimed.

No frontend code changed and no new frontend/browser run is claimed. Earlier
browser results remain historical, including their fixture-provisioned envelope.
Runtimes in this table are test durations, **not** product performance benchmarks.

## The nine actual dispatch observations

1. **Real password/session authentication:** synthetic analyst/readonly/operator
   identities log in through the actual endpoint, with durable session records.
2. **Admission and isolation:** readonly trigger is 403, a target outside declared
   source roots is 400, a foreign tenant's job read is 404.
3. **Actual development scan:** API admission creates the SQL job and Redis
   descriptor; the unmodified worker entrypoint runs in a fresh OS process. The
   real parser/hash/loader produces exactly **one scan and one evidence record**
   in the owning estate despite a duplicate Redis descriptor. Stored content,
   chain, hash format and manifest verification are all PASS. No job, scan or
   evidence completion envelope is preinserted.
4. **Stop after enqueue:** the existing development control API engages emergency
   stop before worker startup. The queued job is refused at the worker gate and
   new admission returns 409. Stop is then disengaged through that API.
5. **Controlled outbox and unprovisioned isolation:** controlled mode is enabled;
   operator routes create policy, budget and a positive grant. The harness checks
   current durable initiating authority and grant before dispatch, and observes
   the real preflight refusal: `Controlled parsing requires the approved
   container profile`. A real worker processes the published outbox descriptor
   and refuses authority. This is **not successful controlled parsing**.
6. **Real Redis outage:** the owned Redis process is stopped. A further
   API-created controlled job remains SQL `QUEUED` with outbox `PENDING` and no
   publication lease, rather than acknowledging an in-memory delivery.
7. **Actual recovery publication:** after owned Redis restart, fresh worker
   maintenance republishes that pending SQL outbox; it becomes `PUBLISHED`.
   The same unprovisioned isolation boundary refuses execution. Across the two
   controlled jobs there are **zero execution attempts and zero extra scans**.
8. **Real draining TTL:** a separate transport-only delivery remains in the
   processing list with a live lease beyond its shortened 3-second TTL after
   intake stops; another consumer cannot recover it. It is then acknowledged.
9. **Actual SIGKILL:** an owned transport probe child is killed after dequeue.
   Recovery moves zero hints before its 5-second lease expires, then one hint
   after expiry, with redelivery attempts incremented to one. That probe is not
   a collector, SQL execution attempt or successful scan.

The API transport here is **in-process ASGI TestClient**, not a browser or live
HTTP server. PostgreSQL and Redis are real Unix-socket processes; workers are
real subprocesses. No collector, policy, claim or launcher double is used in the
actual drill. Unit tests separately use documented doubles to isolate failures.
The outage transcript deliberately retains Redis-unavailable logs; those logs
alone are not proof of a passing recovery test.

## Cleanup, reproducibility and remaining gaps

The final drill stopped all owned children normally, stopped PostgreSQL and
removed its private directory. The broad regression's known temporary PG data
was removed after its process stopped. The owned Redis source/build/archive were
also removed after retaining [source and binary hashes](worker-dispatch-2026-10-24/redis-source.json).
The validation interpreter remains a development tool, not a deployed service.
[Environment versions](worker-dispatch-2026-10-24/environment.txt),
[replay instructions](worker-dispatch-2026-10-24/README.md) and
[source/artifact hashes](worker-dispatch-2026-10-24/manifest.json) aid inspection;
they are not independent attestations or signatures.

**Still open:** a successful digest-pinned controlled container execution with
real SQL attempts/checkpoints and artifact receipts; deployed TLS/ACL/HA and
partition recovery; sustained load/capacity and the agreed paired p95/p99/20%
performance targets; independent expected-scope completeness; original45
platform/protocol/runtime/HSM/PKI/PQC and integration work; and bank/legal/security
review and staffed operating commitments. No bank approval, complete six-BOM
coverage, historical partial-history clearance, 24/7 staffing, or production
readiness is inferred from this run. NBOM, CBOM, TechBOM, HBOM, VBOM and SBOM
remain distinct evidence surfaces with their own unresolved closure requirements.
