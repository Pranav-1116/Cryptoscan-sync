# Controlled history and qualification-harness execution — 2026-10-24

**Scope:** changes after published baseline `267efcfc`. Engineering/synthetic
sandbox evidence, **not** whole-product readiness, deployed security/capacity/DR
qualification, all45 completion or independent bank acceptance.

## Implemented and exercised

- Existing CBOM UI/API now handle exact-estate unassigned assignment and
  append-only mixed-source proposal/second-human approval. Current durable
  authority, snapshot checks, evidence/replacement locks, atomic audit and
  conflict handling are enforced; original assets/evidence are retained.
- Partial native exports disclose retained mixed history. System/portfolio and
  inline-partial clean posture grades are blocked. Changed evidence, link swaps,
  forged/unrelated markers, shared-system histories and failed audit writes have
  negative tests. There is no automatic partialness-clearance endpoint.
- Load/production-evidence verdicts no longer accept zero useful work/all429,
  missing verdicts, failed workers or unconfirmed known-key cleanup. Percentiles
  and useful throughput describe successful operations, with null when absent.
- New opt-in local-only browser and recovery harnesses reuse the existing
  console, database, authentication, backup and restore commands.

See [operator workflow](../operations/controlled-historical-cbom.md) and
[qualification boundaries](../operations/qualification-evidence-boundaries.md).

## Executed results

| Execution | Result | Retained artifact |
|---|---|---|
| Selected broad Python regression | **1,097 passed**, 4 existing warnings; 238.89 s | [transcript](controlled-history-2026-10-24/python.txt), [JUnit](controlled-history-2026-10-24/python.xml) |
| Complete frontend test invocation | **573 passed / 55 files**; 107.81 s | [transcript](controlled-history-2026-10-24/frontend.txt), [JUnit](controlled-history-2026-10-24/frontend.xml) |
| Real PostgreSQL contracts | **32 passed**, 4 warnings; 29.80 s | [transcript](controlled-history-2026-10-24/postgres.txt), [JUnit](controlled-history-2026-10-24/postgres.xml) |
| Real Chromium → console → API → migrated PG | **15 checks passed**, no page errors | [JSON](controlled-history-2026-10-24/browser.json), [screenshot](controlled-history-2026-10-24/browser.png) |
| API-restart readback | **3 histories** retain decisions and partial exports | [JSON](controlled-history-2026-10-24/restart.json) |
| Actual encrypted logical PostgreSQL restore | **8 checks passed**; all table counts/content digests match, schema 0107, 134-entry audit chain OK | [JSON](controlled-history-2026-10-24/pg-recovery.json) |
| Actual Redis SIGKILL/RDB recovery | **105 acknowledged, 70 recovered, 35 lost**; role-specific witness replay/unknown handling | [JSON](controlled-history-2026-10-24/redis-recovery.json), [transcript](controlled-history-2026-10-24/redis.txt) |
| Short local HTTP/key-cleanup probe | **12/12 HTTP200**, 2 VUs × 3 s; both temporary keys revoked | [metrics](controlled-history-2026-10-24/capacity.json), [independent DB readback](controlled-history-2026-10-24/capacity-cleanup.json) |
| TypeScript/build/Ruff/pip-check | Passed | [types](controlled-history-2026-10-24/typecheck.txt), [build](controlled-history-2026-10-24/build.txt), [quality](controlled-history-2026-10-24/quality.txt) |
| Owned sandbox cleanup | Services stopped, ports closed, runtime data/private configs removed | [JSON](controlled-history-2026-10-24/cleanup.json) |

The PG suite includes real lock-contention timeout checks on evidence/link rows
and concurrent approval yielding exactly one 200 and one 409. It also runs the
existing audit concurrency/provenance suite. It is not a fresh full migration
qualification; the browser/recovery fixture was migrated to existing head 0107.

The [all429 red regression](controlled-history-2026-10-24/capacity-red.txt)
exercises the former actual harness `main()` with a synthetic throttled worker:
exit 0 despite no successful operations. It is a harness-correctness reproduction,
not an observed bank deployment. Current regression tests reject that result.

Browser execution used actual password sessions, native file upload, assignment,
proposal, same-human rejection, second-human approval, native schema validation,
blocked assessments, foreign-tenant requests and SQL evidence/audit readback.
An initial harness run reached the final verifier but used the wrong verifier
response key; the harness was corrected and rerun successfully. The successful
run after an owned API restart used current code; ordinary login rate limits
were not disabled. The screenshot contains only synthetic data.

## Interpretation: no hidden PASS expansion

- The HTTP probe is a tiny configured workload. Its p95/p99 are **not** a bank
  SLO, saturation capacity, long soak, scanner throughput or the agreed paired
  ≥20% bottleneck improvement. That performance target remains unmeasured.
- The PG drill restored to a fresh same-host database while source writers were
  stopped. It includes wrong-key/tamper refusal and transactional rollback on a
  real SQL error, not HA/promotion/PITR or deployed service RTO/RPO.
- Redis lost acknowledged post-checkpoint writes. That is retained as loss, not
  reclassified as success because PING worked or replay was possible. The same
  observer survived; scratch role structures are not all production consumers.
  The overcommit warning and unqualified TLS/ACL/replica scenarios remain explicit.
- The 134-entry audit verification supports this synthetic fixture only. It
  neither repairs pre-existing forks nor proves DB-administrator immutability.
- NBOM, CBOM, TechBOM, HBOM, vendor VBOM and SBOM remain six distinct outputs;
  this is not six-output discovery requalification.

Independent bank approval, penetration/security review, actual deployed recovery/
capacity and the remaining [original45 capabilities](../operations/bank-original45-engineering-gaps.md)
are still open. There were no customer deployment changes or invented operating
SLAs. [Replay instructions](controlled-history-2026-10-24/README.md) and
[source/artifact hashes](controlled-history-2026-10-24/manifest.json) make these
bounded claims inspectable; hashes are not an independent signature.
