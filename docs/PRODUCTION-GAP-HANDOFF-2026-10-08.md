# Production gap handoff — 2026-10-08

**Branch:** `arena/01a106c8-cryproscan`  
**Status:** Work stopped at the operator's request. **Not production-approved.** The supported deployment remains one instance per customer; shared multi-tenant SaaS is not qualified. This document records code changes, observed failures, and the next fixes. It is not a passing readiness artifact. The decision gate remains [`PRODUCTION-READINESS.md`](../PRODUCTION-READINESS.md).

## What this change set attempted

The first production blocker was raw source text entering hash-chained evidence. The scanner previously placed the matched line **and five adjacent lines** in `source.code_snippet`. A secret on an unrelated adjacent line could reach `EvidenceRecord.finding_data`, finding detail, JSON export, and audit materials. See `services/scanner/scanner/extractors/snippet_extractor.py`, `services/scanner/scanner/parsers/finding_factory.py`, and `services/database/db/loader/evidence_loader.py`.

The current change set:

- Keeps snippets available during parsing and cascade analysis, then projects scanner findings to structured fields before `Scanner.scan()` returns. Direct `RawFinding` serialization excludes `code_snippet` and `raw_transformation`. `EvidencePipeline` applies the projection again **before** hashing for callers that bypass the public scanner. A structured `crypto.hash_algorithm` retains recognized signature-digest information without publishing the raw transformation. See `shared/shared_models/shared_models/safe_finding.py`, `services/scanner/scanner/core/scanner.py`, and `services/evidence/evidence/core/pipeline.py`.
- Projects historical `finding_data` to a labelled, redacted **response view** for finding detail, scan JSON export, intelligence materials and audit ZIP. This does not alter stored data or make the view match the old content hash. Full-fidelity transfer of a row needing that projection is refused. See `services/api/api/security/evidence_projection.py` and `services/api/api/routers/{findings,export,intelligence}.py`.
- Stops same-ID findings from overwriting one another's content hashes; OT observations now have distinct IDs. Moves compliance-scope annotation before the evidence commitment instead of mutating stored `finding_data` during policy evaluation. See `services/evidence/evidence/core/pipeline.py`, `services/worker/worker/pipeline/{stage_ot_scan,pipeline_runner,stage_policy}.py`.
- Adds stored-content, position, predecessor, chain and manifest checks to the API and operator verifier. Empty evidence is reported separately; unverifiable historical records do not receive an unconditional `PASS`. The downloadable **chain-only** script now calls its outcome `CHAIN_ONLY`. Transfer format is now **1.1** and includes stable evidence IDs plus content/chain verification; version 1.0 is rejected by the new verifier. See `services/evidence/evidence/verification/stored_scan.py`, `scripts/verify_evidence.py`, and `services/evidence/evidence/pack/scan_transfer.py`.
- Regenerated `services/scanner/scanner/output/schema/scan_result_schema.json` using `make -C services/scanner schema`. Three unused imports in unrelated files were removed after the repository-wide Ruff check identified them; no behavior change was intended.

### Verification actually performed

| Check | Recorded result | Limitation |
|---|---|---|
| New scanner/evidence confidentiality regressions | Passed after the fix | Synthetic sentinels, not a customer estate |
| Scanner + evidence service suites | **313 passed, 12 skipped** at an intermediate point | Later changes require another run |
| Focused database loader, API findings/intelligence/transfer, OT, UAE/GCC, key-inventory, and SNB 1,020-system tests | Passed on their individual reruns | These do not replace the full suite |
| First `make test JOBS=4` | **7 failed, 6,591 passed, 20 skipped** | Failures drove subsequent fixes |
| Second `make test JOBS=4` | **1 failed, 6,601 passed, 20 skipped** | Failure was the checked-in scanner JSON schema; it was regenerated and its **4 focused contract tests passed**, but the full suite was **not rerun after the final edits** |
| Repository-wide `ruff check services scripts shared` | **Failed on 3 unused imports** | The imports were removed; the rerun was declined/interrupted, so lint is **not verified green** |
| `git diff --check` | Passed before the final changes | Recheck before release |

No test or scan process was running when the operator requested a stop. **Do not describe this branch as having a green final gate.**

## Open bugs and the smallest safe next step

| Priority | Gap / failure mode | What to do next |
|---|---|---|
| **P0** | **Historical evidence may still contain raw snippets or other sensitive data at rest.** Response projection is not deletion and old hashes commit to the original payload. | Inventory affected scans in the target environment under controlled access. Quarantine raw exports/transfers; obtain the evidence owner's retention/disposition decision. Re-scan/reissue a new chain with explicit provenance where required. Do **not** silently overwrite old `finding_data`, chain links, manifests or signatures. Keep readiness blocked until this is resolved. |
| **P0** | **Evidence change set lacks a final passing suite/lint result.** A schema mismatch was fixed after the second full run, and three baseline lint errors were removed, but neither gate was rerun. The new allowlist may omit fields used by less-tested collectors. | Run focused scanner/evidence/database/worker/API suites, `make test JOBS=4`, Ruff, schema contract and transfer tests; fix failures before starting another subsystem. Add a real-collector matrix for flat cloud/container/network/OT findings and confirm hashes and key-inventory policy fields remain correct. |
| **P0** | **Scan admission can fail open or bypass the gate.** `_safe_scan_gate` logs unexpected policy lookup errors and continues, and the common enqueue helper does not enforce it. The manual request's `is_ot` lookup has no declared schema field. `services/api/api/routers/trigger.py`. | Enforce one fail-closed decision at the common queue boundary; derive OT/active authorization from trusted scope and require an actual approved window. Test emergency stop, lookup outage, helper callers and passive/OT denial before enabling scans. |
| **P0** | **Authorized/passive discovery is not the active-probe boundary.** Onboarding can register network scope (including CIDRs) as enabled TLS targets, removal does not revoke materialized targets, and the Scanners UI falls back to an active CIDR sweep even when passive/TAP is selected. It can display a fabricated completed job. `services/api/api/routers/{onboarding,network}.py`, `frontend/src/pages/Scanners.tsx`. | Validate authorized hosts at registration **and execution**, never schedule CIDRs or passive OT scope as TLS hosts, track target provenance before revocation, remove the UI fallback/synthetic status, and poll a real job or report registration only. Add passive and scope-removal tests with no live probes. |
| **P0 for shared SaaS** | **Tenant ownership is lost across several boundaries.** GitHub webhook, queue reaper and some monitor jobs can omit `tenant_id`; unowned events can be visible to every tenant. WebSockets, global `/stream`/live views and NULL-owned cross-tenant snapshots need isolation. `services/api/api/routers/{webhooks,ws,stream,live,graph,techbom,digital_twin}.py`, `services/worker/worker/core/job_reaper.py`. | Keep shared deployment disabled. Copy ownership from trusted persisted configuration/job rows across every queue and event; scope WS replay and job reads; partition or deny global stores; prevent admin-wide snapshots from becoming tenant-visible NULL rows. Resolve globally unique snapshot versions before tenant-local capture. Test two tenants through HTTP, WS, worker recovery, exports and history, then seek independent adversarial review. |
| **P1** | **Transfer format compatibility changed.** New version 1.1 requires evidence IDs and full content/manifest checks; old 1.0 transfers are rejected. Malformed transfer sections also need more adversarial input coverage. | Document an operator-controlled migration/reissue path instead of downgrading verification. Add malformed `scan`/`digests`/`records` tests and ensure import returns a controlled 4xx, never a 500; do not certify old transfers by simply recomputing their transport digest. |
| **P1** | **Kubernetes readiness uses unconditional `/health`.** Both probes point to it although `/readyz` returns 503 during DB/dependency failure. `k8s/app/20-api-deployment.yaml`. | Point readiness at `/readyz`, liveness at `/healthz`, and set a timeout beyond the bounded DB probe. Test the manifest and an API database-outage response before deploying. |
| **P1** | **CI and release evidence are incomplete.** Frontend CI does not run Vitest; the referenced scanner test workflow is empty; immutable image digests, branch protection and provider/customer evidence are not established by repository files. | Add required frontend/scanner/network/OT jobs, publish digest-pinned images, verify branch protection with appropriate credentials, and retain target-environment evidence. Never convert a local test PASS into HSM, bank accuracy, penetration-test or attestation PASS. |
| **P2** | **BOM/cascade read models can understate impact.** Technology BOM fingerprints omit dependency edges and diffs ignore changed fields; some cascade paths mix names and IDs, drop secondary systems sharing evidence, or lose replay metadata. | After security/integrity gates pass, add edge-only/property-only snapshot tests, canonical system-ID propagation tests, disappeared-watch tests and point-in-time replay history tests; then change the pure projection functions and API persistence order. |

## Round 9 (2026-10-08, later) — gaps closed in code

Status of the table above after the follow-up change set (commit series on this branch, `951bc61`+):

| Gap | Status | What changed |
|---|---|---|
| P0 scan admission fail-open/bypass | **Fixed + tested** | `api/security/scan_admission.py` is one fail-closed decision at the common queue boundary (`enqueue_scan_job` + manual trigger + `/network/discover` + `/network/run-due` + `/network/ssh-scan`). Outage → 503 with no job row; emergency stop → 409; OT derived from trusted declarations (enabled onboarding environments), never the request; active probing on an OT estate requires an **actual declared, currently-open** maintenance window. 17 tests in `test_scan_admission.py`. |
| P0 authorized/passive discovery boundary | **Fixed + tested (backend + UI)** | CIDRs are authorization scope, never TLS targets (registration-time); `/network/discover` additionally verifies the sweep sits inside the declared scope at **execution** time (403 otherwise); `network_scan_targets.source` provenance (migration 0071) and scope deletion revokes only onboarding-materialized targets; `Scanners.tsx` no longer falls back to an active sweep on passive selections and never fabricates job ids or completed status — refusals are shown as failures. 6 materialization/revocation tests. |
| P0 tenant ownership | **Job, WS and snapshot batches fixed + tested; /stream event-bus partitioning still open** | Webhook jobs inherit the RepoConfiguration's tenant (row + payload; inline fallback re-enters the tenant scope); reaper and monitor republished payloads carry `tenant_id`; the tenant middleware now scopes **WebSockets** (query-param credentials routed through the same membership-validated resolution, refusal closes 1008); snapshot versions are unique **per tenant** on all four tables (migration 0071) with tenant-explicit allocation. The in-process eventstream bus behind `/stream/*` and the live-CBOM file store are still global stores — that partition is a separate, larger redesign and remains on the "shared SaaS disabled" list. |
| P1 transfer format 1.1 compatibility | **Adversarial input covered; reissue path documented** | `verify_transfer` rejects non-object `scan`/`digests` sections; 9 malformed-payload cases prove `/scans/import` answers a controlled 400, never a 500. Old 1.0 transfers: reissue via export→import per scan (the export side re-commits with stable evidence ids); see `docs/user-guide/operations-transfer.md`. **Not** certified by recomputing digests. |
| P1 Kubernetes readiness | **Fixed** | readiness → `/readyz`, liveness → `/healthz`, `timeoutSeconds: 10` (beyond the bounded DB probe) in `k8s/app/20-api-deployment.yaml`. |
| P1 CI completeness | **Content written; blocked on a workflow-scope credential** | Frontend Vitest job and a real five-service scanner-tests matrix are staged in `.github/workflows-pending/` (ci.yml copy + rewritten scanner-tests.yml): the automation credential cannot push files under `.github/workflows/` (needs `workflow` scope), the same constraint that emptied those files in `5a32105e`. Digest-pinned images, branch protection and external evidence remain open. |
| P2 BOM/cascade read models | **Not started** (deliberately after the integrity gates) | — |

Verified: ruff clean on all touched files; database suite 162 passed (migration-chain parity incl. 0071); evidence + intelligence suites 77 passed; worker suites green; frontend typecheck + 125 vitest tests green. The full-suite run is recorded in the round-9 commit.

## Round 10 (2026-10-08, evening) — P2 read models closed

Status of the P2 row after this change set (TDD: the failing tests were
written first, then the projections fixed):

| Gap from the P2 row | Status | What changed |
|---|---|---|
| Fingerprints omit dependency edges | **Fixed + tested** | `materialize_technology_bom` now stores the canonicalized `[source, target, type]` edge list in `state["dependencies"]` (both inventory dialects — pair lists and graph-snapshot dicts — normalize through `canonical_dependencies`; duplicates collapse). The fingerprint already hashed that key, so an edge-only change (re-wired estate, identical components) produces a new snapshot version. Engine test + end-to-end API test (`test_edge_only_change_creates_new_snapshot`). |
| Diffs ignore changed fields | **Fixed + tested** | `diff_technology_bom` reports per-layer `changed` entries with exact field-level from/to values for components whose `bom-ref` survived but whose fields moved (e.g. RSA 2048→4096), plus a `dependencies` section with added/removed edges. Surfaced through both `POST /technology-bom/snapshot` and `GET /technology-bom/compare`. |
| Cascade paths mix names and IDs | **Fixed + tested** | The vendor cascade reported `layers.system.systems` as system *names* while every other kind reported canonical IDs — consumers could not join the answer back to the registry. It now reports IDs like every other path (old test pinning names updated to the canonical contract). |
| Secondary systems sharing evidence dropped | **Fixed + tested** | `_cascade_algorithm` deduped evidence rows by id *before* collecting owning systems; the twin emits one row per (record, system) pair, so the second system silently vanished. Systems are now collected from every matching row; the evidence id still appears exactly once. |
| Replay metadata lost | **Fixed + tested** | `replayed_over` is stamped on the result **before** the run row is persisted, so the audit trail (and the `/cascade/runs` list, which now carries `replayed_over` per entry) records which twin snapshot an answer replayed — not just the HTTP response. The same-session identity-map hole that masked the bug is covered by re-reading the row through a fresh session. |
| Disappeared watch targets | **Fixed + tested** | run-due crashed with `KeyError: affected_systems` on the second run after a watched target left the estate (the NOT_FOUND shape carries a count but no system list). The diff now tolerates the NOT_FOUND shape on both sides, the entry carries an explicit `target_missing: true`, the disappearance is persisted as its own run, the collapsed blast radius is diffed once, and the watch stays active until retired. |

Also investigated and **refuted**: the twin-snapshot replay lookup
(`db.query(TwinSnapshot).filter(version==v)`) was suspected of missing a
tenant filter — the ORM tenant guard (`with_loader_criteria` on
`do_orm_execute`) reaches it automatically in tenant scope, matching the
round-9 tenancy design; no change needed.

Also fixed while re-running the full gate (test isolation, no product
change): six pre-round-9 tests (graphql job/batch reads, binary-scan queue
options, estate run-due) only passed through cross-file contamination — the
round-9 admission seam opens the **global** `SessionLocal`, and whichever
test file happened to configure the factory first in the worker process
decided whether these tests saw a bound or unbound session (unbound →
fail-closed 503). Adding round-10 tests shifted the xdist file grouping and
unmasked it. Their fixtures now bind `SessionLocal` to the test's own
engine (the pattern the tenancy fixtures already used), so each test's
admission decision reads its own empty control plane deterministically.

Verified: ruff clean repo-wide; full backend suite result recorded in the
round-10 commit. Docs updated: `docs/user-guide/cross-bom-cascade.md`
(replay provenance, watch disappearance semantics, and a "read-model honesty
guarantees" section).

## Resume order

1. **Finish the evidence subsystem first:** rerun and fix full backend tests, lint and synthetic end-to-end export/verification tests; decide the legacy at-rest gate without rewriting history. If it remains broken, stop there.
2. Then fix scan admission and authorized/passive discovery, including the UI's truthful job lifecycle and nested connector secret scrubbing. Run focused and full relevant suites before moving on.
3. Then fix Kubernetes/CI release checks and the tenant boundary in separately tested job, realtime and snapshot batches. Keep multi-tenant SaaS disabled throughout.
4. Re-run the current engineering/readiness gate against the actual release/environment. Its external categories remain FAIL/SKIP until their owners supply genuine evidence.
