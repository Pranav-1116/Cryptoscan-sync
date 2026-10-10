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

## Round 11 (2026-10-08, night) — /stream + live-CBOM partitioned

The last open item of the P0-SaaS row ("the in-process eventstream bus
behind `/stream/*` and the live-CBOM file store are still global stores")
is closed in code:

| Surface | What changed |
|---|---|
| Bus partitioning | `eventstream.partitions` + `get_bus_for_tenant()`: unscoped requests keep the base log dir (pre-tenancy paths, on-prem unchanged); tenant-scoped requests get `<base>/tenants/<tenant-id>/` with their own append-only logs and consumer cursors. Instances cached per resolved dir; `reset_bus()` clears every partition. |
| Live-CBOM store partitioning | Same rule for the CBOM version store: `<CBOM_STORE_DIR>/tenants/<tenant-id>/`. Two tenants using the same system id get two independent signed chains (tested: same id, both chains valid, versions never cross-bump). |
| Router | `/stream/ingest`, `/stream/events`, `/stream/stats`, `/attacks`, `/attacks/summary`, `/cbom/live|versions|diff|verify|stream` all resolve bus/service/projector per request scope (`db.tenancy.current_tenant()` set by the middleware). |
| Compliance retention | `/compliance/retention` reads the caller's partition for the oldest audit record — one tenant's processing history is not another tenant's retention clock. |
| Monitor daemon | `engine._publish_pass` publishes into the TARGET's partition (tenant-owned monitors write tenant observations); unowned targets keep the platform bus. |
| Ops self-check | The one cross-partition reader: aggregates platform + every tenant partition on disk (bus lag per topic, stale CBOMs). Operator-only, read-only, inventories directories — never the tenant table. |
| Isolation semantics | Strict both directions: each scope sees only its own partition (unlike DB rows, where tenants also see NULL-owned platform rows — stream partitions carry raw observations, and cross-visibility would put one customer's detections in another's console). Documented in `docs/architecture/event-stream.md`. |

Tests: `services/api/tests/unit/test_stream_tenancy.py` (5) runs the real
stack — session cookies, TenantScopeMiddleware, two tenants + an unscoped
operator: cross-tenant invisibility of attacks/events/stats/CBOMs, same
system id → two chains, platform partition invisible to tenants,
retention per partition, and the physical on-disk layout. The existing
stream suite (2) and worker suites (525) stay green; the monitor publish
redirect is covered by the worker battery.

Still open from the wider table: CI digest-pinned images / branch
protection (workflow-scope token; content staged in
`.github/workflows-pending/`), external evidence items, historical
evidence at rest (target-environment decisions). The `/compliance/retention`
endpoint also still lacks an auth dependency of its own (it reads settings
only) — noted, not changed here.

## Round 12 (2026-10-08, late) — tenant_id connected end to end

The user-facing ask: "connect the all API and tenant_id backend, frontend
and database." Audit result first: the enforcement chain built in rounds
5-11 was already complete (the repo's own `tenant_isolation_audit.py`
passes — 99 scoped tables, 12 justified platform tables; every frontend
call already flows through `tenantFetch`, which attaches `X-Tenant-ID`).
What was missing was the last mile of UX and visibility:

| Seam | What changed |
|---|---|
| Frontend picker on the Tenancy page | New inline "Switch organization" panel: one button per membership from `GET /saas/memberships` (backend-derived, never header-derived), a "Platform estate" option for platform admins, hidden for single-org users. Switching refreshes the page's live data and reconnects realtime consumers. The stale "switch orgs by signing in with a member of the other organization" copy is gone. |
| Ownership visible in payloads | `GET /technology-bom/cascade/watches` and `/cascade/runs` now carry `tenant_id` per row (NULL = platform estate) — the DB column is connected to the surface the console reads. |
| The chain, pinned as one test | `test_tenant_e2e_flow.py` runs the real stack (session cookies + TenantScopeMiddleware, one user in two orgs): memberships directory → header → whoami → tenant-stamped write (verified on the raw row under `platform_scope`) → scoped list with `tenant_id` → cross-tenant invisibility → no-header 400 → stranger-header 403/404. |
| Frontend contract pinned | `Tenancy.test.tsx` (5 vitest): picker renders from memberships, switch stores the org, the NEXT API call carries the switched header, platform option only for admins, hidden for single-org users. |
| Docs | New `docs/user-guide/multi-tenancy.md`: the whole chain (browser → header → middleware → ORM → stamped rows → scoped payloads), how switching works, per-surface isolation rules, and the platform estate. |

Gates: full backend suite and frontend typecheck/vitest results recorded
in the round-12 commit; ruff clean; rest-api regen unchanged.

## Round 13 (2026-10-09) — route-auth inventory: a gate, two fixes

The user's continuation picked up the retention-auth note from round 11
and generalized it: audit EVERY route's authentication, then make the
class of bug impossible to reintroduce.

The audit needed three passes because authentication lives in four
shapes: route dependencies, router-level dependencies
(`APIRouter(dependencies=[...])` — telecom/hardware/etc. authenticate
whole routers this way), aliased `require_permission(...)` factories
(the inner function's name carries no marker; only its module
identifies it), and inline handler checks (`require_auditor(request)`,
`token_from_request` + manual 401). Name-matching catches only the
first shape; the final audit resolves every dependency by
module-qualified name and falls back to source inspection for inline
checks.

| Finding | Resolution |
|---|---|
| `GET /compliance/retention` had no authentication of any kind | Now `Depends(get_current_user)` — the retention clock is derived from the caller-partitioned audit trail (round 11), so anonymous readers learned org-specific facts. Behavioral pin: 401 without credentials. The auditor-key path for external auditors remains `/compliance/audit/retention`. |
| The Stripe billing webhook was NOT exempt from the session gate | Its own docstring says "the signature is the only authentication" — but production's AuthMiddleware demanded a session first, so every real billing callback 401'd. Now in `UNPROTECTED_PREFIXES` (same pattern as `/api/v1/webhooks`); behavioral pin: an unsigned callback is answered by the route (400 invalid signature), never by the gate (401). |
| `/metrics`, health, docs, login/SSO/webhooks surfaces | Intentionally open (probes, credential-bearing by design) — enumerated as the exemption list, imported from the middleware so there is one source of truth. |
| Everything else (789 routes) | Already authenticated through one of the four shapes — no action. |

The permanent gate: `services/api/tests/security/test_route_auth_inventory.py`
walks all ~790 routes on every run, resolves each dependency tree by
module, recognizes inline checks, and fails BY NAME if any non-exempt
route ships without an authentication seam. Verified it catches the
retention bug when temporarily reverted. A new route without auth now
fails CI instead of shipping open.

## Round 14 — audit-report reconciliation (2026-10-09)

The user added `audit_reports/` (65 files, generated 2026-09-20). Every
report was read; every actionable claim was re-checked against current code
(audit 88's register is substantially stale — it predates rounds 9–13).
Full verdict table: `docs/AUDIT-RECONCILIATION-2026-10-09.md`.

Two genuinely-missing code capabilities were built:

1. **Remediation verification loop (GAP-006 / audit 62).** Remediation was
   suggestions-only. New: `remediation_tasks` + `remediation_verifications`
   (migration 0072), a pure five-verdict engine
   (`remediation/verification.py` — VERIFIED / PARTIAL / FAILED / REGRESSION
   / INCONCLUSIVE, decision pinned by 13 table tests), and seven endpoints
   on the remediation router. Completion auto-verifies against the latest
   completed scan of the same target newer than the original scan (or an
   explicit rescan; mismatched targets are rejected 400). Findings and the
   target location are snapshotted at task creation, verdicts persist the
   full comparison, and every transition emits a platform event. No rescan
   → INCONCLUSIVE, task honestly stays COMPLETED. 8 end-to-end API tests.
2. **Hybrid-PQC protocol detection (GAP-014/015 / audits 52+59).** TLS
   supported_groups were anonymous hex, `sntrup761x25519` was mislabelled
   plain X25519 (a PQ KEX reported Shor-vulnerable), and the IKEv2 DH table
   contradicted IANA (27/28 are brainpool, not X25519/X448; 24/25/26 were
   wrong too). Fixed across the shared registry (`kem-hybrid-pqc` family →
   PQC_RESISTANT, RFC 10024 hybrids ALLOWED, Kyber drafts + sntrup761
   RESTRICTED), the universal protocol engine (named TLS_GROUPS incl.
   0x11EB–0x11EF and 0x6399/0x639A; SSH hybrid wire names; IKEv2 groups
   35/36/37 = ML-KEM-512/768/1024 per RFC ipsecme-ikev2-mlkem), and the
   runtime TLS parser (same map; 0x00FF "ffdhe8192" bug — 8192 is 0x0104).

Everything else in the register was already fixed (tenant gate, link-table
tenancy, HBOM/VBOM layers, drift/baselines, Technology BOM, realtime cap,
graph sync coordinator), is deployment-scoped (gVisor, encryption at rest,
mTLS, HA/read replicas — see PRODUCTION-ROADMAP), or is not applicable
(no AI exists in the deterministic path; the webhooks router is inbound).
Remaining honest backlog lives in the reconciliation doc §6.

## Round 15 — the remaining code-buildable audit gaps (2026-10-09)

Round 14's reconciliation left an honest open list; the user asked for the
code-buildable remainder to be built. Four more gaps closed (audit_reports/
now carries per-report UPDATE addenda + 00_ROUND_STATUS.md):

1. **Reintroduction detection (GAP-023 / audit 69):** retired_assets
   registry (migration 0073), pure scope-matching detector
   (FILE/ASSET/ALGORITHM), severity routing (hardcoded/FAIL→CRITICAL,
   WARN→HIGH, clean→MEDIUM), auditor-gated registration/lift with reasons,
   and POST /retirements/check/{scan_id} emitting one routed event per
   detection. Malformed registry rows never silently match everything.
2. **Conflict detection (audit 50):** normalization/conflicts.py classifies
   ALGORITHM/PARAMETER/STATUS mismatches at the same site; surfaced at GET
   /findings/conflicts (within-scan across scanners, or scan-vs-scan with
   both sides stamped). Reported, never auto-resolved.
3. **Crypto-asset lifecycle (audit 54):** crypto_assets.lifecycle_state
   (migration 0073) with server-enforced DISCOVERED→VERIFIED→ACTIVE→
   DEPRECATED→RETIRED transitions (RETIRED terminal; illegal jumps 409 with
   the allowed set), reasons mandatory, events audited, inventory filter
   added.
4. **Evidence-chain sweep (TD-010):** GET /ops/evidence/chain-status runs
   the export verifier across recent scans; evidence.chain_broken event on
   breakage — integrity is now a queryable property, not an export-time
   surprise.

Gates: security suite (route-auth inventory now covers the 8 new routes),
database suite (migration chain 0073), inventory/findings/ops/remediation
blast radius, full suite rerun after these edits.

## Round 16 — the ten-report full read (2026-10-09)

Reports 01–10 were read end to end and every finding re-verified against the
code. Five real gaps were built (migration 0074; details in the round-16
UPDATE addenda inside audit_reports/03–10):

1. **Policy rule overrides (audit 05):** tenant-scoped
   `policy_rule_overrides` + admin `PUT/DELETE /policy/rules/{id}/override`
   (disable a rule / change severity per tenant, audited) with
   `GET /policy/rules` reporting pack vs override vs effective; the worker's
   evaluation stage applies the same rows through one shared helper.
2. **MAX_QUEUE_DEPTH admission gate (audit 05):** 429 once active jobs
   exceed the configured depth (default 500); counting is a documented seam,
   fail-closed on count failure.
3. **Optimistic scan-job locking (audit 04):** `scan_jobs.version` CAS in
   `JobRepository.update_status` + terminal-state guard; reaper races
   resolve to detected conflicts, not silent overwrites.
4. **Drift → remediation auto-link (audit 03):** acknowledgement can
   auto-open PROPOSED tasks for the failing evidence behind a drift event
   (`source="drift"`, `source_ref`), listed at
   `GET /drift/{id}/remediation-tasks`.
5. **Clone-URL transport validation (audit 10):** `ext::`/helper
   transports and leading dashes refused before git is imported.

Plus the frontend a11y P0s (ARIA Tabs, keyboard-activatable Table rows,
scoped headers). A large share of the reports' remaining claims were
verified stale and are recorded as such in the addenda (HBOM wired,
CryptoAssetEvidence populated, password policy exists, artifact store
tenant-bucketed, graph sync runs post-scan, crypto_live/audit_log indexes
present; the system_dependencies relation-level unique index was evaluated
and deliberately kept as pair-level dedup).

Gates: full API suite (1353), worker 525, scanner 286 (+20 URL-validation),
database 162 (chain 0074 verified from repo root), cbom 233, policy 96,
remediation 42, shared 519, evidence 55, graph_engine 52, drift 72,
normalization 123, control_plane 81, devsecops 550, frontend 132 +
typecheck, ruff clean repo-wide, rest-api.md regenerated (736 paths / 815
ops / 90 groups).

## Round 17 — the seven-report full read: audits 11–16 + CRYPTO_SCAN_DISCOVERY (2026-10-09)

Read all seven in full; verified every claim against the code (11 of 12
headline claims stale in the reports' favor). Six real gaps built
(migration 0075):

1. **Evidence soft-delete preserving the chain (15 §6.2, 16
   EVIDENCE-003):** tombstone columns + auditor-gated
   `/findings/{id}/soft-delete` and `/findings/{id}/restore`;
   listings/CBOM/conflicts/drift/remediation/intelligence/retirement
   exclude tombstones, chain verification and exports keep them.
2. **Encrypted backups (15 §4):** `backup_evidence.py --encrypt`
   (AES-256-GCM + scrypt, `BACKUP_ENCRYPTION_KEY`, `CSBC1` header);
   restore decrypts pre-manifest, fails closed, deletes plaintext after.
   Shared module `scripts/backup_crypto.py`.
3. **QUIC/DTLS/WireGuard analyzers (13 §3.1, discovery P3-001):**
   protocol_engine + engine wiring, same PROTOCOL evidence pattern as
   TLS/SSH/IPsec.
4. **CBOM portfolio scale (14 TD-007):** set-based `_located_assets` +
   one-query dependency edges + `PORTFOLIO_MAX_ASSETS` explicit
   truncation metadata (no more silent 5000-row stop).
5. **Duplicate OpenAPI operationIds:** fixed (container history router
   rename + explicit operation_id) and pinned by
   `test_openapi_contract.py` (uniqueness, versioned paths + infra-probe
   allowlist, tagged ops).
6. **Property tests + coverage (11):** hypothesis pinned, 7 properties
   over the hashing core; pytest-cov + `.coveragerc` +
   `scripts/coverage.sh` opt-in (gate = suite result, never a
   percentage).

Note for the next session: universal_crypto (148 tests) must run with
the standard PYTHONPATH (services/* + shared/*) — without shared_models
it degrades gracefully and 18 tests fail on registry-family assertions
that only look like regressions. Universal_crypto joins the gate list
from this round on.

Still open after this round (unchanged buckets): transitive-dependency
crypto graph, cloud HSM detection, resource-level RBAC, official SDKs,
deployment-scoped items (encryption at rest, mTLS, HA, read replicas),
CI-blocked tooling (atheris/Playwright/k6/mutmut/Allure/chaos — staged in
`.github/workflows-pending/` where applicable).

## Round 18 — the remaining open audit items (2026-10-09)

Round 17's close-out left three code-buildable items; all three built
(migration 0076):

1. **Transitive crypto propagation (13 §1.3, DISCOVERY P1-002):**
   `propagate_crypto_dependencies` in the scanner cascade — package graph
   ⟕ crypto-library catalog, exposure propagated up lockfile parent
   chains, `crypto_dependency_paths` with per-chain algorithms and honest
   ecosystem edge coverage.
2. **Cloud HSM detection (13 §3.2):** Azure Dedicated HSM scanner +
   GCP `hsm_backed` marker; AWS CloudHSM / Azure Managed HSM were already
   there (stale matrix).
3. **Resource-level grants floor (13 §2.2):** `resource_grants`
   (owner > operator > viewer), restrictive-only-when-present, enforced on
   per-system endpoints (read viewer+/write operator+, superadmin
   bypass, auditor read bypass), admin-only audited management endpoints.

Gates this round: scanner 291 (+5 propagation), cloud_scanner 414 (+2
HSM), api suite re-run green including 6 new grant tests; rest-api.md
regenerated for the 3 new grant endpoints; migration chain 0001→0076.

Remaining open after round 18: BU→System→Asset grant inheritance and
custom role definitions (by design, product decision), official SDKs,
deployment-scoped items (encryption at rest, mTLS, HA, read replicas),
CI-blocked tooling (staged in `.github/workflows-pending/`).

## Round 19 — the advanced/deep re-study (2026-10-10)

Round 18's close-out was challenged ("many things still missing"), so
all advanced/deep reports were re-read against the code. Outcome: two
stale verdicts corrected, four buildable cores shipped (migration
0077):

1. **Evidence authority hierarchy (49):** 6-tier model
   (RUNTIME > BINARY > STATIC > DECLARED > MANUAL > UNRANKED) in
   `normalization/authority.py`, wired into `detect_conflicts` — every
   conflict now carries an `authority` preference (decisive or tie),
   never auto-resolving.
2. **System ownership roles (55):** `technical_owner` +
   `security_owner` on systems (migration 0077), create/patch/import
   surfaces, and `system.ownership_change` audit entries with old→new
   on every effective change.
3. **Exposure path queries (58):** `GET /exposure/paths` — bounded
   walks entry-candidate → dependencies → crypto assets, designation
   filters, cycle-free, honest entry heuristic (no topology scan).
4. **Unified risk upgrades (64):** `CRYPTOSCAN_RISK_WEIGHTS`
   env-configurable weights (all-or-nothing validation, absolute for
   named factors), `GET /risk/systems[/{id}]` with all eight factor
   levels derived from persisted state + raw `signals`,
   `calculation_version` stamping. Report 64's "no unified model" was
   already stale — `/risk/unified` + the §29b engine shipped earlier.

Gates this round: api 1388 (+14), worker 525, normalization 139 (+16),
universal_platform 40 (+5), database 162, scanner 291+12s,
cloud_scanner 414, cbom 233, policy 96, remediation 42, evidence 62,
graph_engine 52, drift 72, control_plane 81, devsecops 550,
universal_crypto 148, shared_models 519; ruff clean; chain 0001→0077;
rest-api.md regenerated (743/823/91). Frontend untouched (no frontend
files changed).

Remaining open after round 19: 47/51 (product-level layering), 57
topology nodes (deployment), 49 freshness decay/calibration, 55
asset-level multi-owner model, 64 threat/EPSS modeling (external
feeds), 13 §2.1/§2.3/§2.4/§3.1 (deployment/product), 82 zero-trust
(deployment), SDKs, CI-blocked tooling.


## Round 20 — full re-read of the 17 reports: error/bug pass (2026-10-10)

All of reports 01–16 + CRYPTO_SCAN_DISCOVERY re-read in full. Fixed:

1. **Silent estate truncation (9 surfaces):** `list_all_bounded()`
   replaces single-page reads in the graph payload, agility ×4, estate
   due-scan ×2, CBOM portfolio ×2, exposure paths — truncation now
   bounded and reported (`collection` meta, `systems_truncated` flags).
2. **Graph ghost nodes:** Neo4j sync prunes kinds present in the sync
   whose ids vanished (deleted systems/assets no longer linger).
3. **Neo4j `network_resources` TypeError:** latent crash on any
   real-driver sync; NetworkResource + CONNECTS_TO now merge properly.
4. **CBOM confidence:** recorded observation confidence propagates to
   the CycloneDX evidence block + component property (was hardcoded 0.9).
5. **Graph export:** `GET /graph/export?format=graphml|gexf`.
6. **Doc correction:** report 16's EVIDENCE-002 "open" line was wrong
   (migrations 0061/0062 did it) — corrected in that file.

Gates: api 1396, graph_engine 58, cbom 236, worker 522, database 162,
ruff clean, rest-api 744/824/91. All 17 files carry round-20 addenda.

Remaining open: container-image graph nodes, PKCS#11/KMIP pipeline,
wire-capture parsing, CBOM signatures/compositions/semantic diff, ADRs,
deployment items, CI-blocked tooling, SDKs, product decisions.

## Resume order

1. **Finish the evidence subsystem first:** rerun and fix full backend tests, lint and synthetic end-to-end export/verification tests; decide the legacy at-rest gate without rewriting history. If it remains broken, stop there.
2. Then fix scan admission and authorized/passive discovery, including the UI's truthful job lifecycle and nested connector secret scrubbing. Run focused and full relevant suites before moving on.
3. Then fix Kubernetes/CI release checks and the tenant boundary in separately tested job, realtime and snapshot batches. Keep multi-tenant SaaS disabled throughout.
4. Re-run the current engineering/readiness gate against the actual release/environment. Its external categories remain FAIL/SKIP until their owners supply genuine evidence.
