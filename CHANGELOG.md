# Changelog

All notable changes to CryptoScan / ZELNX. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
git-tagged from `VERSION`.

## [Unreleased]

### Fixed / Added — round 81: the operator loop ran end to end twice, and two defects it could not hide

Round 81 is an operator-loop round. `scripts/operator_loop_drill.py` drives the
whole chain against a running API — authorize -> scan -> hash-chained evidence ->
auditor-approved baseline -> drift -> owned task -> authorized change -> rescan ->
condition-level verification -> pinned, integrity-checked report — twice over a
three-system estate (Java/Maven payments service, Natural-on-ICSF mainframe, RPG
IV / ILE C / GSKit on IBM i), provoking every verdict on purpose (VERIFIED,
FAILED, PARTIAL, REGRESSION, INCONCLUSIVE) plus a reintroduced condition and the
ticket-as-fix shortcut. It records 121 checks, all passing, in
`docs/readiness-evidence/operator-loop-drill-2026-10-16.json`. Running it is what
found the two defects below; neither is visible to a unit suite, because both need
a *second* scan of the *same* estate through the *whole* chain.

- **Evidence identity carried the worker's job id, so an honest fix could never
  verify.** The container stage handed dependency findings to the evidence stage
  with `file_path` taken verbatim from the library manifest — the worker's own
  staging path (`data/workspaces/job-<uuid>/repo/pom.xml`, `line_number` 0). A
  rescan stages into a *fresh* job directory, so every dependency-derived record
  changed identity between runs: drift saw the old row vanish and a new one appear
  (REMOVED/ADDED alerts for crypto that never moved), and verification's
  target-wide regression sweep — which compares `(file_path, line_number,
  algorithm)` fingerprints — always found a "new" non-compliant row and downgraded
  VERIFIED to REGRESSION. Fixed at the source: the stage rebases container-derived
  paths onto the target's own coordinates (`_rebase_findings`, disclosed as
  `scan_meta["container"]["evidence_paths_rebased"]`; genuinely foreign paths such
  as an image-internal `/etc/apk/world` are left alone), and
  `PipelineRunner._container` — which carried a second inline copy of the stage and
  was what actually ran — now delegates to it. `ContainerScan.target` still records
  the staging path on purpose: that is provenance about the run, not identity of the
  evidence. Measured: 20 evidence records before and after, 0 differing coordinates
  across two job ids, asserted every pass by the drill's `identity.stable` check.
- **`POST /remediation/tasks` dropped its own audit event.** `create_task` wrote the
  task row on the request session and then emitted `remediation.task_created` on a
  *second* connection, inside the still-open request transaction — so on SQLite it
  waited out `busy_timeout` (`database is locked`, ~5 s per request) and lost the
  row while the route answered 200. Before: 5 tasks in the database, 0
  `task_created` events. After: 5 and 5, and the request went from 5021 ms to
  8.7 ms. The fix threads the caller's session (`session=db`) — the convention
  round 80 established for the pipeline — and the same call inside
  `drift._create_drift_remediation_tasks` is fixed too, where the surrounding
  `except` would have swallowed the drop without a trace.
- **A third defect was found and is deliberately not fixed here.**
  `emit_platform_event` writes platform-scope rows with `target_id = NULL`, and
  `GET /monitor/events` filters on `target_id IN (SELECT id FROM monitor_targets ...)`,
  so those rows — every `remediation.task_*` event — are unreachable through that
  endpoint for any caller, a platform admin included. The rows are durable and
  readable through `GET /events/recent` and the SSE stream, which is where the drill
  reads them; rewriting a tenant-scoped query was not a last-step edit. Recorded in
  `PRODUCT-VISION-AND-GAPS.md` §4.7 and in the drill's own notes.

### Fixed — round 80: derived writes were silently lost on the supported SQLite backend (transaction-scope contention)

Found by running one real end-to-end scan against the documented single-box
default (`ALLOW_SQLITE`, file-backed SQLite) and reading the database
afterwards — not by a test that was failing. Every scan logged two warnings
and then reported success, and the rows those warnings described were gone:

```
WARNING platform_event_persist_failed: (sqlite3.OperationalError) database is locked
WARNING stage_cbom_snapshot_persist_failed
scans=1  evidence_records=19  cryptographic_facts=19  cbom_snapshots=0  monitor_events=0
```

- **The mechanism is transaction scope, not the writers.**
  `PipelineRunner.run()` writes every stage on one session and commits once at
  the end, so it holds SQLite's single write lock for the whole run (~18 s
  measured on a 19-evidence scan). Three callees opened their *own*
  `SessionLocal()` to write a derived row — `stage_cbom_generate._persist_snapshot`,
  `emit_platform_event._persist` (reached from `graph_builder.sync_graph`,
  which already had the pipeline session in hand), and `_stamp_coverage_failed`
  — so each waited out `busy_timeout=5000` and lost. The same
  `POST /cbom/scan/{id}/snapshot` against an idle database succeeded in
  milliseconds, which is what made this look like a CBOM bug. All three now
  write on the caller's session (flush; never commit or close a session they do
  not own) — the convention `_set_job_status` already documents at length and
  `_quantum`/`_facts`/`_graph` already follow. Blast radius of the loss was
  the journal the R76 notification feed, the R77 dispatch registry and the
  R78/R79 health probes read, plus the scan's only surviving BOM.
- **A failed scan left system coverage claiming `CURRENT`.**
  `_stamp_coverage_failed` ran *before* the pipeline's rollback, so its own
  connection was locked out by the transaction that was about to be discarded,
  and the failure was swallowed at debug level (`coverage_fail_stamp_skipped`).
  The rollback now happens first: the stamp still travels on its own connection
  (it has to survive the rollback) but no longer has to win a lock the doomed
  transaction is holding.
- **A refused job could crash instead of refusing.** The round-46 execution
  gate fails closed when it cannot read the control plane, and
  `JobExecutor._gated` then stamped the row FAILED on a fresh session — which
  was unavailable in exactly the situation that caused the refusal.
  `UnboundExecutionError` escaped `execute()`, the pool logged
  `job_execution_failed` (a crash), and the row was never stamped with the gate
  reason, so the audit trail lost the one sentence explaining why the scan did
  not run. The stamp is now best-effort by contract: roll back, log
  `job_refusal_stamp_failed` carrying the gate's reason, return `False`, and
  leave the row to the reaper.
- **A silent optional-stage failure now discloses (§4.8 round 39).** The CBOM
  stage logged `stage_cbom_snapshot_persist_failed` and then reported
  `stage_cbom_done` with no `optional_stage_failures` entry, unlike the other
  14 soft-failed sites — and the workspace rendering evaporates with the run,
  so a failed pin means the scan has no surviving BOM at all while coverage
  implied complete observation. `_cbom` now converts the stage's marker into
  the standard disclosure entry on the Scan row; the round-39 source guard
  counts the new site.
- **Tests.** `test_binary_job.py::test_executor_routes_binary_targets_to_the_binary_job`
  was order-dependent: it passed only when an earlier module in the same pytest
  process had bound `SessionLocal` (`services/api`'s `test_auth_lifecycle` is
  the only one that calls `init_db()`), so `make test`'s xdist ordering hid a
  real failure that `make test-serial` and any worker-only run exposed. It now
  permits at the gate explicitly — it asserts routing, not gating, and the
  gate's fail-closed behaviour stays pinned in `test_execution_gate.py`. New:
  `test_job_executor_refusal.py` (4 tests) and
  `test_pipeline_durable_writes_sqlite.py` (7). The latter runs on file-backed
  SQLite with two real connections, because the existing pin test binds an
  in-memory `StaticPool` engine where every "second" session shares the one
  connection and writer-vs-writer contention cannot exist — that is why the pin
  looked durable while every real run lost it. Verified against a real inline
  scan after the fix: zero `*_persist_failed` warnings, `cbom_snapshots=1`
  (generator `pipeline`, 17 components), `monitor_events=1` (`graph.updated`,
  20 nodes / 19 edges).

### Added — rounds 21–79: the gap-closure arc (consolidated entry)

Rounds 21–79 closed the product-vision gaps round by round; the per-round
detail lives in [`audit_reports/00_ROUND_STATUS.md`](audit_reports/00_ROUND_STATUS.md)
(complete through round 79) and [`PRODUCT-VISION-AND-GAPS.md`](PRODUCT-VISION-AND-GAPS.md).
The arc, grouped:

- **Truth and safety (§4.1/§4.2):** hostile-input bounds (fail-closed archive
  extraction, scanner sandbox with wall-clock budgets), seccomp syscall
  isolation + fd hygiene for scanner children (x86-64/arm64), the crypto-asset
  identity spine, historical evidence disposition, per-record evidence
  verification shared by the scan sweep and `GET /findings/{id}/verify`.
- **Engines and BOMs (§4.3/§4.4/§4.6):** behavioral rule coverage 62/63 with
  cross-scanner alias equivalence; content-addressed CBOM/HBOM/report snapshot
  pins with pin-to-pin diffs; the independent unified estate HBOM; live
  TLS-handshake NBOM; the risk explainability chain at system and asset level.
- **Backend and observability (§4.8):** durable per-run job records for every
  scanner mode (HSM key-check and CT-monitor included, with honestly-labeled
  SUBMITTED vs LIVE verification), replica-shared API-key quota windows, the
  trusted-proxy client-IP boundary, and independent health probes for the
  worker fleet (`GET /health/worker-fleet`) and connectors
  (`GET /health/connectors`) — measured from durable records, never API
  liveness.
- **Frontend (§5):** the remediation task lifecycle page; asset-detail
  cross-links (facts by spine join, blast radius, remediation tab through the
  stored asset-evidence join); the persisted certificate estate; per-record
  verification in the Findings drawer and on the Evidence page with an honest
  X-of-Y coverage line; a filterable audit ledger; the global
  accessibility/responsive pass (WCAG-AA contrast contract); and notification
  routing made load-bearing end to end — in-app feed
  (`GET /notifications/feed`), outward webhook/SIEM dispatch
  (`POST /notifications/dispatch`, per-tenant exactly-once registry), measured
  connector status replacing the fabricated CONNECTED derivation.
- **Assurance (§6/§7):** the full-chain end-to-end demonstration (three
  pipeline passes with the operator loop), per-round full serial gates (7,618
  backend / 334 frontend tests at round 79), and regenerated engineering-gate
  + bank-readiness evidence at every push.

### Fixed / Added — round 20: full re-read of reports 01–16 + CRYPTO_SCAN_DISCOVERY (error/bug pass)

- **Silent estate truncation eliminated (bug class, 9 surfaces):** the
  graph payload, four agility endpoints, estate due-scan planning, two
  CBOM portfolio paths, and exposure paths each read a single
  500/1000-row page — systems beyond it were invisible to the graph,
  blast radius, snapshots, agility aggregates, and re-scan scheduling.
  `SystemRepository.list_all_bounded()` now walks every page (bounded at
  50k rows), the graph payload carries `collection` meta, and affected
  endpoints report `systems_truncated`.
- **Graph ghost nodes pruned (bug):** MERGE-only Neo4j sync kept deleted
  systems/assets in the graph forever. Sync now prunes each kind present
  in the payload whose ids are absent (never touches kinds absent from a
  sync; ComplianceScope excluded) and reports `pruned`.
- **Neo4j `network_resources` sync (latent crash fixed):** the payload
  key existed but the store never accepted it — any real-driver sync
  raised `TypeError` (masked in tests by the memory fallback).
  NetworkResource nodes and `CONNECTS_TO` edges now merge on Neo4j,
  mirroring the memory engine.
- **CBOM evidence-confidence propagation (was hardcoded):** recorded
  observation confidence (HIGH/MEDIUM/LOW) now flows into the CycloneDX
  evidence block and a `cryptoscan:confidence` component property;
  unrecorded keeps the historical default, nothing fabricated upward.
- **Graph export:** `GET /graph/export?format=graphml|gexf` — the same
  graph `/graph` serves, XML-escaped, with kind/relation attributes for
  Gephi/yEd/Cytoscape.
- **Docs:** round-20 addenda written into all 17 report files; report
  16's erroneous "EVIDENCE-002 still open" line corrected (migrations
  0061/0062 had covered it).

### Added — round 19: the advanced/deep re-study (advanced/49, 55, 58, 64)

- **Evidence authority hierarchy:** explicit 6-tier model (RUNTIME >
  BINARY > STATIC > DECLARED > MANUAL > UNRANKED) in
  `normalization/authority.py`; every conflict from
  `GET /findings/conflicts` now carries an `authority` annotation
  saying which observer the hierarchy favors and whether that is
  decisive or a tie — annotation only, conflicts are never
  auto-resolved.
- **System ownership roles:** `systems.technical_owner` and
  `systems.security_owner` (migration 0077) with create/patch/CMDB-
  import surfaces; effective ownership changes write
  `system.ownership_change` audit entries (old → new per field);
  same-value patches are not audited.
- **Exposure path queries:** `GET /exposure/paths` — bounded
  (depth ≤ 4, ≤ 100 paths, cycle-free) walks from entry-candidate
  systems (cloud-hosted or remote scan targets) over dependency edges
  to attached crypto assets, filtered by algorithm or NIST designation
  rank; the response states the entry heuristic honestly (no network
  topology scan exists).
- **Unified risk upgrades:** `CRYPTOSCAN_RISK_WEIGHTS` env variable
  re-weights the eight blueprint factors (absolute weights for named
  factors, remainder split proportionally; invalid JSON falls back
  wholly and is reported via `weights_source`); new
  `GET /risk/systems` and `GET /risk/systems/{id}` derive every factor
  level from persisted state (registry designations, quantum impact,
  compliance, drift, CVEs, dependencies, environment, criticality)
  with raw derivation `signals`; every assessment is stamped with
  `calculation_version`.
- **Corrections:** report 64's "no unified risk model exists" was
  already stale (`/risk/unified` + the §29b engine); report 49's
  conflict-detection P0 was already built in round 15.

### Added — round 18: the remaining open audit items (13 §1.3/§2.2/§3.2, DISCOVERY P1-002)

- **Transitive crypto propagation:** the scanner's package inventory
  (manifests + lockfiles) now joins to the crypto-library catalog and
  propagates exposure up every lockfile parent chain.
  `crypto_dependency_paths` records each chain from a crypto-bearing
  package to the direct dependency that pulls it in; package nodes carry
  `crypto_bearing`/`crypto_algorithms`; the cascade summary counts
  direct/transitive crypto exposure and states which ecosystems actually
  carried parent edges (npm nested paths, cargo blocks — flat lockfiles
  invent no edges).
- **Azure Dedicated HSM scanner:** `AZURE_DEDICATED_HSM` findings
  (provisioning state, stamp code, network interfaces) via the optional
  `azure-mgmt-hardwaresecuritymodules` SDK — skipped, not fabricated,
  without it. AWS CloudHSM and Azure Managed HSM were already covered;
  GCP Cloud KMS keys with `protection_level: HSM` now carry an explicit
  `hsm_backed` marker.
- **Resource-level access grants (per-system):** `resource_grants` table
  (migration 0076; owner > operator > viewer) with
  restrictive-only-when-present semantics — unrestricted systems behave
  exactly as before; the first grant switches a system into enforcement.
  Read endpoints require viewer+, writes operator+; platform superadmin
  always passes, auditor passes reads. Admin-only grant management
  (`GET/POST /systems/{id}/grants`, `DELETE /systems/{id}/grants/{subject}`)
  with every restrict/revoke/unrestrict transition hash-chain audited.
- Rest-api.md regenerated for the three new grant endpoints.

### Added — round 17: the seven-report full read (audits 11–16 + CRYPTO_SCAN_DISCOVERY)

- **Evidence soft-delete that preserves the hash chain (audits 15/16
  EVIDENCE-003):** `evidence_records` gains tombstone columns
  (`deleted_at`/`deleted_by`/`delete_reason`, migration 0075).
  `POST /api/v1/findings/{evidence_id}/soft-delete` (auditor-gated,
  mandatory reason, hash-chained audit entry, 409 on double-delete) and
  `POST /api/v1/findings/{evidence_id}/restore` (409 unless retracted)
  manage the lifecycle. Consumption surfaces — findings listings, CBOM
  generation, conflict detection, drift comparison, remediation
  suggestions and task creation, intelligence/agility/work orders,
  retirement planning — exclude tombstones by default, while chain
  verification, exports and audit exports still read every row: a
  retraction stays in the chain it committed to, which is the point.
  `FindingResponse` carries additive `deleted_at`/`deleted_by`/
  `delete_reason` fields.
- **Encrypted evidence backups (audit 15):** `backup_evidence.py
  --encrypt` writes AES-256-GCM backups (scrypt KDF over
  `BACKUP_ENCRYPTION_KEY`, self-describing `CSBC1` salt+nonce header,
  `.enc` suffix, plaintext removed). The manifest keeps the plaintext
  SHA-256 plus `encrypted`/`kdf` fields; `restore_evidence.py` decrypts
  before the manifest check, fails closed on wrong key or tamper, and
  deletes the decrypted plaintext when the restore finishes. Shared
  implementation in `scripts/backup_crypto.py`.
- **QUIC / DTLS / WireGuard protocol analyzers (audit 13 §3.1, discovery
  P3-001):** `QuicAnalysis` (RFC 9001 TLS-1.3 AEAD suites, group lookup
  by wire name and codepoint), `DtlsAnalysis` (IANA suite registry across
  DTLS 1.0/1.2/1.3, PFS flag), and `WireGuardAnalysis` (fixed RFC 8437
  suite, `negotiable: False`, honest quantum-vulnerable verdict) in the
  protocol engine, wired into `UniversalCryptoEngine.scan` via
  `inputs["quic"|"dtls"|"wireguard"]` with the same PROTOCOL evidence the
  TLS/SSH/IPsec analyzers emit.
- **Property-based tests + coverage tooling (audit 11):** hypothesis is a
  pinned test dependency;
  `services/evidence/tests/unit/test_hashing_properties.py` holds the
  hashing core to seven properties (determinism, key-order insensitivity,
  runtime-field exclusion, verify-iff-untampered, link agreement, content
  → chain composition). `pytest-cov` + root `.coveragerc` +
  `scripts/coverage.sh` give opt-in per-service branch-coverage reports —
  the gate stays the suite result, never a percentage.
- **OpenAPI contract tests (audit 11/12):** duplicate operationIds fixed
  (two `list_container_scans` definitions whose distinct paths normalized
  to the same id) and `test_openapi_contract.py` now pins operationId
  uniqueness, versioned paths (with the six infra-probe allowlist) and
  tagged operations against the generated spec.

### Changed — round 17

- **CBOM portfolio generation (audit 14 TD-007):** `_located_assets()` is
  a single set-based JOIN instead of a per-system loop plus a second
  5000-row page; `_portfolio_dependencies()` loads the dependency edge
  list in one query. Estate CBOMs are bounded by `PORTFOLIO_MAX_ASSETS`
  (default 50,000) and truncation is explicit —
  `cryptoscan:truncated`/`cryptoscan:asset_limit`/`cryptoscan:assets_total`
  metadata properties and a logged warning, replacing the silent stop.
- **Drift/remediation reads filter retracted evidence:** worker drift
  comparison and remediation suggestion generation exclude soft-deleted
  evidence rows.

### Added — round 16: the ten-report full read (audits 03/04/05/06/10)

- **Policy rule overrides (audit 05):** `policy_rule_overrides` table
  (migration 0074, tenant-scoped, unique per rule) +
  `PUT /api/v1/policy/rules/{rule_id}/override` and `DELETE` (admin-only,
  audit-logged, severity validated) to disable a rule or change its severity
  for one tenant without editing the reviewed YAML pack.
  `GET /policy/rules` now reports pack state, override and effective state
  side by side, and the worker's policy stage applies the same rows via
  `policy.core.overrides` — the listing shows exactly what the engine
  enforces.
- **Scan-queue backpressure (audit 05, MAX_QUEUE_DEPTH):** the single
  admission decision refuses with 429 once QUEUED+RUNNING scan jobs exceed
  `MAX_QUEUE_DEPTH` (default 500; `<=0` disables). Counting is a documented
  admission seam; failure to count fails closed.
- **Optimistic scan-job locking (audit 04):** `scan_jobs.version` column
  (migration 0074) + compare-and-set `JobRepository.update_status` with a
  terminal-state guard — a stale worker completing a job the reaper already
  failed is a detected conflict, and the first verdict stands. The reaper
  distinguishes races it won from races it lost.
- **Drift → remediation auto-linking (audit 03):**
  `POST /drift/{id}/acknowledge` accepts `create_remediation_tasks` and
  auto-opens PROPOSED remediation tasks (≤10) for the FAIL/WARN evidence
  behind the drift; tasks carry `source="drift"` + `source_ref` (new
  columns, migration 0074) and are listed by
  `GET /drift/{id}/remediation-tasks`. Honest no-op when the drifted
  algorithm has no failing evidence.
- **Clone-URL transport validation (audit 10):** `GitClient.clone` refuses
  remote-helper transports (`ext::`, CVE-2022-24439), helper-by-name forms
  and leading dashes before git is even imported; normal URL/ssh/local
  targets unaffected.
- **Frontend accessibility (audit 06):** `Tabs` implements the ARIA tabs
  pattern (roles, aria-selected, roving tabindex, arrow/Home/End keys);
  `Table` clickable rows are keyboard-activatable and headers carry
  `scope="col"`.
- Audit reports 03–10 now carry round-16 UPDATE addenda (verified-stale
  claims + what was built); `audit_reports/00_ROUND_STATUS.md` updated.

### Added — the remaining code-buildable audit gaps (audits 50/54/69, TD-010)

- **Reintroduction detection:** retired-asset registry (`retired_assets`,
  migration 0073) + `POST /retirements`, `GET /retirements`,
  `POST /retirements/{id}/lift`, `POST /retirements/check/{scan_id}`. A
  retired algorithm reappearing in a scan is detected with severity routing
  (hardcoded key / policy FAIL → CRITICAL, WARN → HIGH, clean reappearance →
  MEDIUM) and one platform event per detection — a broken promise, not a
  "new finding". Scope-matched FILE/ASSET/ALGORITHM; malformed registry rows
  never match.
- **Observation conflict detection:** `GET /findings/conflicts` surfaces
  where observers of the same site disagree — algorithm, parameters, or
  compliance verdict — within a scan (scanner vs scanner) or between two
  scans (both sides stamped). Conflicts are reported, never auto-resolved.
- **Crypto-asset lifecycle state machine:** `crypto_assets.lifecycle_state`
  (migration 0073) with server-enforced transitions
  DISCOVERED → VERIFIED → ACTIVE → DEPRECATED → RETIRED via
  `POST /inventory/assets/{id}/lifecycle` (reason mandatory, event audited,
  RETIRED terminal — a comeback is a reintroduction, see above).
- **Evidence-chain integrity sweep:** `GET /ops/evidence/chain-status`
  recomputes recent scans' evidence chains with the export verifier and
  emits `evidence.chain_broken` on breakage.
- Audit reports now carry per-report UPDATE addenda plus
  `audit_reports/00_ROUND_STATUS.md` (per-report verdict table).



### Added — remediation verification loop (audit 62 / GAP-006)

- Tracked remediation tasks with evidence-based verification instead of a
  human "done" checkbox: `POST/GET /remediation/tasks`,
  `.../accept|complete|verify`, `GET /remediation/verifications`. Findings
  are snapshotted at creation; completion auto-verifies against rescan
  evidence with five deterministic verdicts (VERIFIED / PARTIAL / FAILED /
  REGRESSION / INCONCLUSIVE), each persisting the full machine-readable
  comparison and emitting platform events. Migration 0072.

### Fixed — hybrid PQC protocol detection (audits 52/59, GAP-014/015)

- TLS supported_groups now resolve to names — including RFC 10024 hybrid
  ML-KEM groups (0x11EB–0x11EF) and the pre-standard Kyber drafts
  (0x6399/0x639A) — instead of anonymous hex that classified as UNKNOWN.
- `sntrup761x25519` no longer masquerades as plain X25519: OpenSSH hybrid
  KEX maps to a hybrid identity and classifies PQC_RESISTANT (RESTRICTED —
  round-3 NTRU Prime, not FIPS 203); `mlkem768x25519` maps to
  X25519MLKEM768 (ALLOWED).
- IKEv2 DH group table corrected against the IANA registry: 27–30 are
  brainpool curves (were X25519/X448), 22–24 and 25/26 relabelled, 31/32
  are Curve25519/Curve448, and ML-KEM KE methods 35/36/37 added.
- Runtime TLS parser: hybrid codepoints named; reserved 0x00FF no longer
  masquerades as ffdhe8192 (which is 0x0104, RFC 7919).
- Shared registry: `kem-hybrid-pqc` family with explicit hybrid quantum
  verdict reason; Kyber-draft and sntrup761 hybrids RESTRICTED, RFC 10024
  hybrids ALLOWED.



### Fixed — route-auth audit: one open endpoint, one broken webhook, and a permanent gate

- **`GET /compliance/retention` answered anonymous readers.** The retention
  clock is derived from the caller-partitioned audit trail (round 11), so an
  unauthenticated caller learned org-specific facts. Now requires
  `get_current_user`; the auditor-key path for external auditors remains
  `/compliance/audit/retention`.
- **The Stripe billing webhook was dead in production.** Its signature is
  the only authentication it can have — Stripe never sends a session — but
  the session gate demanded one anyway, so every real billing callback
  401'd. `/api/v1/saas/billing/webhook` is now in the gate's exemption
  list (same pattern as the other webhooks); the route's HMAC check is the
  first gate it meets. Behavioral pin: an unsigned callback gets the
  route's 400, never the gate's 401.
- **A permanent route-auth inventory gate.** Authentication lives in four
  shapes in this codebase (route dependencies, router-level dependencies,
  aliased `require_permission(...)` factories, inline handler checks), and
  name-matching sees only the first. The new security test resolves every
  dependency tree by module-qualified name, recognizes inline checks, and
  fails by name if any non-exempt route ships without an authentication
  seam — exemptions are imported from the middleware's own list, one
  source of truth. All ~790 routes audited; everything else was already
  authenticated.

### Added — tenant_id connected end to end (browser → header → ORM → rows)

- **An organization switcher on the Tenancy page.** The header modal could
  switch orgs, but the tenancy page itself said "switch orgs by signing in
  with a member of the other organization". The page now has an inline
  "Switch organization" panel: one button per membership (from
  `GET /saas/memberships`, which derives the list from the membership
  table — never from the current header), a "Platform estate" option for
  platform admins, and nothing at all for single-organization users.
  Switching refreshes the page's live data and reconnects realtime
  consumers.
- **Ownership is visible in payloads.** `GET /technology-bom/cascade/watches`
  and `/cascade/runs` carry `tenant_id` on each row (NULL = platform
  estate) — the database column is connected to the surface the console
  reads.
- **The chain is pinned as one test on each side.** Backend:
  `test_tenant_e2e_flow.py` over the real stack (session cookies +
  TenantScopeMiddleware, one user in two orgs) — memberships directory →
  header → whoami → tenant-stamped write verified on the raw row → scoped
  list → cross-tenant invisibility → no-header 400 → stranger-header
  403/404. Frontend: `Tenancy.test.tsx` (5 vitest) — the picker renders
  from memberships, switching stores the org, and the next API call
  carries the switched header.
- New user guide `docs/user-guide/multi-tenancy.md` documents the whole
  chain and the per-surface isolation rules.
- Audit note: the enforcement chain (rounds 5-11) was already complete —
  `scripts/tenant_isolation_audit.py` passes (99 scoped tables) and every
  frontend call flows through `tenantFetch`. This round connected the
  last mile of UX and visibility.

### Fixed — /stream event bus and live-CBOM store were cross-tenant global stores

- **The event-stream bus is partitioned by tenant.** Raw observations,
  normalized events, attack detections and the audit trail lived in one
  process-global JSONL log set: any tenant's ingest was readable by every
  other tenant through `/stream/events`, `/attacks`, `/attacks/summary`
  and `/stream/stats`. An unscoped request (single-tenant install, platform
  operator) keeps the base directory — byte-for-byte the pre-tenancy
  paths — and a tenant-scoped request gets
  `<STREAM_LOG_DIR>/tenants/<tenant-id>/` with its own append-only logs and
  consumer cursors. Isolation is strict in both directions: each scope sees
  only its own partition (unlike DB rows, where tenants also see
  NULL-owned platform rows — stream partitions carry raw observations, and
  cross-visibility would put one customer's detections in another's
  console).
- **The live-CBOM version store is partitioned the same way** (`<CBOM_STORE_DIR>/tenants/<tenant-id>/`): two tenants using the same system id get two independent signed, hash-chained CBOM histories — no shared chains, no cross-tenant `/cbom/live|versions|diff|verify|stream` reads.
- **Compliance retention reads the caller's partition.** The
  `/compliance/retention` oldest-audit-record clock was computed over the
  global bus; one tenant's processing history no longer drives another
  tenant's WORM verdict.
- **The monitor daemon publishes into the target's partition.** A
  tenant-owned monitor's passes are that tenant's observations; unowned
  targets keep the platform bus.
- **The operator's `/ops/self-check` aggregates every partition** (platform
  + each tenant directory on disk) for bus lag and stale-CBOM alerting —
  the only cross-partition reader, operator-only, and it inventories
  directories rather than the tenant table.
- 5 new tenancy tests run the real stack (session cookies +
  TenantScopeMiddleware, two tenants and an unscoped operator) covering
  cross-tenant invisibility, same-system-id isolation, platform-partition
  invisibility, per-partition retention and the on-disk layout;
  `docs/architecture/event-stream.md` documents the partition contract.

### Fixed — BOM/cascade read models understated impact (P2)

- **Technology BOM fingerprints now see dependency edges.**
  `materialize_technology_bom` recorded only a `dependency_count`, so the
  content-addressed fingerprint was blind to edge-only changes: a re-wired
  estate with identical components kept the old snapshot version forever.
  The state now carries the canonicalized `[source, target, type]` edge
  list (both inventory dialects — pair lists and graph-snapshot dicts —
  normalize through the new `canonical_dependencies()`; duplicates
  collapse), and the fingerprint hashes it.
- **Snapshot diffs name changed fields, not just appearance/disappearance.**
  A component whose `bom-ref` survived but whose fields moved (an RSA key
  grown 2048→4096, a version bump) was invisible to
  `diff_technology_bom`. Per-layer `changed` entries now carry exact
  field-level from/to values, and a `dependencies` section reports
  added/removed edges — surfaced through both `POST /technology-bom/snapshot`
  and `GET /technology-bom/compare`.
- **Every cascade kind reports canonical system IDs.** The vendor cascade
  filled `layers.system.systems` with system *names* while every other kind
  reported registry IDs, so vendor answers could not be joined back to
  systems. It now reports IDs like every other path.
- **Secondary systems sharing evidence stay in the blast radius.** The
  algorithm cascade deduped evidence rows by id *before* collecting owning
  systems; the digital twin emits one row per (record, system) pair, so
  when one evidence record was reachable through assets of two systems the
  second system silently vanished. Systems are now collected from every
  matching row; the evidence id itself still appears exactly once.
- **Point-in-time replay provenance is persisted.** `replayed_over` was
  stamped on the cascade result *after* the run row was committed, so the
  audit trail lost which twin snapshot an answer replayed (only the HTTP
  response carried it — and same-session dict identity masked the loss).
  It is now stamped before persistence, and `/cascade/runs` list entries
  carry `replayed_over` too.
- **A disappeared watch target no longer crashes run-due.** The second
  `POST /cascade/watches/run-due` after a watched target left the estate
  raised `KeyError: affected_systems` (the NOT_FOUND result shape carries
  a count but no system list). The diff now tolerates that shape on both
  sides, the entry carries an explicit `target_missing: true`, the
  disappearance is persisted as its own run, the collapsed blast radius is
  diffed once, and the watch stays active until an operator retires it.

### Fixed — adversarial tenant-isolation review: two critical cross-tenant holes closed

- **The graph plane no longer serves a tenant the global Neo4j store.**
  `resolve_graph()` preferred the process-global `Neo4jGraphStore` whenever
  Bolt answered a health ping, so every tenant-scoped `/graph*` route (blast
  radius, impact, compliance, vendor chains, hotspots) read **every
  tenant's** systems and assets, and a scoped sync wrote tenant inventory
  into the shared store while returning global `counts()` as a volume
  oracle. While a tenant scope is active the graph is now served from the
  tenant-filtered payload on the in-process engine
  (`backend="memory-tenant-isolated"`) and the driver is never touched — not
  even for a health probe; Neo4j sync/populate under a scope is suppressed.
  Unscoped (platform, single-tenant) behaviour is unchanged.
- **Raw SQL and pure-Core statements fail closed inside a tenant scope.**
  `text()` queries and statements assembled only from `Table.c` columns
  carry no ORM mapper, so neither `with_loader_criteria` (SELECT) nor the
  DML predicate branch reached them — verified cross-tenant read *and*
  write under an active scope. The guard now inspects every non-ORM
  statement executed through a Session and raises `TenantScopeViolation`
  when its compiled SQL touches a tenant-scoped table (subqueries and
  aliases included). Platform tables (`users`, `tenants`, `monitor_leases`,
  ...) are unaffected, and `platform_scope()` remains the greppable
  opt-out.
- **ORM bulk INSERTs are tenant-stamped.** `session.execute(insert(Model)
  .values(rows))` bypasses `before_flush`, so the PostgreSQL bulk-evidence
  path landed unstamped rows as platform estate — readable by every tenant.
  An omitted `tenant_id` is now stamped from the active scope and a foreign
  claim is rejected; `BulkInserter` stamps evidence rows from their parent
  scan explicitly.
- **ORM statements can no longer embed unfiltered Core subqueries.** A
  scalar subquery, `in_()`, `exists()` or `select_from(Table)` built from
  `Table.c` inside an otherwise ORM-shaped statement escaped
  `with_loader_criteria` (a per-row cross-tenant read and a boolean
  oracle). Each select level is now analysed independently and raises on
  scoped-table references the filter cannot reach; legitimate shapes —
  `select(Model)`, the repositories' `select(func.count()).select_from(Model)`
  pagination count, ORM joins and embedded ORM subqueries — are unaffected.
- **54 new adversarial tests + a permanent audit.**
  `services/database/tests/adversarial/` (31),
  `services/graph_engine/tests/test_tenant_isolation.py` (10, recording
  fake driver: scoped = zero Bolt statements) and
  `services/api/tests/security/test_cross_tenant_adversarial.py` (13, over
  HTTP: graph routes, scan-transfer ownership, 404-absence, SSE predicate).
  `scripts/tenant_isolation_audit.py`, wired into `scripts/engineering_gate.py`,
  requires every model to be `TenantScoped` or carry an in-source
  `# platform-scope: <reason>` marker, flags `session.get()` on scoped
  models and `text()` naming scoped tables in request/worker code, and
  inventories every `platform_scope()` site. Full report:
  `docs/security/adversarial-tenant-isolation.md`.

### Fixed — the worker ran every scan unscoped (cross-tenant disclosure)

- **The tenant now survives the queue.** `worker.core.job_consumer.ScanJob`
  had no `tenant_id` field, so the owner was dropped at the queue boundary,
  and `JobExecutor` entered no scope — every worker-executed scan wrote with
  `tenant_id = NULL`. That is not an absent label: `db.tenancy` defines NULL
  as the platform estate, readable by every tenant, so each customer's scan
  findings landed where their neighbours could see them. The work succeeded
  silently, because outside a scope the ORM guard is inert and
  `stamp_tenant` is a no-op.

  `tenant_id` is now carried on the descriptor, serialised and deserialised,
  captured into the payload by `trigger.py` while the request scope is still
  open (the publish is a background task that runs after it is gone), and
  re-entered by `JobExecutor.execute` around the *whole* dispatch — binary,
  org and cloud jobs write the same tenant-owned rows. The inline no-queue
  path is scoped identically. Payloads without the field still deserialize
  to `None`, so in-flight jobs keep their old behaviour instead of failing
  to parse.

  Found by writing the cross-tenant battery below; `monitor/network_sweep.py`
  had been scoping correctly all along, which is what made the omission
  visible. Third leak in three layers of the same control.

### Added — cross-tenant test battery and the control register

- **30 tests** across the seven categories `fix.md` item 9 lists that were
  uncovered: cross-tenant writes, resolution rules (ambiguous header,
  suspended tenant, API-key binding, known-ID non-oracle) and worker scope.
  Two record real gaps rather than asserting absent protections: Core bulk
  `update()`/`delete()` is not filtered by `with_loader_criteria`, and a
  companion test proves no repository uses that pattern today.
- **Control register** (`config/control-register.yaml` +
  `scripts/control_register.py`): every procurement control classified by the
  tier of evidence it can actually produce — repository control, operational
  record, customer attestation, external certification — with a gate that
  refuses a claim outranking its evidence and forbids the top two tiers from
  resting on repository paths. Currently zero controls at external
  certification.

### Fixed — tenant scope failed open (cross-tenant disclosure)

- **`TenantScopeMiddleware` now fails closed.** `resolve_tenant_for_request`
  caught every exception and returned `None`, and the middleware caught again.
  `None` means "no scope", and outside a scope the `db.tenancy` ORM guard is
  inert — so the request read **every tenant's rows**. Two reachable paths on
  the ~85 routers that do not depend on `get_tenant_context` (the routers this
  middleware exists to cover):
  - a member sending another tenant's `X-Tenant-ID` → 404 → swallowed → full
    estate read;
  - a member of two tenants sending **no** header → 400 → swallowed → full
    estate read. No forged header needed.

  Refusals now raise `TenantResolutionRefused`, carrying the status the route's
  own dependency would have returned; the middleware answers with it instead of
  running unscoped. `None` is reserved for principals who legitimately have no
  tenant (unauthenticated, platform operator, legacy single-tenant). Both
  docstrings asserted the opposite behaviour and have been corrected, and
  `docs/architecture/multi-tenancy.md` now documents the ORM-guard and
  middleware layers it previously omitted.
- **First tests for that middleware.** It is not installed under
  `ENVIRONMENT=test` (`api.main`), so it had no coverage at all. Added
  `services/api/tests/unit/test_tenant_scope_middleware.py` — 8 tests driving
  the ASGI middleware directly, asserting the downstream app is not reached for
  each refusal status, plus the happy path and the skip paths.

### Fixed — test collection and repository hygiene

- **`pytest` from the repo root collects cleanly again** (5,770 tests, 0
  errors). `python_files` is now `test_*.py`: the default pattern also matches
  `*_test.py`, which collected `scripts/load_test.py` — a CLI capacity probe
  with no test functions — whose `from _bootstrap import bootstrap` then failed
  because `scripts/` is not on `sys.path`. No test module uses the `*_test.py`
  spelling, so nothing is deselected. CI names its test directories explicitly
  and never saw this.
- Registered the `integration` marker used by
  `services/worker/tests/integration/`.
- **Untracked 5,189 junk files.** `_tmp/snbchk/` held 247 levels of recursive
  `ws/repo/ws/repo/…` nesting (21 byte-identical files per level) from a single
  sandbox commit. `_tmp/` was already in `.gitignore`, which does not untrack;
  `git rm -r --cached _tmp` drops tracked files 8,113 → 2,924 with the working
  copy untouched.

### Production burn: live deployment smoke, Stripe billing, DR drill, security campaign
- **Deployment burn** (`scripts/deploy_burn.py` + `docs/deploy-burn.md`):
  boots the real API and walks the live OpenAPI surface — 360 safe
  operations exercised with real sessions, **zero 5xx**. Found and fixed a
  real latent bug day one: `/healthz/schema` 500 on every call (import of a
  nonexistent `engine` symbol — now `get_engine()` like its siblings).
- **Stripe billing** (`services/billing`, `/saas/billing/*`): checkout
  sessions against the real Stripe API (form-encoded, Idempotency-Key,
  price IDs from env — never invented amounts), webhook ingestion with
  Stripe's documented `t=…,v1=…` HMAC scheme (constant-time, replay
  window), subscription state in the platform settings store, honest 503
  `billing_not_configured` without keys. 5 tests incl. signature round-trip
  and request-shape pinning via mocked transport (product code always calls
  the real endpoint when configured).
- **Infra burn-in** (`docs/burn-in.md`): GitHub signed-webhook round trip
  PASS (job COMPLETED through the live API — full pipeline: scan → 14
  findings → policy → quantum HNDL alert → CBOM), SMTP delivery PASS (real
  wire conversation via built-in sink), live TLS probe PASS
  (github.com:443, TLS 1.3 parsed). Cloud/Neo4j/container honestly SKIP
  (no creds/JVM/Docker in this environment).
- **Load/soak** (`docs/load-soak.md`): 68,390 requests / 90 s / 12 sessions,
  **0 errors**, p99 133 ms served; the 600/min/identity burst limiter was
  the ceiling and shed the rest correctly. Harness hardened for the
  platform's own defenses (login budget respected, per-user sessions).
- **Backup/restore drill** (`scripts/backup_drill.py` +
  `docs/backup-drill.md`): hot online backup of the durable trio (SQLite
  estate + bus logs + signed CBOM store) → restore into a clean dir →
  second instance boots from backup alone → 12/12 checks PASS (estate
  survives, CBOM chain verifies from genesis, bus replays, logins work).
- **Security campaign** (`services/api/tests/security/` +
  `docs/security-campaign.md`): 7 adversarial probes all green — anonymous
  sweep (no leaks), cross-tenant absence (no existence oracle), injection
  sweep (no 5xx, store survives DROP TABLE), webhook signature enforcement
  (GitHub + Stripe), production boot gate fails closed, brute-force limiter
  429 on attempt #6, logout invalidation.

### Performance benchmark + parser fuzz hardening
- **A15 closed**: `scripts/perf_benchmark.py` runs the real static scanner
  over a deterministic 10,000-file corpus (py/java/js/config/PEM with
  realistic crypto API shapes) and publishes measured numbers to
  `docs/performance.md` — ~2,300 files/s end-to-end, 16,050 findings, zero
  parse errors on 2 sandbox CPUs; reproducible, honestly scoped to the
  environment.
- **Parser robustness fuzzing** (roadmap G): seeded fuzz suite
  (`telecom_scanner/tests/test_fuzz.py`) throws random/structured-corrupt/
  truncated bytes at the Diameter/GTP-C/SIP parsers and arbitrary dicts at
  the stream normalizer — no raise, always serializable. Day one it caught
  and this round fixes 4 real bugs: an out-of-bounds read in the Diameter
  AVP walk (short AVP header), raw-junk `kind` echo poisoning the canonical
  schema (now pinned to `unknown` with `reported_kind` kept), typed loaders
  crashing on non-dict `crypto`/`summary` fields, and bytes leaking into
  HMAC-signed canonical JSON (now coerced to visible `bytes:n:hex` form).
  `normalize()` now guarantees a serializable output contract on every path.

### Prioritization work queue + JWS-conformant exports
- **Remediation prioritization** (gap A8): `GET /api/v1/priority` + the
  `/priorities` page — every OPEN drift event and weak runtime finding folded
  through the deterministic correlation engine and ranked by
  revenue × severity × agility with effort bars, replacement rules, migration
  plans and BFS blast radius from the system dependency graph. Revenue tiers
  come from linked business processes (`revenue_daily`/`customer_count`
  bands), agility from the 6-factor system scores, neutral defaults
  otherwise — nothing invented, empty estate ranks empty.
- **RFC 7515 JWS on export manifests** (gap A2): `export_bom` now emits
  `signature_jws` (compact JWS, HS256 by default, RS256/ES256 available)
  over the same canonical bytes as the content hash; legacy raw-HMAC hex
  retained for older verifiers. CBOM documents already sign via
  `cbom.signing.jws_signer`.
- `docs/roadmap.md`: the full master update list (A–J) mapped to shipped /
  blocked / planned status with pointers.
- Tests: prioritization engine (bands, clamps, ranking determinism, counts),
  API ranking over seeded real tables (incl. resolved-event exclusion,
  revenue/agility weighting, blast radius, honest empty estate), JWS export
  coverage (payload-claim equality, tamper rejection, byte formats).

### Event stream, Live CBOM, deterministic correlation, telecom passive collection
- **Message bus** (`services/eventstream`): 8 fixed topics (raw-events,
  normalized-events, policy-results, attack-detections, cbom-updates,
  graph-sync, audit-log, alerts) on append-only JSONL logs. Envelopes carry
  canonical-JSON payload hashes + HMAC-SHA256 signatures (constant-time
  verify); consumer groups with cursors + lag stats; replay from any offset;
  torn-tail tolerant, tampered lines are detected and never delivered.
- **Stream processor**: normalize → dedup → policy → attack-detect → fan-out,
  fully deterministic and stateful. Canonical CBOM schema across TLS findings,
  monitor passes, telecom NFs/certs; unmapped kinds are honestly flagged.
  Identity dedup (kind/system/endpoint/proto/fingerprint/algorithm) merges
  re-observations into one asset with a seen_count. The audit topic carries a
  SHA-256 evidence chain (prev hash + input hash + dedup key + policy fails +
  rules) — every verdict is reproducible.
- **Real-time attack detection** — 13 deterministic rules with pinned
  severities replace batch drift: crypto/algorithm downgrade (ALERT/CRITICAL),
  key-size reduction (ALERT), MITM pin mismatch (CRITICAL), unexpected CA
  (HIGH), cross-system key reuse (HIGH), weak entropy (MEDIUM), protocol
  violations (ALERT), 3σ rate anomalies (MEDIUM), new endpoints (MEDIUM),
  near-expiry (MEDIUM) and revoked-in-use certs (CRITICAL), KMS/HSM policy
  changes (HIGH). Baselines learn from clean traffic only and never
  auto-overwrite; `AttackState` snapshots make the detector replayable.
- **Live CBOM service**: per-system versioned CBOMs — compact JWS (HS256)
  signed docs, SHA-256 hash chain back to genesis, deterministic diffs
  (added/removed/changed), freshness window (default 1h), full-chain
  re-verification that reports the exact version where a signature or hash
  breaks. APIs: `/cbom/live/{system}`, `/cbom/versions/...`, `/cbom/diff`,
  `/cbom/verify/{system}`, and SSE push on `/cbom/stream/{system}`.
- **Telecom passive collection**: offline parsers for Diameter (RFC 6733
  commands/AVPs), GTP-C v2 (TS 29.274 header/TEID/IEs) and SIP/IMS
  Security-Server/Verify (ipsec-3gpp + TLS mechanisms, TS 33.203) — captured
  or replayed wire bytes join the same pipeline as active scans.
- **Deterministic correlation engine** (`services/correlation`): replaces any
  AI — priority = revenue × severity × agility, effort formula, replacement
  rule table (3DES→AES-256-GCM, RSA-2048→ML-KEM-768 hybrid / ML-DSA-65, …),
  template explanations, phase-plan templates (banking/telecom/default) and
  cycle-safe BFS blast-radius over the asset graph. Same input ⇒ identical
  report.
- **Surface**: `POST /stream/ingest` (external collectors; returns the
  pipeline verdict + detections for that payload), `GET /stream/stats`,
  `GET /stream/events?topic=`, `GET /attacks` + `/attacks/summary`; the
  monitor daemon now publishes every pass to the bus. Compose: stream/CBOM
  dirs ride the telecom volume, `CBOM_SIGNING_SECRET` required in prod.
- Docs: `docs/architecture/event-stream.md`; product inventory and
  completeness tracker: `docs/product-completeness.md`.

### SaaS round 2: invitations, full-surface metering, network-scan SSRF fix
- Invitations: `POST /saas/invites` (one-time `csi_` token, hash-stored,
  7-30 day expiry), `POST /saas/invites/accept` (new identities set their
  own password; existing identities must accept from a session signed in
  as the invited username — a leaked token can never take over a live
  account), pending-invite listing/revocation, seat quota enforced at
  accept. Dashboard: Pending invites panel + `/invite` accept page.
- Metering now covers EVERY scan writer: daemon passes, monitor scan-now,
  manual `POST /network-scans` (one scan_run unit per host) and
  `POST /scans/{id}/retry` — plan monthly limits are honest across the
  whole product, not just the monitor.
- Security fix (round-28 review): `POST /network-scans` ran the live TLS
  scanner on unvalidated hosts — the same OWASP A10 class as the round-26
  monitor finding. Host lists now pass `target_validation` (metadata/
  loopback/URL targets 422; regression-tested with a mocked scanner that
  provably never probes refused hosts).

### Multi-tenant SaaS: organizations, isolation, plans, metering
- Tenancy core: `tenants` / `tenant_memberships` / `tenant_usage_events` /
  `tenant_provision_events` tables; `POST /saas/signup` self-serve org
  provisioning (slug-unique, password-policy enforced); tenant roles
  (owner/admin/member/viewer) independent of platform RBAC.
- Isolation enforced in depth: `tenant_id` on monitor targets and API keys
  (schema reconciliation migrates existing stores; NULL = platform estate),
  repository filters, `TenantContext` request resolution (per-request DB
  lookup; header or sole-membership selection; foreign tenant = 404, no
  existence oracle), suspension = 423 with the daemon skipping suspended
  tenants' passes.
- Plans with honest quotas (FREE 5 targets / 200 scans-mo / 3 seats, PRO
  100 / 20k / 25, ENTERPRISE unlimited): breaches are 402 quota_exceeded;
  append-only usage metering (month SUM, delete-proof) powers
  `GET /saas/usage` and the dashboard Tenancy page (org, meter bars,
  members, platform tenant registry with suspend/restore/plan).
- Platform admin surface: tenant registry with live counts, suspend /
  restore / plan change — all audited.

### Security round: monitor targets can no longer be turned into internal probes (OWASP A10)
- Found by live attack testing against the running stack: an authenticated
  `POST /api/v1/monitor/targets` accepted NETWORK configs with loopback,
  cloud-metadata (`169.254.169.254`) and URL-scheme endpoints — the daemon
  would have probed them on every tick, making a monitor target an SSRF
  primitive against the host network and cloud metadata services.
- Fix (two layers): `_validate_config` now routes every NETWORK endpoint /
  scope through the platform's SSRF choke point (`api.security.
  target_validation`) — refused at create AND at update (422 with the reason);
  and the monitor's network runner re-checks at execution time (defense in
  depth for configs that predate the gate) — blocked targets are never probed
  and surface as named `SSRF_BLOCKED:*` issues. Legit public and RFC1918
  targets, and wildcard-domain discovery scopes, are unchanged (verified
  live and by tests).
- Regression tests pin the behavior: metadata IP/URL, IPv6 metadata
  (`fd00:ec2::254`), loopback, userinfo and metadata-CIDR scopes all 422;
  a public endpoint still 201s; editing a legit target into a probe is 422;
  the runner probe list provably contains only the public endpoint.

### PQC adoption journey: drift detection becomes a trend answer
- New pure engine `telecom_scanner.journey`: every pass folds into per-NF
  readiness **eras** (consecutive same-verdict passes coalesce — a passes
  counter, no era spam; a readiness flip opens a new era), with
  transitions and adoption % over tracked NFs only. Honest empties:
  nothing probed reports `nf_tracked: 0`, `adoption_pct: null` — never a
  fabricated percent.
- `GET /telecom/journey` serves the trend; `GET /telecom/roaming` joins
  each partner row with its protecting SEPP's journey (ready / since /
  flips / passes). History is file-backed (`telecom_journey.json` beside
  the snapshot, mtime-aware loader) and written by ALL writers — API
  scans, operator ingest, and monitor-daemon TELECOM passes (atomic
  replace, never fails the scan).
- Telecom page: "PQC adoption journey" panel — adoption %, ready/tracked,
  transitions, and the per-NF era table; refreshes on drift events.
- Tests: pure engine (coalescing, flips, adoption math, pqc_kex fallback),
  API accumulation/coalescing/flip + restart persistence, runner mirror.

### Telecom guardrails: the curated 3GPP/NIST defaults, installable in one call
- `POST /automation/telecom-guardrails` (admin-gated, idempotent upsert)
  installs three vetted operator rules through the SAME store, validation
  and governance gates as hand-authored rules:
  `guardrail-roaming-pqc-drop` (a roaming edge losing hybrid PQC -> PQC
  migration queue + ticket + alert, CRITICAL), `guardrail-mission-nf-down`
  (5GC/EPC/IMS NF dark -> ticket + alert, HIGH; roaming-plane down stays
  with the default playbook), `guardrail-sepp-cert-expiry` (ticket ahead of
  a roaming-link cert expiring, MEDIUM; rotation stays behind the gated
  approval). Fail-closed: every preset validates BEFORE anything is
  written; re-running updates in place, never duplicates.
- Presets are pure (`telecom_scanner.automation.telecom_guardrail_rules`)
  and pinned against the rules-engine vocabulary and condition semantics
  (roaming vs 5gc vs SEPP matching proven, not asserted).
- Automation page: one-click "install telecom guardrails" with an
  idempotency hint; API reference regenerated (585 paths / 644 ops).
- Live-verified: install (3 created, then 0/3 on re-install) -> real AMF
  outage -> daemon pass -> the run cites `guardrail-mission-nf-down` in
  matched_rules with create_ticket + create_alert (pre-guardrail runs show
  matched: [] — the before/after is visible in the runs table).

### PQC regression wakes automation; drift → ticket loop closed live
- `TELECOM_PQC_DROPPED` now maps onto the EXISTING
  `quantum_vulnerable_detected` trigger — a roaming link that LOST hybrid
  PQC is quantum-vulnerable again and reuses the `pb_pqc` playbook
  (rescan, CBOM refresh, migration queue, ticket, alert, gated approval).
  No new action vocabulary; `TELECOM_PQC_READY` stays noise.
- The snapshot tailer's bus payload now carries `plane` + `endpoint`
  (extracted into the pure `_telecom_event_payload`), so operator rules can
  target `plane == "roaming"` on daemon-originated drift too.
- Telecom page: live drift indicator — connection state plus the latest
  `telecom.event` (kind + NF + time) rendered from the SSE stream, above
  the event feed.
- Live-verified end-to-end (real outage): AMF TLS listener recovered then
  killed again — the daemon wrote both passes, SSE streamed
  `TELECOM_RECOVERED` and `TELECOM_REACHABILITY_LOST`, and the automation
  bridge persisted runs (`agent_offline`, `drift_detected`,
  `certificate_expiring` — all `triggered_by: event-bus:telecom-scanner`)
  with tickets requested on the bus. Cross-process freshness re-proven.

### Telecom drift streams; Docker wiring for the realtime loop
- Verdict changes now STREAM: a new snapshot tailer federates telecom drift
  events written by OTHER processes (monitor-daemon TELECOM passes, CLI
  runs) onto the SSE bus as `telecom.event` — a daemon pass streams exactly
  like an API scan. One event, one delivery: the API's direct publisher
  registers a shared `telecom:`-prefixed key per event and the tailer skips
  those; the tailer's first read after boot seeds history without
  publishing (a restart never floods the bus).
- PQC readiness drift is now an event: `TELECOM_PQC_READY` (info) /
  `TELECOM_PQC_DROPPED` (high). The pqc.hybrid_kem finding is info-severity
  and excluded from the fingerprint — without the explicit transition a
  roaming link gaining/losing hybrid ML-KEM was event-silent. `classify`
  rows now carry `pqc_ready` (single source: `bool(pqc_kex)`); the API
  scan/ingest and the monitor mirror persist it in the drift state.
- Docker updated for the realtime loop: `api` + `monitor` services share a
  `telecom_data` volume (snapshots) and the operator-mounted
  `telecom_registry.json` — daemon passes appear in the API and on SSE
  with no restart; an absent registry file = honest BLOCKED. The PoC stack
  gains an opt-in `monitor` service (`--profile continuous`) on the same
  `poc_data` volume; the two-container PoC footprint is unchanged by
  default. Docs: live-monitoring.md, telecom runbook, PoC CHECKLIST.
- Tests: PQC transition directions/first-pass quiet/fingerprint-identity
  pin, tailer seed/publish/dedup-key contract (cross-module key agreement
  with the direct publisher), runner state carries `pqc_ready`.

### Continuous telecom monitoring: TELECOM joins the monitor loop
- New monitor target type `TELECOM` (default 15-min interval): the 24/7
  daemon re-probes the registered 3GPP NF estate through the SAME engine as
  `POST /telecom/scan` — classify verdicts, honest BLOCKED (with the fix)
  when no estate is registered, issues derived from real severities
  (critical/high NFs -> SCAN_DEGRADED + ALERT on new issues). Optional
  scope: `carrier`, `nf_ids`, `timeout`.
- Each pass mirrors the snapshot the API serves (same file, same shape),
  and `/telecom/posture` + the roaming view + the exit report now pick up
  daemon-written passes LIVE (the API loader re-reads on file mtime — no
  restart). Monitor events flow to SSE via the existing event tailer.
- `VALID_TYPES` in the monitor router now imports `TARGET_TYPES` from the
  model — one source of truth for target types.
- Shortening a target's interval now takes effect immediately
  (`next_scan_at` pulls in to `last_scan_at + new_interval`; lengthening
  never accelerates an already-scheduled run).
- Live-verified on real endpoints: daemon pass against a lab AMF running a
  REAL TLS server (TLS_OK with self-signed-cert findings) + a dead SEPP
  (UNREACHABLE/critical); `/telecom/posture` showed each daemon pass
  without an API restart; exit report picked up the daemon-written estate
  (2 targets, 1 critical).
- Tests: runner classification/filter/mirror/blocked paths (4) + API
  target-type acceptance (1); telecom engines, monitor API and
  audit-pack/exit-report suites re-verified against the mtime loader.

### De-mock: the simulated benchmark runner is gone; first boot is empty
- Removed `POST /control/benchmark/run` — the "detector profile" runner that
  fabricated predictions from `detect_rate`/`false_alarm_rate` RNG knobs.
  Accuracy numbers can now come only from the REAL detector
  (`POST /control/benchmark/run-real`, the shipping universal-crypto engine
  over labelled ground truth) or from real external predictions
  (`POST /control/benchmark/score`). The runs listing and scoring endpoints
  are unchanged; a unit test now pins the simulated path as 404 and re-pins
  `run-real` scoring real detection.
- `scripts/run_stack.sh` no longer seeds anything: a fresh boot is EMPTY —
  inventory exists only after real scans run. Deleted
  `scripts/seed_demo.py` (bundled `local://demo/vulnerable-app` sample scan)
  and `scripts/seed_test_data.sh`. Kept the operator-configuration seeders
  (network targets from YAML config, compliance rule pack, business
  owners/processes) — those load operator config, not fabricated findings.
- Live realtime verified end-to-end (no mocks): SSE `GET /events/stream`
  carries real events (`monitor.scan_degraded`, `monitor.alert`,
  `telecom.event`, `alert.raised`, `ticket.requested` from the automation
  bridge) with Last-Event-ID resume; `scripts/run_monitor.py` daemon holds
  the leader lease and re-scans real NETWORK targets (github.com:443,
  api.github.com:443 probed OK, one genuine CERT_EXPIRING finding) on their
  intervals; the dashboard dev server proxies /api to the control plane —
  the browser path sees the same live data.

### Engagement archive + Go/Rust parser hardening
- `GET /audit-export/engagement-archive` — the FINAL deliverable in one ZIP:
  the examiner audit pack, the exit report in both renderings (ONE report —
  JSON and markdown share the same SHA-256), and a top-level manifest whose
  hashes cover every file (any sha256sum -c-style check verifies it).
  Reports page gained the archive download button.
- Scanner: fixed two real rust_parser gaps found by probing —
  `openssl::sha::{sha1,md5,sha256}` were invisible (only the standalone
  crates were matched), and the ring digest rule labeled SHA-1/SHA-512
  usage as "SHA-256" (now per-algorithm rules); `Rsa::generate(bits)` now
  extracts the key size. Go parser verified strong (weak primitives, TLS
  floor, rsa key size) and pinned.
- New tests: Go/Rust parser contracts (5) incl. regression pins for the
  fixed gaps; engagement-archive bundling test (nested pack opens,
  manifest hashes verify, both renderings agree). Matrix corrected: six
  first-class languages, not four.

### PoC exit-report generator: pack -> engagement deliverable
- New pure engine `reporting.exit_report`: scores the collected estate
  against the fab-poc.md success criteria — per-estate coverage
  (collected vs verbatim skips; no data renders as NOT MEASURABLE,
  never a faked 100%), SC-1 threshold 90% evaluated from computed
  coverage, SC-4 client acceptance stays unmet until a human name is
  supplied (never inferred). Deterministic: identical estate + scope
  produce an identical SHA-256 `report_hash` (canonical JSON excl. the
  hash), independently re-verifiable via `verify_exit_report()`.
  Markdown renderer for the client-facing document.
- `GET /audit-export/exit-report` (auditor-gated, json|md): assembles
  the estate from the same queries as the audit pack (payment keys,
  certificates, cloud KMS, ACM, code findings, Shor-exposed families,
  telecom snapshot) — the telecom block appears with honest zeros for
  registered-but-empty passes and stays absent when never scanned.
- Reports page: "PoC exit report" panel — client/window/owner/
  accepted-by inputs, hash-only generation or markdown download, hash
  shown on screen.
- Tests: engine determinism/tamper-detection/coverage-threshold/
  acceptance semantics (6) + endpoint json/md/hash pinning (1).

### Vendor PQC refresh: hardware registry reflects shipping reality (2026-09)
- `shared_models.hardware_registry` updated against vendor releases and
  CAVP/CMVP listings: Thales Luna HSM (fw 7.9 — ML-KEM/ML-DSA in core
  firmware, T-Series CNSA 2.0 under FIPS 140-3 L3 cert 5450), Entrust
  nShield (fw 13.8.0 — CAVP-validated ML-KEM/ML-DSA/SLH-DSA), Utimaco
  SecurityServer (Se Gen2 fw 5.5 — validated ML-DSA-65 module), AWS
  CloudHSM (managed firmware; KMS internal HSM CMVP-validated for
  ML-DSA-65), IBM Cloud HSM, Google Cloud HSM and Azure Dedicated HSM
  (user-managed Luna 7 — PQC requires the tenant's own fw upgrade) are
  now `quantum_resistant=True`. Thales payShield stays False with an
  explicit "announced, not yet shipping" note — roadmap never flips a
  flag. 10 of 60 devices quantum-resistant (7 keystore HSMs + 2 IBM Z
  entries + ARM CCA).
- `GET /hardware/catalog` now reports `quantum_resistant_count`; the
  Vendor page (already rendering per-device/per-vendor PQC) picks the
  refresh up with zero frontend changes.
- New pinned tests: shipping-support facts frozen by firmware number
  (`test_hardware_registry_vendors.py`), catalog count + honest
  roadmap-≠-shipped assertions in the hardware API suite (350 green).

### Sales enablement: security-questionnaire answer pack + demo script
- `docs/security-questionnaire.md` — SIG-lite answers grounded in named code
  artifacts: on-prem/no-egress deployment (telemetry heartbeat is in-process
  event-bus stats, verified), data flows (metadata only, never key material),
  encryption (PBKDF2-SHA256 @210k, SHA-256-hashed API keys, Fernet-encrypted
  backups, honest "DB at rest is deployment-owned"), identity (TOTP MFA,
  OIDC+PKCE/SAML/LDAP/SCIM, fail-closed 9-role RBAC), tamper-detecting audit
  chain, test gates — and a published known-gaps section.
- `docs/proposals/fab-demo-script.md` — the 45-minute meeting plan: six acts
  from sign-in to the live sha256sum pack verification, with the honest
  failure moments staged deliberately (a real provider error shown, then
  fixed) and four true objection one-liners.

### PoC delivery bundle: whole-estate audit pack + on-prem bring-up kit
- The examiner-ready audit-export pack now covers EVERY estate the platform
  produces: `cloud/kms-inventory.json` (AWS/Azure/GCP keys),
  `cloud/acm-certificates.json`, `code/findings-summary.json` (by language,
  by algorithm, hardcoded-key count), and `telecom/posture.json` (rollup +
  verdict rows) — each with an honest `NO_*.txt` note when empty. Manifest
  totals gained cloud_kms_assets, cloud_acm_certificates,
  code_finding_assets and telecom_targets. The SHA-256 manifest covers the
  new files like every other.
- `deploy/poc/`: two-container on-prem PoC stack (API + dashboard, SQLite in
  a named volume so nothing leaves the tenancy), `poc.env.example`, and
  `CHECKLIST.md` — a day-by-day operator plan (scope sheet, read-only cloud
  roles, bring-up, network/cloud/code/telecom passes, exit report, `down -v`
  data destruction) mapped to the success criteria in docs/proposals/
  fab-poc.md.
- docs/enterprise-readiness.md: the code-scanning row corrected to reality
  (Python/Java/C#/JS detectors incl. hardcoded keys + PEM material run by
  the worker pipeline) and the PoC proposal references the bundle.

### Enterprise breadth: GCP/ACM collectors, OIDC PKCE, Jira/Sentinel delivery
- Cloud collectors extended on the same adapter pattern: **GCP Cloud KMS**
  (symmetric/HMAC/RSA-PSS+PKCS1+OAEP/EC algorithm table, honest skips,
  limit+1 truncation so "more keys exist" is known, not guessed) and
  **AWS ACM certificates** (list->describe->PEM; the stored fingerprint is
  the REAL SHA-256 of the certificate DER — pending-validation certs are
  skipped with their reason). ACM rows land in the shared certificates
  table (fingerprint-unique), so renewal workflow and expiry surfaces
  apply to cloud-issued certs too.
- OIDC **PKCE S256** (RFC 7636): automatic for public clients (no client
  secret configured). The verifier rides a callback-path-scoped HttpOnly
  cookie — never the front-channel state, which the IdP and browser can
  see — and the callback fails closed without it. Confidential clients
  unchanged (secret auth, no PKCE).
- Two more ITSM/SIEM connectors: **Atlassian Jira** (REST v3 issue, ADF
  description, tier-to-priority) and **Microsoft Sentinel** (Log Analytics
  Data Collector API with the documented SharedKey HMAC signature — the
  string-to-sign is pure and unit-tested). /automation/connectors status,
  preview and dispatch all speak four connectors now; the Automation page
  derives its connector list from the live catalog.
- Schema unchanged (583 paths / 642 ops — all extensions are inside
  existing endpoints). docs/enterprise-readiness.md matrix updated.

### Enterprise readiness: SSO code flow, cloud KMS inventory, ITSM/SIEM delivery
- OIDC authorization-code flow (the enterprise redirect flavor of SSO):
  `GET /auth/oidc/authorize` → IdP → `GET /auth/oidc/callback` — HMAC-signed
  self-contained state carrying the nonce (no server-side session store),
  confidential code exchange, the same RS256/issuer/audience/expiry
  verification as the token relay, auto-provision as viewer only. Discovery
  inherits the JWKS SSRF discipline (same host, https for https issuers).
  Air-gap overrides: OIDC_AUTHORIZATION_URL / OIDC_TOKEN_URL.
- Unified `GET /auth/sso/status` (public, booleans + paths) — the login
  screen renders only the SSO options the platform actually has (OIDC,
  SAML, LDAP); nothing is a dead button.
- Cloud KMS key inventory: new `inventory` service — AWS KMS
  (ListKeys/GetKeyDescription) and Azure Key Vault (KeyClient) collectors,
  read-only, metadata-only, bounded per pass, unknown key types skipped
  WITH their reason (never guessed into a family). Normalized rows land in
  the SAME crypto-asset table (idempotent upsert per provider ref), so
  cloud keys flow into the existing CBOM/roadmap/evidence surfaces.
  Endpoints: `POST /inventory/cloud/collect` (dry-run supported),
  `GET /inventory/cloud/assets` (crypto.manage permission).
- ITSM/SIEM delivery of automation runs: pure payload mappers + injectable
  sender (`automation.connectors`) — ServiceNow incident (tier→impact/
  urgency, stable correlation_id for idempotent retries) and Splunk HEC
  (fixed sourcetype). `GET /automation/connectors` reports configuration
  NAMES only; `POST .../preview` builds the exact payload sending nothing;
  `POST .../dispatch` delivers honestly (never raises into the engine).
  Automation page gains a delivery panel; Cloud page gains the KMS
  inventory panel with collect buttons.
- `docs/enterprise-readiness.md` — measured capability/gap matrix
  (identity, discovery coverage, automation delivery, ops artifacts,
  deployment) and `docs/proposals/fab-poc.md` — a two-week, read-only,
  fixed-scope PoC proposal for a UAE bank.

### Telecom observability & operations
- Prometheus metrics (best-effort, DB-independent): telecom target count,
  verdicts by severity, unreachable count and scan age — rendered even
  during database outages (the moment dashboards matter most); the
  DB-down early-return path now carries them too.
- Roaming matrix rows carry `pqc_ready` — the partner's protecting SEPP
  probed hybrid ML-KEM; unknown edges never infer it.
- Operations runbook: `docs/runbooks/telecom-operations.md` (concepts,
  bring-up, scan modes incl. operator ingest, verdict table, automation
  playbook, regulatory artifacts, metrics + suggested alerts,
  troubleshooting, boundaries).
- Smoke test now covers the telecom surfaces (posture + registry).

### Telecom operations: automation linkage + per-carrier NRA packs
- Realtime posture events now drive the EXISTING automation rules engine
  (no parallel system): TELECOM_CERT_EXPIRING → certificate_expiring (the
  cert playbook with gated rotation), TELECOM_REACHABILITY_LOST →
  agent_offline (new Telecom NF unreachable playbook: re-probe, NOC alert
  with carrier/PLMN context, ticket, gated failover), high/critical
  FINDINGS_CHANGED/FINDING → drift_detected. Recoveries and info events
  never wake the engine. Proven end-to-end: a real REACHABILITY_LOST bus
  event with a seeded agent_offline rule produces an automation plan.
- `GET /telecom/pack?carrier=…&format=json|csv`: per-carrier NRA pack —
  the national-regulator artifact (one carrier's posture, flagged IR 8547
  families, the roaming edges it serves, declared limits). Other
  carriers' rows are deliberately excluded. Frontend: NRA pack button per
  carrier row.

### Telecom roadmap linkage & roaming matrix
- The telecom estate joins the SAME NIST IR 8547 migration plan: verdict
  crypto inventory (leaf key, signature, cipher) feeds the family taxonomy
  through cbom.banking.quantum_vulnerability — SHA1-with-RSA and 3DES land
  in `immediate`, RSA-2048 in `by-2030`, RSA-3072/EC-256 in `by-2035`;
  per carrier, and foldable into the group legal-entity view.
- `GET /telecom/roadmap` (carrier-bucketed); `GET /banking/group/roadmap
  ?include_telecom=true` merges carrier families into the supervisors'
  one artifact (bank IT + carrier NFs per legal entity).
- Roaming partner registry (GSMA IR.21 context) + `GET /telecom/roaming`
  matrix: per partner PLMN, is the inter-PLMN SBI demonstrably protected
  by the carrier's SEPP (TS 33.501)? protected / unprotected / unknown —
  unprobed edges are never fabricated. Frontend: roadmap tiles + roaming
  matrix panel on /telecom.

### Telecom realtime crypto scanner (international carrier estates)
- New `telecom_scanner` service: carrier registry (PLMN per ITU-T E.212,
  country, legal-entity link into the group registry) over 3GPP network
  functions — 5G SBA (AMF/SMF/UPF/AUSF/UDM/NRF/…), EPC, IMS, signaling,
  NDS/IP gateways, gNB-CU. TLS probing composes the network_scanner
  primitives; IPsec/IKE is classified ONLY from operator-side ingest
  (unknown ≠ pass, unknown ≠ fail).
- Classification per 3GPP TS 33.210 (NDS/IP floors: IKEv2, DH ≥ 14,
  AES-GCM), TS 33.501 (SEPP roaming edge must be TLS-protected), NIST
  SP 800-52r2 (TLS 1.2 floor, cert/key rules) and IR 8547 (hybrid
  ML-KEM key exchange on SBI recorded when detected).
- Realtime: every pass diffs against persisted previous state —
  REACHABILITY_LOST / RECOVERED / FINDINGS_CHANGED / CERT_EXPIRING with
  cooldown dedupe; events publish onto the platform bus (SSE) as
  `telecom.event`. Periodic driver: `CRYPTOSCAN_LIVE_TELECOM=1` in the
  live scan runner; on-demand: POST /telecom/scan (bounded, 64/pass).
- API (7 routes): registry CRUD (telecom.manage), scan (scan.trigger),
  operator ingest (telecom.ingest), posture + events (findings.read).
- Frontend `/telecom`: posture tiles (incl. roaming-edge protection),
  per-carrier/PLMN table with legal-entity column, live event feed,
  registry management, scan-now.

### Supervisory portal page & environment hygiene
- Frontend `/supervision` page: the read-only portal as a first-class surface —
  pack stats, jurisdiction table, DORA summary, roadmap table with bucket
  tones and the declared_limits section; honest 403 notice when the role is
  not provisioned. Nav entry + i18n (en/ar).
- Test-environment hygiene net (api suite): every fixture now snapshots and
  restores the managed env keys at setup/finalizer (any scope), plus a
  per-test guard for in-test writes — 19 test files wrote os.environ raw;
  a leaked DATABASE_URL had silently redirected an alembic run to the
  wrong database. Fixtures stay untouched; the suite is order-independent.

### Supervisory portal & migration roadmap
- Read-only `supervisor` RBAC role (the spec's 8 roles + 1) with the new
  `supervision.read` permission: posture, DORA register and roadmap —
  never configuration, ingestion or management.
- Cross-entity migration roadmap on the NIST IR 8547 milestones (purge
  legacy now → 112-bit public-key before 2030 → ≥128-bit before 2035),
  bucketed strictly from `cbom.banking.quantum_vulnerability` — JSON + CSV.
- `GET /banking/group/supervisor-pack`: one read-only artifact with group
  posture, jurisdiction distribution, DORA summary, roadmap summary and an
  explicit `declared_limits` section (honesty travels with the pack).
- Frontend: Roadmap (CSV) and Supervisor pack (JSON) downloads in the
  Group panel.

## [1.0.0] — 2026-09-10

First semver production release. `VERSION` moves from interim git-hash
naming to semver; releases are tagged `v<version>` and gated by
`python3 scripts/release_check.py` (VERSION == API version == tag,
dated CHANGELOG section, contiguous migrations, prod-guard intact).

### Group governance & DORA register (9758f85)
- Legal-entity registry for banking groups with ISO 17442 LEI validation
  (ISO 7064 MOD 97-10 checksum, round-trip tested).
- Per-entity and group-wide crypto posture rollup: jurisdiction
  concentration, exposure ranking, weak families recurring across entities.
- DORA register of information (Reg. (EU) 2022/2554 art. 28) with
  ICT-service taxonomy, criticality and contract end-date proximity;
  JSON/CSV export with explicit bank-to-supply placeholders.
- API: 6 `/banking/group/*` routes (28 total); frontend Group panel.
- Scope boundary completed: z/OS mainframe crypto-configuration discovery
  is a covered area; COBOL/PL-I application-source scanning remains a
  declared non-goal.
- Release sweep found and fixed: the documented root-level LB probes
  `/healthz` + `/readyz` were missing (only `/api/v1/healthz` existed) —
  the post-deploy smoke test now passes against a live stack; `/readyz`
  carries the 503 drain semantics; shared_config production-gate tests
  made hermetic against ambient ENVIRONMENT.

### International banking layer
- Jurisdiction packs for 10 supervisory regimes (EU/ECB+DORA, UK, US, SG, HK,
  CH, IN, JP, CA, UAE) with dated milestones and evidence-artifact mapping.
- SWIFT CSP/CSCF control-theme evidence mapping (satisfied/gap/unknown).
- NIST SP 800-57 key-lifecycle register (compromised/expired/rotation).
- Multi-language supervisory action plan (EN/DE/FR/ES/IT/AR, RTL).

### Deep discovery & banking surfaces (de33cc2, 620cfbe)
- z/OS mainframe discovery: RACF RACDCERT, ICSF CKDS/PKDS, DB2 TLS config,
  CICS TCPIPSERVICE — into the unified crypto inventory.
- HSM depth: PKCS#11 slot/object parsing, IBM CEX adapters, PQC mechanism
  detection, firmware-baseline advisories, M-of-N custody posture.
- Regulator artifacts: action plan (HTML/CSV/JSON) with owner assignment,
  HNDL register, migration roadmap (NIST IR 8547), FIPS 140 CMVP registry.
- Enterprise integrations: ServiceNow CMDB payloads, Qualys-style detection
  CSV, ISO 27001/SOC 2 crosswalk, procurement trust package.
- Assurance layer: VEX prioritization, xBOM correlation, admission gate,
  runtime verification.

### Production upgrade (cb645bd, de33cc2)
- Backup/restore: `scripts/db_backup.sh`, `scripts/db_restore.sh`, systemd
  timer (`deploy/systemd/`).
- TLS edge: `docker-compose.tls.yml`, HSTS + TLS 1.2/1.3, `deploy_prod.sh --tls`.
- Smoke test (`scripts/smoke_test.sh`), security scan
  (`scripts/security_scan.sh`), self-SBOM (`scripts/generate_own_sbom.py`).
- Lint baseline (`ruff.toml`, F+E9 defect gate), pytest importlib mode,
  test-isolation fixes, `scripts/env.sh` auto-discovery.
- CI workflows complete in `deploy/ci-workflows/` (ci, scanner-tests,
  db-migration on PostgreSQL, docker-build) + dependabot; copy to
  `.github/` to activate.
- Base images: node 22, nginx 1.29.

## [0cb159e] — 2026-09-07

### Baseline
- ZELNX multi-sector profiles, unified Technology BOM (SBOM/CBOM/HBOM/Vendor),
  live asset intelligence, scanners (static/TLS/cloud/container/OT),
  drift gate, graph engine, evidence chain, RBAC/SSO/SCIM/MFA.
