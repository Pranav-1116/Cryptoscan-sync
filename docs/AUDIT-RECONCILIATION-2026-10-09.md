# Audit Report Reconciliation — 2026-10-09

**Input:** `audit_reports/` (65 files, ~28k lines, added in commit `f194174`, generated 2026-09-20).
**Method:** every report was read and every actionable claim re-checked against the current
code — code is the source of truth, and the audits predate rounds 9–13 (route-auth inventory,
tenant-scoped snapshot versions, DR/soak/load evidence, retention auth, billing-webhook fix).
**Outcome:** two genuinely-missing code capabilities were built this round (remediation
verification, hybrid-PQC protocol detection); the rest of the register is either already
fixed, infrastructure-scoped, or not applicable to this codebase.

---

## 1. What round 14 built (the two real, code-buildable gaps)

### 1.1 GAP-006 — Remediation verification loop (audit 62)

The audit's only P0 that was 100% code-buildable and 100% missing. Remediation was
suggestions-only; nothing proved a fix actually worked.

| Piece | Where |
|---|---|
| `RemediationTask` + `RemediationVerification` models | `services/database/db/models/remediation_task.py` |
| Migration `0072` (tables + indexes) | `services/database/migrations/versions/0072_remediation_verification.py` |
| Pure five-verdict decision engine | `services/remediation/remediation/verification.py` |
| Task/verification repositories | `services/database/db/repositories/remediation_repository.py` |
| 7 API endpoints (create/list/get/accept/complete/verify/verifications) | `services/api/api/routers/remediation.py` |
| Decision-table tests | `services/remediation/tests/test_verification.py` (13) |
| End-to-end lifecycle tests | `services/api/tests/unit/test_remediation_tasks.py` (8) |

Semantics implemented (per audit §5.1, tightened):

* Task creation **snapshots** the finding + the scan's `target_location` — later evidence
  pruning cannot rewrite what is being verified.
* `complete` **automatically verifies** against the latest COMPLETED scan of the same
  target that is newer than the original scan (or an explicit `rescan_id`); no newer scan →
  `INCONCLUSIVE`, and the task honestly stays `COMPLETED`.
* Verdicts: `VERIFIED` (gone/replaced/compliant), `PARTIAL` (improved or replaced but still
  failing), `FAILED` (unchanged), `REGRESSION` (site fixed but new non-compliant crypto
  appeared — target-wide when the original scan's evidence survives, file-scoped otherwise),
  `INCONCLUSIVE` (no usable rescan evidence).
* Every verdict persists the full machine-readable comparison (audit 62 §2.1 "replayable
  verification") and drives the task status; every step emits a platform event
  (`remediation.task_created/accepted/completed/verified`).
* Mismatched rescan targets are rejected (400) — verification compares like with like.
* Auto-**rescan enqueue** on completion is deliberately NOT implemented here: spawning
  scans belongs to the monitor daemon / trigger surface; the verifier consumes whatever
  completed scan evidence exists, deterministically, without inventing evidence.

### 1.2 GAP-014/015 (+ audit 52/59) — Hybrid PQC protocol detection

TLS supported_groups were emitted as raw hex (`0x11ec`) with no identity, so hybrid-PQC
endpoints silently classified as UNKNOWN. Worse, two tables were factually wrong:

* `sntrup761x25519-sha512` (OpenSSH hybrid KEX) was mapped to plain **X25519** — a
  quantum-resistant KEX reported as Shor-vulnerable.
* IKEv2 DH groups 27/28 were mapped to X25519/X448; IANA assigns 27–30 to **brainpoolP224r1
  … brainpoolP512r1** (Curve25519/Curve448 are 31/32, RFC 8031), and 24/25/26 were
  mislabelled as P-256/P-384/P-521 when they are 2048-bit MODP and 192/224-bit ECP groups.

Fixed end to end:

| Change | Where |
|---|---|
| Registry families + aliases for RFC 10024 hybrids (`X25519MLKEM768` …), pre-standard Kyber drafts (RESTRICTED), and `X25519+sntrup761` | `shared/shared_models/shared_models/algorithm_registry.py` |
| `kem-hybrid-pqc` family → `PQC_RESISTANT` with an explicit hybrid reason | `shared/shared_models/shared_models/quantum_classify.py` |
| Named `TLS_GROUPS` map (classics + ffdhe + hybrids + Kyber drafts) in the ClientHello/ServerHello parsers | `services/universal_crypto/universal_crypto/protocol_engine.py` |
| SSH KEX: hybrid identities + the real `@openssh.com` wire names | same file |
| IKEv2: groups 22–37 per IANA incl. **35/36/37 = ML-KEM-512/768/1024** (RFC ipsecme-ikev2-mlkem) | same file |
| Runtime TLS record parser: hybrid codepoints named; `0x00FF: ffdhe8192` bug fixed (0x00FF is reserved; 8192 is 0x0104, RFC 7919) | `services/runtime/runtime/agent/tls_record_parser.py` |
| Tests: registry/quantum (4 new), protocol engine TLS groups + SSH + IKEv2 (3 new, 2 updated) | `shared/shared_models/tests/test_quantum_classify.py`, `services/universal_crypto/tests/test_protocol_engine.py` |

`keyassure`'s active PQC-downgrade probe already spoke the hybrid names; now the passive
parsers, the shared registry and the quantum classifier agree with it.

---

## 1.5 Round 15 — the next four code-buildable gaps (2026-10-09, same day)

The user asked for the remaining open items to be built too. Four more audit
gaps closed (details in `audit_reports/00_ROUND_STATUS.md` + the UPDATE
addenda inside the affected reports):

1. **Reintroduction detection (GAP-023 / audit 69)** — `retired_assets`
   registry (migration 0073) + pure detector + `POST /retirements`,
   `GET /retirements`, `POST /retirements/{id}/lift`,
   `POST /retirements/check/{scan_id}` with severity-routed events
   (CRITICAL pages / HIGH alerts / MEDIUM logs). Scan-time; monitor-time
   background checking remains open.
2. **Observation conflict detection (audit 50)** — pure three-class detector
   (ALGORITHM / PARAMETER / STATUS mismatch) in the normalization service +
   `GET /findings/conflicts` (within-scan across scanners, or scan-vs-scan).
   Reported, never auto-resolved.
3. **Crypto-asset lifecycle (audit 54)** — `crypto_assets.lifecycle_state`
   (migration 0073): DISCOVERED → VERIFIED → ACTIVE → DEPRECATED → RETIRED,
   server-side transition rules (RETIRED terminal — a comeback is a
   reintroduction), reasons + audited events via
   `POST /inventory/assets/{id}/lifecycle`; inventory lists/filters by state.
4. **Evidence-chain integrity sweep (TD-010 / audit 14)** —
   `GET /ops/evidence/chain-status` recomputes every recent scan's chain with
   the export verifier and emits `evidence.chain_broken` on breakage.

## 1.6 Round 16 — the ten-report full read (2026-10-09, same day)

The user asked for reports 01–10 to be read in full and every remaining
code-buildable finding built. All ten were re-verified against the code; a
large share of their gap claims were already stale (verdict per report in
`audit_reports/00_ROUND_STATUS.md`, with UPDATE addenda inside each). Five
real gaps remained and were built (migration 0074):

1. **Policy rule management surface (audit 05)** — `policy_rule_overrides`
   (tenant-scoped, unique per rule): `PUT/DELETE
   /policy/rules/{rule_id}/override` (admin, audited) disables a rule or
   overrides its severity for one tenant without touching the reviewed YAML
   pack. `GET /policy/rules` now reports pack state, override, and effective
   state side by side, and the worker's evaluation stage applies the same
   rows through the same helper (`policy.core.overrides`) — what the listing
   shows is what the engine enforces.
2. **Scan-queue backpressure (audit 05's MAX_QUEUE_DEPTH)** — the admission
   decision now refuses with 429 when QUEUED+RUNNING jobs exceed
   `MAX_QUEUE_DEPTH` (default 500, `<=0` disables). Counting is a documented
   seam like the other admission seams; fail-closed on count failure.
3. **Optimistic scan-job locking (audit 04's lost-update race)** —
   `scan_jobs.version` + compare-and-set `JobRepository.update_status`,
   which also refuses to leave a terminal state non-forcefully (a stale
   worker completing a job the reaper already failed is a detected conflict;
   the first verdict stands). The reaper reports lost races instead of
   counting them.
4. **Drift → remediation auto-linking (audit 03's strongest data-flow gap)**
   — `POST /drift/{id}/acknowledge` accepts `create_remediation_tasks` and
   auto-opens PROPOSED tasks (max 10) for the FAIL/WARN evidence behind the
   drift, carrying `source="drift"`, `source_ref=drift_id` (migration 0074
   columns) so `GET /drift/{id}/remediation-tasks` lists them afterwards.
   Honest no-op when the drifted algorithm has no failing evidence.
5. **Clone-URL transport validation (audit 10's unvalidated git input)** —
   `GitClient.clone` now validates the repo URL first: remote-helper
   transports (`ext::…`, CVE-2022-24439), helper-by-name forms and leading
   dashes are refused before git is even imported; http/https/git/ssh/file,
   scp-style and local paths still work.

Plus one frontend accessibility pass (audit 06 P0): `Tabs` implements the
ARIA tabs pattern (roles, aria-selected, roving tabindex, arrow/Home/End
keys) and `Table` clickable rows are keyboard-activatable with column
headers scoped — with tests (frontend suite 130 → 132).

Verified-stale highlights recorded in the addenda: HBOM frontend is wired to
`/live-scan/bom`; `CryptoAssetEvidence` links are populated by
`replace_for_scan`; password policy exists at register/change/reset; the
reaper + CAS make drift-ack races detectable; graph sync runs post-scan as a
pipeline stage; audit_log and crypto_live already carry the indexes audit 04
asked for; the `system_dependencies` (parent, child, relation) unique-index
ask was evaluated and deliberately kept as pair-level dedup (the codebase
upserts by pair; a relation-level constraint would create duplicate edges).

## 1.7 Round 17 — the seven-report full read (2026-10-09, same day)

The user pasted reports 11–16 plus CRYPTO_SCAN_DISCOVERY_REPORT and asked
for the same treatment: read all in full, verify every claim against the
code, build everything real and code-buildable. Verification showed the
usual pattern — 11 of 12 headline claims were stale in the reports' favor
(4.1k+ backend tests vs "no coverage tooling", 132 frontend tests,
736-path/815-operation API). Six real, code-buildable gaps remained and
were built (migration 0075):

1. **Evidence soft-delete that preserves the chain (15 §6.2,
   16 EVIDENCE-003)** — tombstone columns on `evidence_records`;
   auditor-gated `/findings/{id}/soft-delete` (mandatory reason, chained
   audit entry, 409 double-delete) and `/findings/{id}/restore`;
   consumption surfaces exclude tombstones while chain verification and
   exports still read every row. A hard DELETE was never acceptable: each
   row's chain_hash commits to its predecessor.
2. **Encrypted backups (15 §4)** — `--encrypt` on backup_evidence.py:
   AES-256-GCM, scrypt KDF over `BACKUP_ENCRYPTION_KEY`, `CSBC1`
   self-describing header, plaintext SHA-256 kept in the manifest;
   restore decrypts before the manifest check, fails closed on wrong
   key/tamper, and the decrypted plaintext never outlives the restore.
3. **QUIC/DTLS/WireGuard analyzers (13 §3.1, discovery P3-001)** — three
   new protocol_engine analyzers wired into the engine input bundle,
   following the SSH/IPsec observations pattern; QUIC inherits the TLS
   group registry (wire names + codepoints), DTLS reuses the IANA suite
   registry, WireGuard reports its fixed RFC 8437 suite as non-negotiable
   and honestly quantum-vulnerable.
4. **CBOM portfolio scale (14 TD-007)** — set-based `_located_assets`
   (one JOIN, no per-system loop, no second 5000-row page), one-query
   dependency edges, `PORTFOLIO_MAX_ASSETS` bound with explicit
   `cryptoscan:truncated` metadata + logged warning. Streaming remains
   open; the OOM and silent-truncation failure modes do not.
5. **Duplicate OpenAPI operationIds (12's regeneration dependency)** —
   two same-named functions whose distinct paths normalized to one id;
   fixed, and pinned by a new contract test (uniqueness, versioned paths
   with the six-probe allowlist, tagged operations).
6. **Property tests + coverage tooling (11)** — hypothesis pinned;
   seven properties over the hashing core; `pytest-cov` + `.coveragerc`
   + `scripts/coverage.sh` as an opt-in measured report (the gate stays
   the suite result; CI wiring remains credential-blocked, staged in
   `.github/workflows-pending/`).

Verified-stale highlights: the universal_crypto suite's 18 apparent
failures were a PYTHONPATH artifact (shared_models not importable), not a
regression — 148/148 with the standard path; audit 11's test-count and
coverage rows describe a codebase several rounds old.

## 1.8 Round 18 — the remaining open audit items (2026-10-09, same day)

Round 17 closed with three genuinely open code-buildable items (transitive
dependency crypto, cloud HSM detection, resource-level RBAC). Round 18
built them (migration 0076):

1. **Transitive crypto propagation (13 §1.3, DISCOVERY P1-002)** — the
   package inventory now joins the crypto-library catalog; exposure
   propagates up lockfile parent chains, each path from a crypto-bearing
   package to its direct-dependency entry recorded in
   `crypto_dependency_paths`. Honest edge coverage: only ecosystems whose
   lockfiles carry parent edges (npm nested paths, cargo blocks) get
   chains; the report says which.
2. **Cloud HSM detection (13 §3.2)** — matrix complete: AWS CloudHSM and
   Azure Managed HSM were already covered (stale claims); Azure Dedicated
   HSM scanner added (optional SDK, skip-not-fabricate); GCP HSM keys
   carry an explicit `hsm_backed` marker.
3. **Resource-level grants floor (13 §2.2)** — per-system grants with
   restrictive-only-when-present semantics, enforced on the per-system
   endpoints, platform-role bypass rules, admin-only audited management.
   BU→System→Asset inheritance and custom roles remain open by design.

Also verified stale: "fixed 3 roles" (the RBAC module ships the 8-role
catalog + permission matrix).

## 1.9 Round 19 — the advanced/deep re-study (2026-10-10)

The round-18 close-out ("all code-buildable findings closed") was
challenged, so every advanced/deep report was re-read against the code.
Two things fell out: several 🟡-Open verdicts were already stale (the
§29b unified risk engine predates report 64's "no unified model"
verdict), and four reports carried genuinely buildable cores. Built
(migration 0077):

1. **Evidence authority hierarchy (49 P0#1)** —
   `normalization/authority.py`: explicit 6-tier model (RUNTIME >
   BINARY > STATIC > DECLARED > MANUAL > UNRANKED), deterministic
   provenance matching, never guessing. Wired into `detect_conflicts`:
   every conflict now carries an `authority` preference annotation
   (decisive or tie) — annotation only, no auto-resolution.
2. **System ownership roles (55 P0#1/#2)** — `systems.technical_owner`
   + `systems.security_owner` (migration 0077), full API surface
   (create/patch/import), and audited changes: effective ownership
   changes write `system.ownership_change` chain entries with old→new
   per field; no-op patches are not audited.
3. **Exposure path queries (58 P3#14)** — `GET /exposure/paths`:
   bounded (depth ≤ 4, ≤ 100 paths, cycle-free) walks from
   entry-candidate systems (cloud-hosted or remote-target) over
   dependency edges to attached crypto assets, with designation
   filters. Honest about the entry heuristic; P0–P2 topology nodes
   remain deployment-scoped.
4. **Unified risk upgrades (64 P0#2, P2#8–#11)** —
   `CRYPTOSCAN_RISK_WEIGHTS` env-configurable factor weights
   (absolute for named factors, remainder split proportionally, invalid
   configs fall back wholly and say so); `GET /risk/systems[/{id}]`
   deriving all eight factor levels from persisted state with raw
   derivation `signals`; `calculation_version` stamping on every
   assessment. Also corrected the stale "no unified model" claim —
   `/risk/unified` + the §29b engine predate the re-read.

Gates this round: api 1388 (1374 + 14 new; unit 1094 + integration/
security 294), worker 525, normalization 139 (+16 authority),
universal_platform 40 (+5), database 162, scanner 291+12s,
cloud_scanner 414, cbom 233, policy 96, remediation 42, evidence 62,
graph_engine 52, drift 72, control_plane 81, devsecops 550,
universal_crypto 148, shared_models 519 (+config 16 + logging 11);
ruff clean; migration chain 0001→0077; rest-api.md regenerated
(743 paths / 823 ops / 91 groups). Frontend untouched this round (no
frontend files changed; last green at 13faf13).

Verified stale this round: 64's "no unified risk model" (engine +
endpoint already shipped); 49's P0#2 conflict detection (round 15);
58's P0–P2 require discovery sources that do not exist in scope.

Remaining open after round 19: 47 unified asset identity + 51
observation→fact→risk layering (product-level), 57 attack-surface
nodes beyond persisted data (deployment), freshness decay + collector
calibration (49), asset-level/multi-owner model (55), threat-actor/
exploitability modeling (64, needs external feeds), report-13 §2.1
Neo4j tenancy/quotas + §2.3 automated compliance reports + §2.4 key
rotation automation + §3.1 CT monitoring (deployment/product), 82
zero-trust (deployment), SDKs, CI-blocked tooling
(`.github/workflows-pending/`).

## 1.10 Round 20 — full re-read of reports 01–16 + DISCOVERY: the error/bug pass (2026-10-10)

The user challenged again ("many things missing, many errors and bugs");
every one of the 17 files was re-read in full. Outcome: one stale-verdict
correction, four real defects fixed, one feature built:

1. **Silent estate truncation (bug, 9 surfaces):** the graph payload,
   agility ×4, estate due-scan planning ×2, CBOM portfolio ×2, and
   exposure paths each read a single 500/1000-row page — systems beyond
   it were invisible to the graph, blast radius, snapshots, agility
   aggregates, and re-scan scheduling. Fixed with
   `SystemRepository.list_all_bounded()` (paged, 50k bound, honest
   `truncated` flag), bounded per-kind walks in `collect_graph_payload`
   (payload now carries `collection` meta), and `systems_truncated`
   flags on the affected endpoints.
2. **Graph ghost nodes (bug):** MERGE-only Neo4j sync never deleted
   removed entities. Sync now prunes per-kind (only kinds present in the
   sync; full keep-set per query; ComplianceScope excluded) and reports
   `pruned`.
3. **Neo4j `network_resources` TypeError (latent crash):** the payload
   key existed but `Neo4jGraphStore.sync` never accepted it — any
   real-driver sync raised; the memory fallback masked it in tests.
   NetworkResource nodes + CONNECTS_TO now merge on Neo4j; dead duplicate
   `network_rows` removed.
4. **CBOM hardcoded confidence (bug + 08 P1#6):** `_component` claimed
   0.9 detection confidence regardless of the record. Recorded
   confidence now propagates (HIGH→0.9 / MEDIUM→0.6 / LOW→0.3) plus a
   `cryptoscan:confidence` property.
5. **Graph export (09 #12):** `GET /graph/export?format=graphml|gexf`.
6. **Correction:** report 16's round-17 addendum listed EVIDENCE-002
   (link-table tenant_id) as open — wrong; migrations 0061/0062 already
   covered it. Fixed in that file.

Gates: api 1396 (unit 1102 + 294), graph_engine 58 (+6), cbom 236 (+3),
worker 522, database 162; ruff clean; rest-api.md regenerated
(744/824/91). All 17 report files carry round-20 addenda.

Still open after round 20: container-image graph nodes, PKCS#11/KMIP
pipeline integration, wire-capture parsing, CBOM signatures/
compositions/semantic diff, ADRs, deployment-scoped items, CI-blocked
tooling, SDKs, product decisions (multi-owner, custom roles, 47/51).

## 2. P0 gap register (88_FINAL_GAP_PRIORITIZATION) — status after round 14

| Gap | Audit claim | Current status | Evidence |
|---|---|---|---|
| GAP-001 Scanner sandboxing (gVisor/Kata, seccomp) | Zero | **Open — deployment-scoped.** Container hardening is a target-environment task (runtime class, seccomp profiles, capability drop live in the deploy manifests, not this repo's code paths). Tracked in PRODUCTION-ROADMAP. |
| GAP-002 Tenant resource quotas | Zero | **Largely fixed.** Plan quotas enforce members/invites/targets/monthly scans with `402 quota_exceeded` (`api/routers/saas.py`); usage metering + billing webhooks live. CPU/memory/worker-pool quotas are orchestrator-level (same bucket as GAP-001). |
| GAP-003 Neo4j tenant isolation | Zero | **Fixed (rounds ≤8).** `graph_engine/core/tenant_gate.py` + `memory-tenant-isolated` backend; adversarial cross-tenant tests exist. |
| GAP-004 Encryption at rest | Zero | **Open — deployment-scoped** (PG TDE/LUKS/Neo4j native encryption are target-env config). Backups: `scripts/backup_evidence.py` chain-verified. |
| GAP-005 mTLS / zero trust | Zero | **Open — deployment-scoped** (SPIFFE/service mesh). In-process trust boundary documented in audit 79 and enforced in code by the deterministic/AI split. |
| GAP-006 Remediation verification | Zero | **FIXED THIS ROUND** (§1.1). |
| GAP-007 Automated drift detection | Zero | **Fixed.** `services/drift/` + `api/routers/drift.py` + `DriftRepository`; baselines (`api/routers/baselines.py`) with approval workflow (GAP-011 also covered). |
| GAP-008 Replayability | Zero | **Partial (by design).** Scan manifests + manifest_hash, evidence chain hashes, graph snapshots (content-addressed), twin snapshot replay and scan-transfer verification exist. Full environment-capture replay (scanner image digests per scan) is target-env work. |
| GAP-009 Runtime AI boundary | Zero | **Not applicable as stated.** There is no AI in any deterministic path (audit 80 itself proves it by import analysis); audits 80/81's residual ask is *runtime enforcement* (eBPF/seccomp) — deployment-scoped. |
| GAP-010 Continuous monitoring | Zero | **Largely fixed.** Monitor daemon with scheduled re-scans, GitHub/container-registry inbound webhooks (`api/routers/webhooks.py`) triggering scans, SSE realtime stream, drift events, report schedules (`api/routers/report_schedules.py` with `_run_schedule`). CT-log/CVE-feed streaming remains open (P3). |

## 3. P1/P2 register + missing-features (13) — status after round 14

* **HBOM / VBOM (GAP-012/013)** — **fixed** inside the unified Technology BOM:
  `layer = sbom | cbom | hbom | vendor | certificates | all` (`api/routers/techbom.py`),
  CycloneDX/SPDF/CSV/PDF signed exports, scheduled exports, snapshots + diffs.
  The audit predates the Technology BOM unification.
* **PQC protocol detection (GAP-014/015)** — **fixed this round** for TLS hybrids, SSH
  hybrid KEX and IKEv2 ML-KEM (§1.2). QUIC/DTLS/WireGuard protocol *parsers* remain open
  (audit 13 §3.1) — no evidence of them on the wire in current deployments; logged below.
* **Baseline workflow (GAP-011)** — fixed: propose/approve/list with auditor gate.
* **Evidence packages (GAP-024/025)** — fixed: compliance evidence pack, attestations,
  closure register (`config/readiness-closure-policy.json`), signed report schedules.
* **Reintroduction detection (GAP-023)** — **partially fixed this round**: REGRESSION is
  now first-class in remediation verification (a retired-and-fixed finding that reappears
  flips the task to REGRESSION and events fire). A standalone retired-asset registry with
  monitor-time (not scan-time) detection remains open.
* **Webhook retry/dead-letter (13 §4.1)** — **mis-scoped in the audit**: the webhooks
  router is *inbound* (registry/GitHub → scan trigger, HMAC-verified, synchronous).
  Outbound delivery is inApp/email/webhook/SIEM *routing configuration*
  (`api/routers/notifications.py`); an outbound delivery worker with retry/DLQ would be new
  infrastructure — logged as open.
* **Transitive dependency crypto (13 §1.3)** — partial: cascade runs + `depends_on_systems`
  (`cascade_run` model, migrations 0069/0070); unified lockfile graph + recursive crypto
  propagation remains open (multi-week).
* **Resource-level RBAC / custom roles (13 §2.2)** — open as designed: domain-level RBAC
  (`hardware.read/…`, `scan.trigger`, …) is the shipped model; per-asset ACLs are a product
  decision, not a defect.
* **Crypto asset lifecycle states (audit 54)** — open (no `lifecycle_state` on
  `crypto_assets`); verification tasks now provide the *evidence* trail for VERIFIED/RETIRED
  transitions, the lifecycle state machine shipped in round 15 (migration 0073).

## 4. Technical debt register (14) — status after round 14

| Item | Status |
|---|---|
| TD-002 Neo4j tenant isolation | **Fixed** (tenant gate; audits 20/27's finding is stale) |
| TD-011 Link tables no tenant_id | **Fixed** — `SystemAsset`, `SystemDependency`, `CertificateUsage`, `CryptoAssetEvidence` all `TenantScoped` |
| TD-012 Live crypto bypasses evidence | **Largely fixed** — live scan runner carries evidence references; digital-twin reconciliation joins `evidence_records ↔ crypto_asset_evidence ↔ crypto_assets`; live CBOM is versioned |
| TD-025 Realtime events unbounded | **Fixed** — `frontend/src/lib/realtime.tsx` caps at `EVENT_CAP` |
| TD-008 Graph sync full rebuild | **Fixed** — `sync_coordinator.sync_payload` (no delete-all), plus `graph.updated` SSE event |
| TD-016 DevSecOps 93k lines | **Stale** — now 1,688 lines (split in earlier rounds) |
| TD-007 CBOM portfolio in-memory | Open (streaming pagination) — tracked |
| TD-001/003/004/005 monolith/dual-CBOM/techbom-duplicate/dual-registry | **Deliberate architecture**, re-litigated in audits 02/46/53: one deployable API, one Technology BOM with layered export, registries unified through `shared_models` normalization. Merging is a rewrite, not debt paydown. |
| TD-009 read replicas, TD-013 compose secrets, TD-014 encryption at rest, TD-015 mTLS | Deployment-scoped (see GAP-004/005); prod compose/env guidance exists |
| TD-010 evidence chain auto-verification | **Fixed round 15**: `GET /ops/evidence/chain-status` sweeps recent scans with the export verifier, event on breakage; per-scan verify already ran in exports |
| TD-034 migration 0060 risk | Superseded — chain now at **0072**, migration-chain test green |

## 5. Advanced/deep report clusters — verdicts

* **46/47/48 (BOM consistency, asset identity, fact graph):** largely addressed by the
  Technology BOM unification + `bom-ref` identity + graph snapshots. Residual: unified
  asset-identity spec across live/static (open, product-level).
* **49/79/80 (evidence quality, trust model, deterministic truth):** these audits
  themselves conclude the platform's evidence chain and zero-AI pipeline are its strengths;
  their asks (formal evidence-authority enum) are enhancements, open.
* **50 (conflict detection), 51 (observation/fact layering), 53 (normalization):** open
  design work — conflicts are now detected and surfaced (round 15:
  `normalization/conflicts.py` + `GET /findings/conflicts`); a persisted
  conflict model with resolution workflow remains open.
* **52 (detection accuracy):** PQC blind spots fixed this round; binary control-flow
  analysis (angr/ghidra) remains P3.
* **55/56/57/58 (ownership, business impact, attack surface, exposure paths):** business
  context (`business_context`, `business.py`, `system_business_process`) ships the core;
  direct finding→business-service edges and exposure-path tracing are open enhancements.
* **59/29/61 (HNDL/PQC):** classification strong; this round closed the hybrid-KEM
  detection hole (§1.2); migration waves/planning already shipped (`migration_project`).
* **63 (continuous monitoring):** see GAP-010. **64 (risk scoring):** quantum + compliance
  + agility scoring shipped; unified cross-score model open. **65 (policy engine):** the
  audit itself finds versioning + pack hashing solid.
* **66 (compliance evidence):** requirement→policy string references were replaced by the
  evidence pack + closure register work (rounds ≤8); cross-framework mapping matrix open.
* **68 (temporal):** graph snapshots + event journal shipped. **69 (reintroduction):**
  scan-time regression detection shipped this round; monitor-time detector open.
* **70 (dedup), 71 (idempotency):** evidence content-hash dedup is idempotent (audit 70
  confirms); asset dedup partial; graph sync is now coordinator-based (idempotent re-sync).
* **73 (air-gap):** deployment runbook scope. **75 (credential scope):** credential leases
  + repo configurations shipped; per-surface least-privilege matrices are operational docs.
* **78 (audit trail):** platform events cover the audited surfaces this round's work
  touched (remediation lifecycle); audit 78's full coverage matrix is partially open.
* **82 (zero trust):** GAP-005 bucket. **84/85/86/87:** not in the 65 files shipped;
  referenced by 88 only.
* **deep/17–30:** superseded in most findings by rounds 9–13 (route auth, tenancy, DR
  evidence); their still-open items are captured above (read replicas, HA clusters,
  encryption at rest, secret rotation — all deployment-scoped).

## 6. Honest open list after round 14 (what "solve all the problems" still means)

1. **Deployment/target-environment** (not codeable here): gVisor/Kata + seccomp, encryption
   at rest, mTLS/service mesh, HA (StatefulSets/replicas), read replicas, digest-pinned
   images, branch protection + CI (credential-blocked; staged in `.github/workflows-pending/`).
2. **Multi-week engineering (backlog)**: unified transitive-dependency crypto graph;
   conflict model (audit 50); crypto-asset lifecycle state machine (audit 54); outbound
   notification delivery worker with retry/DLQ; CT-log
   streaming; QUIC/DTLS/WireGuard parsers; monitor-time reintroduction detector;
   cross-framework compliance mapping.
3. **External evidence (SKIP by policy):** HSM provider attestations, SOC2/ISO/FIPS,
   bank field data — tracked in `config/readiness-closure-policy.json`.

Decision unchanged from PRODUCTION-READINESS.md: supervised pilot / pre-production, one
instance per bank. Full plan: `docs/PRODUCTION-ROADMAP.md`.
