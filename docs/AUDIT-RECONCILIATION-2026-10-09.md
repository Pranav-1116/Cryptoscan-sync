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
