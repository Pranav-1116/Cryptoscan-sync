# Audit Report Status — 2026-10-10 (post-remediation, rounds 13–20)

**Generated:** 2026-10-10, after remediation rounds 13–20 (rounds 17/20 fully read reports 01–16 + CRYPTO_SCAN_DISCOVERY; round 19 built the open cores of advanced 49/55/58/64; round 20 fixed the error/bug class found on the full re-read: silent estate truncation, graph ghost nodes, Neo4j network-resource crash, CBOM confidence, graph export).
**Purpose:** every report in this folder was read and every actionable claim
re-verified against the code. This file records the verdict per report and what
was built in response. The original report text is unchanged; reports that were
acted on carry an `## UPDATE` addendum at the end.

**Key fact for reading these reports:** they were generated **2026-09-20**,
which predates rounds 9–17 of remediation (route-auth inventory, tenant-scoped
snapshot versions, DR/soak/load evidence, remediation verification, hybrid-PQC
detection, retirement registry, conflict detection, asset lifecycle). A large
share of the gap register was already closed when these reports landed in the
repository on 2026-10-09.

## Verdict table

| Report | Verdict | What happened |
|---|---|---|
| 01_REPOSITORY_MAP | 📷 Snapshot | Accurate as of 2026-09-20; counts have grown (799 routes, migration chain now 0074) |
| 02_ARCHITECTURE_AUDIT | ✅ Mostly current | Monolith-by-design reaffirmed; no action |
| 03_REAL_DATAFLOW | 🔧 Extended | **UPDATE addendum (R16)** — drift→remediation auto-linking built; runtime/cloud/network/certificates already in the graph payload |
| 04_DATABASE_AUDIT | 🔧 Extended | **UPDATE addendum (R16)** — scan_jobs.version + CAS, policy_rule_overrides + remediation task source (migration 0074); most index asks were already stale |
| 05_BACKEND_AUDIT | 🔧 Extended | **UPDATE addendum (R16)** — policy override surface + MAX_QUEUE_DEPTH admission built; problem-details + resource-level authz documented as open |
| 06_FRONTEND_AUDIT | 🔧 Extended | **UPDATE addendum (R16)** — Tabs ARIA + Table keyboard/scope a11y built; HBOM page + realtime cap claims stale; 132 frontend tests |
| 07_CRYPTO_DISCOVERY_AUDIT | ✅ Current + addendum | **UPDATE addendum (R16)** — detection surface matches; QUIC/transitive-dep items remain backlog |
| 08_EVIDENCE_CBOM_HBOM_AUDIT | 🔧 Extended | **UPDATE addenda (R16/R20/R22)** — CryptoAssetEvidence IS populated; HBOM ships as TechBOM layer; chain sweep R15; confidence propagation R20; standard JSF signature + compositions/externalReferences + semantic diff R22 |
| 09_GRAPH_AUDIT | ✅ Mostly current | **UPDATE addenda (R16/R22)** — tenant gate + post-scan sync postdate it; container-image nodes BUILT R21 (see R22 note) |
| 10_SECURITY_AUDIT | 🔧 Extended | **UPDATE addendum (R16)** — clone-URL transport validation built; password policy/artifact store already covered |
| 11_TESTING_AUDIT | 🔧 Extended | **UPDATE addendum (R17)** — hypothesis property tests + coverage tooling + OpenAPI contract tests built; counts stale in the report's favor |
| 12_DOCUMENTATION_REALITY | ✅ Current | Rest-api reference regenerated per change (728 paths/805 ops) |
| 13_MISSING_FEATURES | 🔧 Partially remediated | **UPDATE addendum (R16–R18, R22)** — QUIC/DTLS/WireGuard (R17), transitive propagation + Azure Dedicated HSM + resource-grant floor (R18), BU→System→Asset grant inheritance (R22); container graph nodes R21; custom roles/SDKs remain open |
| 14_TECHNICAL_DEBT | 🔧 Partially remediated | **UPDATE addendum (R16+R17)** — TD-007 portfolio set-based + bounded truncation and duplicate-operationId fix built R17; TD-010 evidence-chain sweep built R16; TD-002/008/011/012/016/025 already fixed |
| 15_PRODUCTION_READINESS | 🔧 Extended | **UPDATE addendum (R17)** — backup encryption + evidence soft-delete (chain-preserving) built; predates DR (RTO 0.103s/RPO 0s), soak, load, compliance-burn evidence in PRODUCTION-READINESS.md |
| 16_IMPLEMENTATION_ROADMAP | 🕰 Superseded + addendum | docs/PRODUCTION-ROADMAP.md is the live plan; **UPDATE addendum (R17)** — EVIDENCE-003 closed |
| CRYPTO_SCAN_DISCOVERY_REPORT | 📷 Snapshot + addendum | **UPDATE addendum (R17)** — P3-001 QUIC/DTLS/WireGuard closed; honest snapshot otherwise |
| advanced/46 CROSS_BOM | ✅ Addressed | Technology BOM unification (layered exports) |
| advanced/47 UNIFIED_ASSET_IDENTITY | 🟡 Open | Unified identity spec is product-level follow-up |
| advanced/48 CRYPTO_FACT_GRAPH | ✅ Mostly addressed | Graph snapshots + evidence links |
| advanced/49 EVIDENCE_QUALITY | 🔧 Partially remediated | **UPDATE addendum (R19)** — 6-level authority hierarchy built + wired into conflict annotation; freshness decay/calibration remain product-level |
| advanced/50 CONFLICT_RESOLUTION | 🔧 **REMEDIATED** | **UPDATE addendum** — conflict detector built (3 classes) + `GET /findings/conflicts` |
| advanced/51 OBSERVATION_FACT_RISK | 🟡 Open | Layering is design follow-up; conflicts now at least visible (50) |
| advanced/52 DETECTION_ACCURACY | 🔧 Partially remediated | **UPDATE addendum** — hybrid-PQC detection built round 14 |
| advanced/53 NORMALIZATION | ✅ Current | Collision catalogue still valid; conflict surfacing added |
| advanced/54 ASSET_LIFECYCLE | 🔧 **REMEDIATED** | **UPDATE addendum** — lifecycle state machine built (DISCOVERED→…→RETIRED) |
| advanced/55 CRYPTO_OWNERSHIP | 🔧 Partially remediated | **UPDATE addendum (R19)** — technical/security owner fields (migration 0077) + audited ownership changes; asset-level/multi-owner model remains a product decision |
| advanced/56 BUSINESS_IMPACT | ✅ Mostly addressed | business_context + system_business_process |
| advanced/57 ATTACK_SURFACE | 🟡 Open | Supply-chain/CI-CD/data-flow nodes need discovery sources the platform lacks |
| advanced/58 EXPOSURE_PATH | 🔧 Partially remediated | **UPDATE addendum (R19)** — `GET /exposure/paths` query API over the persisted graph (entry→deps→assets); NetworkEdge/LB/K8s nodes remain deployment-scoped |
| advanced/59 HNDL_PQC | 🔧 Partially remediated | **UPDATE addendum** — hybrid KEM detection + classification fixed round 14 |
| advanced/60 AGILITY | ✅ Current | 6-factor scoring shipped |
| advanced/61 PQC_MIGRATION_DEP | ✅ Mostly addressed | Migration waves/projects shipped |
| advanced/62 REMEDIATION_VERIFICATION | 🔧 **REMEDIATED** | **UPDATE addendum** — full verification loop built round 14 |
| advanced/63 CONTINUOUS_MONITORING | ✅ Mostly addressed | Monitor daemon + webhooks + SSE + report schedules |
| advanced/64 RISK_SCORING | 🔧 Partially remediated | **UPDATE addendum (R19)** — "no unified model" was already stale (§29b engine + `/risk/unified`); configurable weights, system-level view (`/risk/systems`), calculation versioning built R19; threat-actor/EPSS modeling needs external feeds |
| advanced/65 POLICY_ENGINE | ✅ Current | Audit itself found it solid (versioning + pack hashing) |
| advanced/66 COMPLIANCE_EVIDENCE | ✅ Addressed | Evidence packs, attestations, closure register |
| advanced/68 TEMPORAL | ✅ Addressed | Graph snapshots + event journal |
| advanced/69 REINTRODUCTION | 🔧 **REMEDIATED** | **UPDATE addendum** — retired-asset registry + scan check built this round |
| advanced/70 DEDUPLICATION | ✅ Current | Content-hash evidence dedup confirmed idempotent |
| advanced/71 SCAN_IDEMPOTENCY | ✅ Mostly addressed | Sync coordinator replaced full rebuild |
| advanced/73 AIR_GAPPED | 🟡 Deployment | Runbook scope |
| advanced/75 CREDENTIAL_SCOPE | ✅ Mostly addressed | Credential leases + repo configs |
| advanced/78 FORENSIC_AUDIT_TRAIL | 🔧 Extended | Platform events now cover remediation + retirement + lifecycle + chain sweeps |
| advanced/79 ZELNX_TRUST_MODEL | ✅ Current | Internal trust model holds |
| advanced/80 DETERMINISTIC_TRUTH | ✅ Current | Zero-AI pipeline confirmed by the audit itself |
| advanced/81 AI_BOUNDARY | 🟡 N/A | No AI exists in the deterministic path; runtime enforcement is deployment work |
| advanced/82 ZERO_TRUST | 🟡 Deployment | mTLS/service mesh = target environment |
| advanced/88 FINAL_GAP_PRIORITIZATION | 🔧 Partially remediated | **UPDATE addendum** — per-gap status table |
| deep/17–30 | 🕰 Stale | Superseded by rounds 9–15; still-open items are deployment-scoped (HA, replicas, encryption at rest) |
| deep/31 ENTERPRISE_WORKFLOW | 🔧 Extended | **UPDATE addendum (R23)** — drift automation/distribution/resource-authz claims stale; drift SLA metrics (MTTA/MTTR, `GET /drift/sla`, migration 0079 honest ack stamps) + clean-scan baseline proposals built R23; execution/orchestration engines remain product-scoped |

## Built in direct response to these reports

| Round | Capability | Reports answered |
|---|---|---|
| 14 (2026-10-09) | Remediation verification loop (tasks, 5-verdict engine, 7 endpoints) | 62, 88 GAP-006 |
| 14 (2026-10-09) | Hybrid-PQC detection (TLS groups, SSH KEX, IKEv2 ML-KEM, registry) | 52, 59, 88 GAP-014/015 |
| 15 (2026-10-09) | Retired-asset registry + reintroduction check (`/retirements`, `/retirements/check/{scan}`) | 69, 88 GAP-023 |
| 15 (2026-10-09) | Observation conflict detection (`/findings/conflicts`) | 50 |
| 15 (2026-10-09) | Crypto-asset lifecycle state machine (`/inventory/assets/{id}/lifecycle`) | 54 |
| 15 (2026-10-09) | Evidence-chain integrity sweep (`/ops/evidence/chain-status`) | 14 TD-010 |
| 16 (2026-10-09) | Policy rule overrides (`PUT/DELETE /policy/rules/{id}/override`, worker applies same rows) | 05 |
| 16 (2026-10-09) | Scan-queue backpressure (`MAX_QUEUE_DEPTH` admission gate, 429 at capacity) | 05 |
| 16 (2026-10-09) | Optimistic scan-job locking (`scan_jobs.version` CAS + terminal-state guard) | 04 |
| 16 (2026-10-09) | Drift→remediation auto-linking (ack `create_remediation_tasks`, `/drift/{id}/remediation-tasks`) | 03 |
| 16 (2026-10-09) | Clone-URL transport validation (blocks `ext::`/helper transports before git loads) | 10 |
| 16 (2026-10-09) | Frontend a11y pass (ARIA Tabs, keyboard-activatable Table rows, scoped headers) | 06 |
| 17 (2026-10-09) | Evidence soft-delete preserving the hash chain (`POST /findings/{id}/soft-delete`, `/restore`, migration 0075) | 15, 16 EVIDENCE-003 |
| 17 (2026-10-09) | Backup encryption (AES-256-GCM + scrypt, `--encrypt`, fail-closed restore) | 15 |
| 17 (2026-10-09) | QUIC/DTLS/WireGuard protocol analyzers wired into the engine | 13, CRYPTO_SCAN_DISCOVERY P3-001 |
| 17 (2026-10-09) | CBOM portfolio set-based query + `PORTFOLIO_MAX_ASSETS` explicit truncation | 14 TD-007 |
| 17 (2026-10-09) | OpenAPI operationId contract tests (duplicate fixed) | 11, 12 |
| 17 (2026-10-09) | Hypothesis property tests for the hashing core + opt-in coverage tooling | 11 |
| 18 (2026-10-09) | Transitive crypto propagation (`propagate_crypto_dependencies`, crypto_dependency_paths in cascade) | 13 §1.3, DISCOVERY P1-002 |
| 18 (2026-10-09) | Azure Dedicated HSM scanner + GCP `hsm_backed` marker (cloud HSM matrix complete) | 13 §3.2 |
| 18 (2026-10-09) | Resource-level grants floor (`resource_grants`, migration 0076, per-system enforcement + admin endpoints) | 13 §2.2 |
| 19 (2026-10-10) | Evidence authority hierarchy (6 tiers) + conflict annotation (`authority` on every conflict) | 49 P0#1, 50 |
| 19 (2026-10-10) | System ownership roles (`technical_owner`/`security_owner`, migration 0077, audited changes) | 55 P0#1/2 |
| 19 (2026-10-10) | Exposure path query API (`GET /exposure/paths`, bounded entry→deps→assets walks) | 58 P3#14 |
| 19 (2026-10-10) | Unified risk upgrades: env-configurable weights, `GET /risk/systems[/{id}]` with derivation signals, calculation versioning | 64 P0#2, P2#8/9/10/11 |
| 20 (2026-10-10) | Bounded estate walks everywhere (`list_all_bounded`, collection meta, truncation flags) — silent 500/1000-row truncation class eliminated | 03, 04, 05, 13, 14, DISCOVERY P1-005 |
| 20 (2026-10-10) | Graph ghost-node pruning + NetworkResource Neo4j sync (latent TypeError fixed) | 03, 09 |
| 20 (2026-10-10) | CBOM evidence-confidence propagation (recorded confidence → evidence block + property) | 08 P1#6 |
| 20 (2026-10-10) | Graph export `GET /graph/export` (GraphML / GEXF, XML-escaped) | 09 #12 |
| 21 (2026-10-10) | ContainerImage graph nodes + honest RUNS linkage (both planes, prune-set) | 03, 09, 13 |
| 21 (2026-10-10) | Trace-context propagation across the queue (payload key + job progress → PipelineContext) | 02 P2#7 |
| 21 (2026-10-10) | Migration 0078: 24 truly-missing model indexes + parity/minimality/downgrade-roundtrip tests | 04 |
| 22 (2026-10-10) | CycloneDX-spec standard enveloped signature (JSF top-level field, `?signed=jsf`) | 08 P2#6 |
| 22 (2026-10-10) | CBOM compositions (INCOMPLETE) + externalReferences (provenance + file locations), XML included | 08 P2#7 |
| 22 (2026-10-10) | Semantic CBOM diff (ALGORITHM/PARAMETER/VERSION/LOCATION_CHANGED classification) | 08 P2#8 |
| 22 (2026-10-10) | BU → System → Asset grant inheritance (repo resolution + endpoint enforcement + BU grant management) | 13 §2.2 |
| 23 (2026-10-10) | Drift SLA metrics — MTTA/MTTR + §5.2-window compliance (`GET /drift/sla`), honest `acknowledged_at` stamps (migration 0079, ack ≠ resolve) | 31 §5/§6 |
| 23 (2026-10-10) | Clean-scan baseline proposals (worker proposes on first clean scan; auditor activates — `GET /baselines/proposed`, `approve-proposed`, `DELETE .../proposal`) | 31 §2.9, 88 GAP-011 |
| 24 (2026-10-10) | Monitor-time reintroduction sweep (newest scan per target vs retired-asset registry, alert-routed, `detected_by: monitor`) | 69 follow-up |
| 24 (2026-10-10) | Drift SLA escalation sweep (window crossings alert once via CEF/webhook/email + `drift.sla_breach` events) | 31 §5.2 |
| 25 (2026-10-10) | Normalization alias canonicalization (exact-miss rescue: AES256/AES_256→AES-256, secp256r1/prime256v1→P-256, HMACSHA256→HMAC-SHA256, case retry) + 53's #12 collision suite | 53 §2.2/§5.1, deep/23 §1 |
| 25 (2026-10-10) | SHA-224 normalization rule (omission: siblings 256/384/512 existed; pattern path was reporting digest size as key_size=224) | 53 §2.2 (hash family) |
| 25 (2026-10-10) | Monitor-time evidence chain verification sweep (content hash, chain recompute, position contiguity, manifest pin; persistent CRITICAL alerting) | 25 P0#3 |
| 25 (2026-10-10) | Graph edges cite the evidence chain (`evidence_refs` with content/chain hashes) + reverse lookup `GET /cbom/evidence/{content_hash}` | 25 P1#4/P1#5 |
| 25 (2026-10-10) | HBOM content bug fixed (snapshots froze EMPTY documents — `hbom.add` never called) + `GET /hardware/hbom` document endpoint + lifecycle remove/re-observe semantics | 26 §5 |
| 25 (2026-10-10) | deep/27 addendum: P0#2/#3 + P1#5/#6 + P2#9 verified stale or shipped (link table, edge evidence refs, network/container nodes, export); Neo4j tenant isolation + CDC remain deployment-scoped | 27 P0–P2 |
| 25 (2026-10-10) | deep/28 addendum: P0#1/#3 (automated detection + `drift.event` emission) and P1#4 metrics (R23 `/drift/sla`) verified stale; per-event hash embedding + recurrence remain product-scoped | 28 P0/P1 |
| 26 (2026-10-10) | CurrentRunStore made a real ABC (`@abstractmethod` get/set; incomplete subclasses fail at instantiation, not first call) | 17 §1.1 |
| 26 (2026-10-10) | Secret-scan CI workflow staged under workflows-pending (gitleaks, push/PR + nightly full-history) | 22 P0#6 |
| 26 (2026-10-10) | Full re-verification sweep of deep/17–30 + advanced 46/48/56/60/61/63/66/70/71/78: per-report addenda written; nearly all concrete claims stale (shipped R17–R25), remainder classified product/deployment-scoped | 17–30, 46–78 |
| 27 (2026-10-10) | Cross-rule conflict detection for policy packs (`policy/rules/rule_conflicts.py` + `GET /policy/rules/conflicts` over the effective post-override set; DUPLICATE_ID/EXACT_DUPLICATE/CONTRADICTORY/SHADOWED/OVERLAPPING, typed per condition shape, scope-gated) — found 3 real issues in the shipped packs (CBUAE-001 duplicates BASELINE-001; BASELINE-005 shadowed by both forbidden-algorithm rules) | 65 P0#1 |
| 27 (2026-10-10) | Evidence freshness decay — exponential `0.5**(age/half_life)` with evidence-class half-lives (RUNTIME 7d / DECLARED-MANUAL 30d / BINARY-STATIC 90d) and a verified floor, wired into `POST /security/intelligence/state` as `decayed_confidence` with replayable notes | 49 P0#3/#4/#7 |
| 27 (2026-10-10) | Direct ownership on crypto assets / certificates / vendors (migration 0080; `POST /inventory/assets/{id}/ownership`, `POST /certificates/{fp}/ownership`, `POST /vendors/{id}/ownership` — auditor-gated, audited, reason-required, partial-update semantics; inventory listing carries the fields) | 55 P0#3/#4/#5 |
| 27 (2026-10-10) | `GET /api/v1/trust-model` — the enforced trust rules published as one machine-readable document imported live from the governing modules (authority tiers, calibrated confidence weights/bands, freshness decay, conflict policy, AI-boundary statement) | 79 P0#3/#4, 80 |
| 27 (2026-10-10) | Air-gap deployment runbook (`docs/airgap-deployment.md`) grounded in the verified mechanisms: AIRGAP_MODE/ALLOWLIST, signed feed bundles, signed exports, offline attestation, encrypted backups, honest limits | 73 P0#2/#4 |
| 27 (2026-10-10) | Full read + verdict of the remaining 20 no-marker reports (advanced 47–82): per-report addenda; shipped-surface claims verified stale (51/52/54/57/58/59/62/64/68 largely built R17–R25), remainder classified product/deployment-scoped and tracked | 47–82 |
| 28 (2026-10-10) | Detector calibration scorecards (`normalization/calibration.py` + `GET /findings/detectors/scorecards`): per-detector retraction rate (soft-deleted evidence = operator-judged FP proxy) + decisive-authority-loss share over the detector's own observations; CALIBRATED/WATCH/DEGRADED tiers, INSUFFICIENT_DATA under 20 observations, annotation-only reliability multipliers | 49 P0#4 |
| 28 (2026-10-10) | Scan coverage statements (`GET /scans/{id}/coverage`): the origin universe with zero-observation origins listed (negative evidence recorded, never inferred), per-detector observation counts from provenance, unattributed count, clean-scan flag | 49 P1#6 |
| 28 (2026-10-10) | Per-rule test coverage matrix (`policy/rules/rule_coverage.py` + `GET /policy/rules/coverage`): rules → referencing test files with per-pack rollups; first run found 8 untested rules (CNSA-004, FIPS140-003, HIPAA-002, NIST131A-001/002/004/006, PCIDSS-006) — all 8 got direct evaluation tests, coverage now 63/63 with a guard test | 65 P0#4 |
| 29 (2026-10-10) | Cross-source corroboration (`normalization/corroboration.py` + `GET /findings/corroboration`): independent observers fully agreeing on a fact, tier-aware suggested uplift (+0.05 same tier / +0.10 distinct tiers / +0.15 three-plus, capped), annotation only; cross-scan mode keeps the same-instrument rule | 49 P1#5 |
| 29 (2026-10-10) | Change classification taxonomy (`universal_crypto/live/change_taxonomy.py`): all 15 journal event types → change class + impact ordinal + direction, payload-aware (key-size comparison, algorithm designation comparison via the shared registry); wired into `GET /crypto/live/timeline` with per-class/per-direction rollups | 68 P0#3 |
| 29 (2026-10-10) | Library identity normalization (`normalization/library_identity.py` + `GET /assets/libraries/identity`): free-form library names → registry identities (sonames, module paths, packaging prefixes, version tails, aliases; generic domain words and unknowns stay unmatched) with the estate-wide alias-fold dedup view | 70 open item |
| 30 (2026-10-11) | Custom roles (13 §2.2): `custom_roles` table (migration 0081), admin CRUD `/auth/custom-roles` (409 builtin collision / 422 unknown permission), `require_permission` resolves custom grants read fresh per request; lifecycle test caught and fixed two real bugs — `UserRepository` silently replaced custom roles with `viewer`, and the legacy empty-role fallback in `require_roles` upgraded any custom-role-only provisioned user to admin | 13 §2.2 |
| 30 (2026-10-11) | VBOM generator (46 P1#5): `vendor_intel/vbom.py` (pure `VbomGenerator` + `build_vbom` from vendors/vendor_crypto/system links/latest profile) with native ZELNX-VBOM + CycloneDX exports carrying per-entry provenance; `GET /vendor-bom` + `GET /vendors/{id}/vbom`; found and fixed `technical_contact` never being accepted by the vendor create/patch API | 46 P1#5 |
| 30 (2026-10-11) | Migration execution engine (61 §4.2/§5, deep/29 §9.2): pure `db/migration_execution.py` (Kahn staging + cycle rejection, parallelization, critical path, ready set, transition matrix), migration 0082 `depends_on`, gated `start` (409 + blocking chain), `complete`, `rollback` with cascading dependents, `execute/advance` wave kickoff, `dependencies/auto` from system edges; actuators (refactor/config/HSM/cert automation) honestly stay deployment-scoped | 61 §4.2/§5, deep/29 §9.2 |
| 31 (2026-10-11) | Offline licensing (73 P0#1): HMAC-signed license packages (site-bound, feature-validated, structured failure codes), `require_license` dependency composing with RBAC, `GET /license/status` + `POST /license/trial`; LICENSE_REQUIRED=off keeps community installs open | 73 P0#1 |
| 31 (2026-10-11) | External vault reference layer (75 P0#1): `env:`/`file:`/`vault://` (HashiCorp KV-v2 client) secret references resolved fail-loud at startup, rotation bookkeeping without values, `GET /security/secrets/status` (admin); the vault instance + rotation policy stay deployment-scoped | 75 P0#1 |
| 31 (2026-10-11) | Zero-trust PDP / policy-as-code (82): embedded deny-wins policy engine + real OPA HTTP adapter, `ZeroTrustMiddleware` (ABAC-style deployment gate, fail-closed when enforced), composition rule "PDP deny blocks RBAC allow, PDP allow never bypasses RBAC", dry-run `POST /security/zero-trust/evaluate` + policies surface | 82 |
| 31 (2026-10-11) | Declared network topology ingestion (58 P0#1–2): migrations 0083, total validation (kinds/relations/dangling/self/cycles) with full-replace semantics, first-class DNSRecord/CDN/WAF/LoadBalancer graph nodes with `source: declared`, declared chains make exposure entry candidates with chain evidence, `GET /network/topology/paths` | 58 P0#1–2 |
| 31 (2026-10-11) | Crypto threat-intel advisories (deep/30): `AlgorithmAdvisory` store (migration 0084) + signed-bundle import/export (HMAC convention, tamper → nothing persisted), algorithm/asset annotation overlays (effective-date aware, STANDING/CURRENT/UPCOMING) that never rewrite scores | deep/30 |
| 31 (2026-10-11) | Cryptographic fact read model (48/51 P0#1 read side): `GET /facts/crypto` pure projection over evidence — (algorithm, purpose, file, parameters) facts with observation counts, scanners, first/last seen, exact evidence ids; the fused write side unchanged (first step of the 51 rearchitecture) | 48, 51 P0#1 |
| 32 (2026-10-11) | Field-level audit diffs (78 P0#1): pure `audit_diff.py` (`{field, before, after}` changed-fields only, sensitive values masked to `***`, summary key) wired into `user.update`, `user.profile_update`, `custom_role.update`; remaining surfaces are bounded wiring over the helper | 78 P0#1 |
| 32 (2026-10-11) | Lifecycle timestamps derived (54 P0#4): `GET /inventory/assets/{id}/lifecycle/timeline` (`lifecycle-timeline/derived-v1`) — audited transition trail plus `derived_timestamps` = most recent transition into each state; denormalised columns stay a deliberate non-choice | 54 P0#4 |
| 32 (2026-10-11) | Composite certificates (59): pure detection registry (composite OID arcs `2.16.840.1.114027.80/81/82` + PQ×classical name pairing, unknown stays unknown), ingest-time detection into `extra["composite"]`, `GET /certificates/composite` read projection with scheme counts; backup-crypto longevity propagation stays open | 59 |
| 32 (2026-10-11) | Per-algorithm business impact (56): `GET /business/impact/by-algorithm` graph-derived attribution (CryptoAsset ← USES ← System → SUPPORTS → BusinessProcess) with distinct-process revenue/customer sums; direct-FK models remain open product decisions | 56 |
| 33 (2026-10-11) | Field-level audit diffs everywhere (78 P0#1): `write_audited_diff` wired into vendor patch, migration project/task patches, certificate renewal (previously un-audited) + ownership (canonicalised), policy rule overrides (config-change audit), remediation accept/complete transitions; no-op writes audited with an honest empty diff | 78 P0#1 |
| 33 (2026-10-11) | Alembic schema-migration auditing (78): `db/migration_audit.py` + `migrations/env.py` hook — one hash-chained audit row per applied revision after `alembic upgrade`; bootstrap revisions not back-filled, non-linear moves recorded as `linear_walk=false`, audit failure never fails a committed migration | 78 |
| 33 (2026-10-11) | Unified cross-system timeline (78 P0#4): `GET /auth/audit/timeline` (`unified-timeline/v1`) merging AuditLog + platform MonitorEvents newest-first with source/actor/action filters; pure normaliser in `api/security/timeline.py` | 78 P0#4 |
| 34 (2026-10-11) | Labeled ground-truth calibration (49 P0#4 + 52): benchmark carries per-finding detector reports; pure `labeled_detector_metrics` (per-detector TP/FP/precision vs hand-labeled corpus, hard negatives = any report is FP, FN stays scanner-level, thin data INSUFFICIENT_DATA); `GET /findings/detectors/labeled-calibration` separate from proxy scorecards | 49 P0#4, 52 |
| 34 (2026-10-11) | CT-log entry ingestion (63): RFC 6962 leaf parsing (x509 entries; precerts skipped with explicit reason), DER→inventory payload with CT provenance, `POST /certificates/ct-entries` batch ingest with composite detection riding along; live log streaming stays deployment-scoped | 63 |
| 34 (2026-10-11) | Code-level fact graph slice (48 P1#11 + 58): `GET /facts/code-graph` (`code-fact-graph/read-projection-v1`) projecting `file DEFINES fact OBSERVED_BY evidence` live over evidence; CALLS edges honestly absent (needs call-graph parsing); nothing persisted, write side unchanged | 48 P1#11, 58 |

| 35 (2026-10-12) | Fact store write side (51 P0#1 step 2): `cryptographic_facts` materialised projection (migration 0085, verbatim `""`-identity), `FactRepository.rebuild` (full/per-file, stale marking, idempotent), admin `POST /facts/rebuild`, fail-soft `stage_facts` pipeline stage after dedup; live `/facts/crypto` read contract unchanged; full `crypto_assets` rearchitecture still open | 51 P0#1 |
| 35 (2026-10-12) | Threat-intel feed layer (deep/30): `sync_feed`/`sync_feeds` verify-first inbound sync of the same signed-bundle format (tampered/malformed → nothing extracted), `GET /threat-intel/feeds` + admin `POST /threat-intel/advisories/sync` with per-feed failure isolation, automation-bridge sweep; feeds are deployment config, real endpoints external | deep/30, 63-adjacent |
| 35 (2026-10-12) | Runtime egress guard (81 P0#2 application layer): fail-closed `socket.create_connection` allowlist wrap (`EGRESS_GUARD=enforce` + `EGRESS_ALLOWLIST`), lifespan install, idempotent, uninstall restores; seccomp/eBPF stay deployment-scoped | 81 |
| 35 (2026-10-12) | Neo4j per-tenant isolation, write side (deep/20 §6.3 + deep/27 P0#1): every node MERGE tenanted + stamped, every edge endpoint MATCH tenant-scoped, `PRUNE_KIND` tenant-safe with legacy-cleanup only on platform syncs; payload builders re-attach the stamp (real bug: dropped stamp fed nodes to the platform prune); reads stay memory-isolated under scope (zero-Bolt contract unchanged) | deep/20 §6.3, deep/27 P0#1 |
| 35 (2026-10-12) | Automation → ticket link (deep/31): `ticket.requested` bus consumer creating ITSM tickets (`provider=automation`, external ref `automation/{event_kind}/{asset or estate}`) with redelivery-idempotent dedup; ChatOps routing stays external | deep/31 |

| 36 (2026-10-12) | Full-table binary fingerprints (52 P0#3 slice): whole-file scan for complete crypto tables (AES S-box/inverse + OpenSSL Te0/Td0 both byte orders, SHA-2 K/IV, Keccak RC, CRC32/CRC32C, NIST curve params cross-checked against the cryptography library, Ed25519/Curve25519) with offset-carrying `TABLE_FINGERPRINT` evidence (0.95); stripped binaries with no symbols/strings now detected; angr/Ghidra CFA stays open | 52 P0#3 |
| 36 (2026-10-12) | Seccomp profile for deterministic services (81 P0#1 deployment artifact): `deploy/seccomp/deterministic-services.json` (fail-closed OCI format, 52 escape primitives denied) + `api/security/seccomp.py` validator pinned by tests; execve-limit honestly stated (runtime needs it; runtime AI-invocation proof stays eBPF) | 81 |
| 36 (2026-10-12) | Serving-TLS posture (82 deployment set slice): cert/key/bundle inspection (parse, pairing, expiry, strength, signature, SANs; never key material), `GET /security/tls/posture`, production boot gate fails fast on configured-but-invalid TLS; unconfigured app boundary reported honestly (reverse proxy invisible); mTLS/TDE stay infrastructure | 82 |
| 36 (2026-10-12) | Cross-BOM linking + conflicts (46): canonical identity per component across CBOM generator / TechBOM layers / VBOM (algorithm-only crypto identity — key size/mode/purpose are comparable attributes, disagreements become conflicts not separate identities), `GET /cbom/cross-links` over the live inventory with per-BOM refs; single-generator merge + unified query layer stay open | 46 |

Detailed engineering evidence: `docs/AUDIT-RECONCILIATION-2026-10-09.md`.
