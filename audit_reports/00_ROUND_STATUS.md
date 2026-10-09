# Audit Report Status — 2026-10-09 (post-remediation, rounds 13–16)

**Generated:** 2026-10-09, after remediation rounds 13–16 (last full read of reports 01–10 in round 16).
**Purpose:** every report in this folder was read and every actionable claim
re-verified against the code. This file records the verdict per report and what
was built in response. The original report text is unchanged; reports that were
acted on carry an `## UPDATE` addendum at the end.

**Key fact for reading these reports:** they were generated **2026-09-20**,
which predates rounds 9–16 of remediation (route-auth inventory, tenant-scoped
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
| 08_EVIDENCE_CBOM_HBOM_AUDIT | 🕰 Stale + addendum | **UPDATE addendum (R16)** — CryptoAssetEvidence IS populated; HBOM ships as TechBOM layer + live page; chain sweep built R15 |
| 09_GRAPH_AUDIT | ✅ Mostly current | **UPDATE addendum (R16)** — tenant gate + post-scan sync stage postdate it; container-image nodes remain open |
| 10_SECURITY_AUDIT | 🔧 Extended | **UPDATE addendum (R16)** — clone-URL transport validation built; password policy/artifact store already covered |
| 11_TESTING_AUDIT | 🕰 Stale | 498 test files → more; backend 4.1k+ across the suites run, all green |
| 12_DOCUMENTATION_REALITY | ✅ Current | Rest-api reference regenerated per change (728 paths/805 ops) |
| 13_MISSING_FEATURES | 🔧 Partially remediated | **UPDATE addendum** — remediation verification, HBOM/VBOM, drift/baselines, PQC built; transitive-dep graph + QUIC/DTLS/WireGuard remain open |
| 14_TECHNICAL_DEBT | 🔧 Partially remediated | **UPDATE addendum** — TD-010 evidence-chain sweep built this round; TD-002/008/011/012/016/025 already fixed |
| 15_PRODUCTION_READINESS | 🕰 Stale | Predates DR (RTO 0.103s/RPO 0s), soak, load, compliance-burn evidence in PRODUCTION-READINESS.md |
| 16_IMPLEMENTATION_ROADMAP | 🕰 Superseded | docs/PRODUCTION-ROADMAP.md is the live plan |
| CRYPTO_SCAN_DISCOVERY_REPORT | 📷 Snapshot | Honest snapshot; "what is fake" items already addressed in earlier rounds |
| advanced/46 CROSS_BOM | ✅ Addressed | Technology BOM unification (layered exports) |
| advanced/47 UNIFIED_ASSET_IDENTITY | 🟡 Open | Unified identity spec is product-level follow-up |
| advanced/48 CRYPTO_FACT_GRAPH | ✅ Mostly addressed | Graph snapshots + evidence links |
| advanced/49 EVIDENCE_QUALITY | 🟡 Open | Formal authority model = enhancement |
| advanced/50 CONFLICT_RESOLUTION | 🔧 **REMEDIATED** | **UPDATE addendum** — conflict detector built (3 classes) + `GET /findings/conflicts` |
| advanced/51 OBSERVATION_FACT_RISK | 🟡 Open | Layering is design follow-up; conflicts now at least visible (50) |
| advanced/52 DETECTION_ACCURACY | 🔧 Partially remediated | **UPDATE addendum** — hybrid-PQC detection built round 14 |
| advanced/53 NORMALIZATION | ✅ Current | Collision catalogue still valid; conflict surfacing added |
| advanced/54 ASSET_LIFECYCLE | 🔧 **REMEDIATED** | **UPDATE addendum** — lifecycle state machine built (DISCOVERED→…→RETIRED) |
| advanced/55 CRYPTO_OWNERSHIP | 🟡 Open | Single-owner model is a product decision |
| advanced/56 BUSINESS_IMPACT | ✅ Mostly addressed | business_context + system_business_process |
| advanced/57 ATTACK_SURFACE | 🟡 Open | Enhancement |
| advanced/58 EXPOSURE_PATH | 🟡 Open | Enhancement |
| advanced/59 HNDL_PQC | 🔧 Partially remediated | **UPDATE addendum** — hybrid KEM detection + classification fixed round 14 |
| advanced/60 AGILITY | ✅ Current | 6-factor scoring shipped |
| advanced/61 PQC_MIGRATION_DEP | ✅ Mostly addressed | Migration waves/projects shipped |
| advanced/62 REMEDIATION_VERIFICATION | 🔧 **REMEDIATED** | **UPDATE addendum** — full verification loop built round 14 |
| advanced/63 CONTINUOUS_MONITORING | ✅ Mostly addressed | Monitor daemon + webhooks + SSE + report schedules |
| advanced/64 RISK_SCORING | 🟡 Open | Unified cross-score model = enhancement |
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

Detailed engineering evidence: `docs/AUDIT-RECONCILIATION-2026-10-09.md`.
