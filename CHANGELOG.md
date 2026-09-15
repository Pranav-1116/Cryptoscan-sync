# Changelog

All notable changes to CryptoScan / ZELNX. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
git-tagged from `VERSION`.

## [Unreleased]

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
