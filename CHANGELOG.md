# Changelog

All notable changes to CryptoScan / ZELNX. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
git-tagged from `VERSION`.

## [Unreleased]

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
