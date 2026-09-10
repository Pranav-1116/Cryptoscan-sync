# Changelog

All notable changes to CryptoScan / ZELNX. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are
git-tagged from `VERSION`.

## [Unreleased]

(nothing yet)

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
