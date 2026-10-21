# CryptoScan — end-to-end product capabilities

**2026-10-21 correction:** the numerical table below is a dated snapshot, not a
current census or production claim. The regenerated [API reference](api-reference/rest-api.md)
now reports **848 paths / 936 operations / 103 groups**. Current queue authority,
durable SSH and TLS/Sentinel replay controls are summarized in the
[API contract companion](api-reference/execution-and-replay.md); production
acceptance remains the [root gate](../PRODUCTION-READINESS.md).

**What this is:** the whole product described as one loop, from connecting an
environment to producing a signed, regulator-ready artefact — with the code,
endpoint or console page that implements each step.

**Historical repository snapshot** (2026-09-25; not recounted by this refresh):

| | |
|---|---|
| Backend services | **51** packages under `services/` |
| REST surface | **659 paths / 725 operations** across **86 tagged groups** in the 2026-09-25 API snapshot (`docs/api-reference/rest-api.md`; regenerate after API changes) |
| Console | **74 page components / 73 classified surfaces** in **6 sidebar sections**, with **31 menu slots / 30 unique primary routes** (`frontend/src/components/Layout.tsx`, `frontend/src/App.tsx`) |
| Database migrations | **59** (`services/database/migrations/versions`) |
| Tests collected | **4,808** backend test functions, plus frontend tests and live qualification suites |
| Docs | **270** Markdown files plus generated diagrams, JSON/CSV evidence and templates |
| Localisation | English + Arabic, **217 keys each** (`frontend/src/i18n`) |

Every capability below is marked **shipped** · **partial** (gap stated) ·
**external** (not code — a company action). Nothing is listed that a reader
cannot exercise, and no page or endpoint fabricates data: panels render
zeros/empty/offline until a real scan produces evidence.

---

## The loop, stage by stage

### 1. Onboard and scope — "what am I responsible for?"

Connect a customer environment and declare what is in scope. Everything later is
filtered by this.

* **Console:** `Discovery` (`/onboarding`) first-run wizard — create organisation,
  add environments, define scope, add connectors (GitHub, cloud, network,
  scanner agents), test credentials, launch a first discovery scan.
* **API:** `onboarding`, `scope`, `systems`, `assets`, `sectors` groups.
* **Sector profiles** (`services/sector_profiles`) select banking / telecom /
  oil-and-gas / government baselines, which drive the rule packs used later.
* **Produces:** an organisation, environments, a scope grant, and connected
  credentials — the filter every subsequent stage respects.

### 2. Collect — getting cryptography out of everything

Eleven kinds of input feed one inventory. Every collector is read-only and
deterministic; where a target is unreachable it reports that honestly instead of
inventing a finding.

| Collector | What it finds | Where |
|---|---|---|
| **Source code** | hardcoded keys, PEM material, weak primitives, key sizes, secrets misuse — Python, Java, C#, JavaScript/TypeScript, Go, Rust plus Kotlin, PHP, Ruby, config/IaC | `services/scanner`, worker pipeline |
| **SBOM / dependency graph** | manifests + **10 lockfile formats** → resolved/transitive components, licences, crypto libraries | `services/devsecops/devsecops/sbom_scan.py`, `sbom_lockfiles.py` |
| **Network / TLS** | live TLS endpoints, protocol+cipher posture, certificate chains, STARTTLS | `services/network_scanner` |
| **Certificates** | inventory, expiry, chain validation + full lifecycle (CSR → issue → renew → revoke) | `services/api` certificates group, `Certificates` page |
| **Cloud** | AWS KMS, Azure Key Vault, GCP Cloud KMS key metadata; AWS ACM certificates (fingerprint = real SHA-256 of the DER) | `services/cloud_scanner` |
| **Binaries / firmware** | **real bounded parsing, not name matching**: ELF (deps, RPATH, build-id, compiler, symbols, Go build-info + module graph), PE, Mach-O, `ar`/`.deb`, jars/wheels/nupkgs, WASM, Android binary XML, iOS `Info.plist`, firmware container chains + device-tree identity — graded crypto evidence and correlated SBOM/CBOM/HBOM/static-NBOM/VBOM/vulnerability views | `services/devsecops/devsecops/binary_scan.py`, `services/devsecops/devsecops/binary_boms.py`, `POST /devsecops/binary/scan` |
| **Containers / IaC** | image and filesystem package inventory, crypto binaries, Dockerfile/IaC rules | `services/container_scanner`, `container_scans` group |
| **OT / ICS** | **passive — zero packets sent**; PLC/RTU/SCADA crypto posture | `services/ot_scanner`, `services/ot_safety` |
| **Telecom** | 5GC / EPC / IMS / roaming verdicts, SEPP PQC readiness, per-carrier packs, closed-network ingest | `services/telecom_scanner` |
| **Telecom — 5G crypto configuration** | the parts of TS 33.501 no external probe can reach, where the permissive setting looks healthy in service: SUPI concealment (null-scheme = IMSI-catcher exposure), NEA/NIA air-interface algorithms (NEA0 ahead of NEA2 defeats configured AES), N32 roaming (TLS vs PRINS against the IPX topology), MILENAGE/TUAK sets (XOR test algorithm, OP-vs-OPc), and the K → K_AUSF → K_SEAF → K_AMF → K_gNB hierarchy | `suci.py`, `air_interface.py`, `n32.py`, `authentication.py`, `key_hierarchy.py` |
| **Hardware** | HSMs, TPMs, firmware, vendors — the hardware root of trust software scanning cannot see | `services/universal_crypto`, `hardware` group |
| **Payment** | HSM key inventory, TR-39-style ceremony provenance, dual custody, PCI-relevant attributes | `services/payment_crypto` |
| **Payment — card standards** | TR-31/X9.143 key-block headers; **ISO 9564** PIN-block formats (format 2 online, formats 1/2 not PAN-bound, the TDES→AES-format-4 backlog); **ISO 8583** field-level crypto from the declared data elements (52 PIN, 55 EMV, 64/128 MAC — a PIN-bearing link with no MAC field); **EMV/ARQC** cryptogram lifecycle keyed on the CVN (CVN 10 derives session keys without the ATC, so every transaction on a card uses the same key). Declarations only — the analysers refuse input that looks like a PIN block or an IMK | `keyblocks.py`, `pinblocks.py`, `iso8583.py`, `emv.py` |
| **Runtime hosts** | live hosts and runtime findings | `services/runtime`, `Runtime` page |

Registry push events (ACR/GCR/ECR/Harbor/Docker Hub style) arrive through one
authenticated webhook (`api/routers/webhooks.py::container_registry_webhook`),
fail-closed on a bad signature.

### 3. Normalise and deduplicate — one asset model

Raw findings from eleven collectors become one canonical Technology BOM model
(`shared_models`), so a key seen by the cloud collector and by code scanning is
**one asset with two evidence sources**, not two rows.

* **Services:** `normalization`, `deduplication`, `correlation`
  (every judgement is a formula — no AI), `business_context` (impact enrichment).
* **Produces:** the unified crypto-asset store + findings, which every page and
  report reads from.

### 4. Inventory and BOMs — the single source of truth

| View | What it answers | Where |
|---|---|---|
| **Asset & CMDB** | all assets, activity feed, unified risk score | `/cmdb` |
| **Crypto assets / libraries / protocols** | what cryptography is where, by primitive | `/crypto-assets`, `/libraries`, `/protocols` |
| **CBOM** | CycloneDX-style cryptographic bill of materials, versioned + fingerprinted | `/cbom`, `services/cbom` |
| **HBOM / VBOM** | hardware and vendor bills of materials | `/hbom`, `/vendor` |
| **NBOM** | network bill of materials from authorized network scans, plus a distinct static binary capability view. Binary-derived candidates are explicitly `observed: false`; imported socket/TLS APIs do not prove a live endpoint | `/nbom`, `/dev-sec-ops`, `services/cbom/cbom/nbom.py`, `services/devsecops/devsecops/binary_boms.py` |
| **Vulnerability BOM** | separate normalized findings view for binary weak/deprecated algorithms, hardening failures, malformed/truncated/refused artifacts and supplied package/library matches; “no evidence” is not “not vulnerable” | `/dev-sec-ops`, `/devsecops/binary/artifacts/{id}/bom/vulnerability-bom` |
| **SBOM** | software bill of materials for any artifact, with licence + VEX + gate (see §6) | `/dev-sec-ops` → SBOM |
| **Dependency graph** | component/system relationships, blast radius (Neo4j when configured, in-process otherwise) | `/graph`, `services/graph_engine` |
| **Live asset intelligence** | build-time vs live view of the same estate | `/live-asset-intelligence` |

### 5. Assess — turn inventory into posture

* **Policy engine** (`services/policy`) — YAML rule packs; **policy is the only
  source of pass/fail**. Deterministic, no model decides compliance.
* **Risk** — scoring and prioritisation (`services/api` risk/priority groups,
  `Priorities` page).
* **Drift** (`services/drift`) — baseline vs observed; every change is surfaced,
  not silently absorbed.
* **PQC readiness** (`services/quantum`) — NIST IR 8547-aligned migration
  buckets, harvest-now-decrypt-later exposure, `/pqc`, `/pqc-map`.
* **Crypto agility** (`services/agility`) — what-if simulation of algorithm
  migration before committing to it.
* **Crypto assurance** (`services/compliance`) — JWS-signed attestations over a
  snapshot, so a CISO's statement is verifiable later.
* **Exceptions & waivers** — time-boxed, approved, audited (never a silent
  suppression).

### 6. The SBOM supply-chain gate (recent build-out)

The scanner answers five questions end to end:

1. **What is in this build?** `POST /devsecops/sbom/scan` — source tree or
   container → CycloneDX 1.5 / SPDX 2.3, merging **10 lockfile formats** for the
   real resolved/transitive graph (demo tree: 3 declared → **11 components, 5
   direct / 6 transitive, 5 edges**).
2. **Is it complete enough to trust?** NTIA minimum-elements scoring
   (`/sbom/validate`, on every scan) — honest gaps named, never invented; a
   supplier document scoring 5/7 is told exactly which two elements are missing.
3. **Is it safe to ship?** Offline advisory matching against a feed you supply
   (`pip→pypi`, `go→golang`, `gradle→maven`, …) plus a **gate** with
   critical/high allowances, denied licences, unpinned limits and a signature
   requirement. `python -m devsecops.sbom_gate` blocks a pipeline with exit codes
   **0/1/2/3** — a gate behind an authenticated API cannot stop a build.
4. **What do the licences say?** Grouped by SPDX id, family-aware matching
   (a policy banning `GPL-3.0-only` catches `GPL-3.0-or-later`), undeclared
   reported as undeclared, and a copyleft **review trigger** worded as a policy
   flag — not a compatibility ruling.
5. **What are we doing about each advisory?** CycloneDX **VEX** statements:
   matched advisories are `exploitable` with their fix; `not_affected` requires
   a justified operator statement or a provably absent component (an unjustified
   one is refused 422); authoring needs an operator role.

Plus provenance: every artifact stores its bytes, sha256 and an HMAC manifest
signature, re-verified by `/sbom/{id}/verify` (tamper drill: byte flip and
manifest edit both detected, repair returns OK, and an artifact signed before a
restart still verifies after it). Cross-artifact queries answer "where is this
component used?" and "what does this CVE affect?", counting only artifacts that
were actually matched against a feed.

### 7. Enforce — stop bad change at the pipeline

* **CI gate** (`scripts/ci_gate.py`, `services/api` ci group) — profiles,
  SARIF 2.1.0 for GitHub code scanning, PR-comment markdown, blocked-deployment
  statistics.
* **SBOM gate** — CLI + API (§6).
* **Scanning policy / scope authorisation** — who may scan what.
* **Governance** (`services/governance`) — rule-based approvals, migration
  approval gates, dual custody for ceremonies.

### 8. Automate and remediate

* **Automation engine** (`services/automation`) — deterministic WHEN/IF/THEN
  plans with safety tiers and **fail-closed approval gates**; nothing fires
  without the required human authorisation.
* **Playbooks** — certificate rotation, network-function-down, crypto-team
  notify (including telecom NF-unreachable).
* **Remediation** (`services/remediation`) — deterministic suggestions, work
  orders; **never a compliance determination**.
* **SLA tracking** (`services/sla`) — remediation deadlines by severity.
* **Delivery integrations** — ServiceNow incidents (stable `correlation_id`,
  idempotent on retry), Splunk HEC, Jira (REST v3, ADF descriptions), Microsoft
  Sentinel (documented SharedKey signature). Preview endpoints build the exact
  payload before anything is sent; tokens never leave the process.
* **Event bus + realtime** (`services/eventstream`) — SSE, cooldown dedup,
  recoveries that do not spam.

### 9. Evidence, audit and resilience

* **Evidence packs** (`services/evidence`) — hash-manifested exports; the
  manifest is the proof, not the prose.
* **Hash-chained audit trail** — every auth/admin action recorded,
  chain-verifiable (incremental verification is ~213× faster than a full walk).
* **Audit export** — examiner-ready ZIP, deterministic JSON + SHA-256 manifest.
* **Audit pack / exit report / engagement archive** — the three hash-sealed
  engagement deliverables.
* **WORM retention gate** (`services/compliance`) — append-only stores refuse
  truncation/deletion.
* **Signing** — JWS (RFC 7515) over attestations and CBOMs; `/trust` surfaces key
  material provenance.
* **Resilience** (`services/api` resilience group) — backup/restore and PITR
  drills with recorded results; air-gap mode (JWKS-from-file, feed import, no
  phone-home).

### 10. Report, attest and operate

* **Compliance reports** — eight templates (`services/reporting/report_templates.py`):
  **PCI-DSS 4.0, DORA, NIST SP 800-131A r2, FIPS 140-3, SOC 2, ISO/IEC
  27001:2022, NIST SP 800-53 r5, UAE PDPL** + custom requirement selection.
  Frameworks without a native rule pack are explicitly *mapped* and say so.
* **Regulatory packs** — banking action plan (ECB/FCA-framed), NRA per-carrier
  (json/csv), supervisor pack (hash-manifested); Kuwait/UAE regulatory mappings.
* **Export & distribution** — PDF export, scheduled reports, SMTP delivery that
  reports "not delivered" when SMTP is unconfigured rather than pretending.
* **Dashboards** — Command center, Executive view, Role workspace (CISO /
  analyst / OT engineer), Security centre.
* **Localisation** — English + **Arabic RTL** for regulatory submissions.

**Operating the platform itself:** local auth + TOTP MFA, OIDC SSO (token relay,
authorization code, RFC 7636 PKCE for public clients), SAML 2.0 SP with
enveloped-signature verification, LDAP/AD group→role mapping, SCIM 2.0
provisioning, 9-role RBAC with fail-closed checks, scoped machine API keys,
tenant model with provisioning/invites, Prometheus metrics, `/healthz` +
`/readyz` with drain semantics, SLOs and self-alerting — all in
`docs/enterprise-readiness.md`.

---

## Domain coverage at a glance

| Domain | Status |
|---|---|
| Code, SBOM, containers, network, certificates, cloud, hardware, payment, telecom, OT, runtime | shipped |
| CBOM / HBOM / VBOM / SBOM + dependency graph | shipped |
| Binary BOM bundle: static NBOM, vulnerability BOM and correlated technology snapshot | shipped for supervised pilot / pre-production evaluation; bounded evidence and tenant-scoped sidecars |
| NBOM + per-component blast radius | shipped for authorized network evidence; static binary candidates remain `observed: false` until corroborated |
| Policy, risk, drift, PQC, agility, assurance | shipped |
| CI/CD + SBOM gates, automation, remediation, SLA | shipped |
| Evidence, audit chain, WORM, JWS signing, DR drills | shipped |
| Reports (8 frameworks), regulatory packs, Arabic RTL | shipped |
| SSO/MFA/LDAP/SCIM/RBAC/API keys, metrics, air-gap | shipped |
| Database TDE / mainframe (RACF, ICSF) collectors | **not built** — needs customer-environment adapters |
| Qualys / ServiceNow VR / Jira Server connectors | **not built** — same connector pattern, on demand |
| Multi-active HA control plane | **partial** — readiness drains + read-only mirrors designed, multi-active untested without real infra |
| Managed multi-tenant SaaS operations | **not claimed** — tenant model ships; running it as a service is a product decision |
| ISO 27001 / SOC 2 attestation of this product | **external** — controls implemented and auditable in-repo; the audit is a company action |
| Independent penetration test, real multi-site DR, 24/7 on-call | **external** |

## Honest engineering rules the product follows

1. **No AI decides compliance.** Every verdict is a formula, a rule pack or a
   recorded human approval.
2. **Unknowns are reported, never guessed.** Unknown algorithm, undeclared
   licence, unparsable documh is surfaced with a
   reason.
3. **Unchecked ≠ clean.** An SBOM with no advisories says whether a feed was
   applied; an unreachable registry returns "unavailable", not a pass.
4. **Every claim is verifiable.** Hashes, signatures, chain links and manifests
   can be re-checked after the fact by someone who does not trust the platform.

## Where to read deeper

| Doc | For |
|---|---|
| `docs/NAVIGATION-FEATURE-REFERENCE.md` | current six-section console navigation, primary/deep-linked routes, role-guarded actions and feature ownership |
| `docs/product/02-features.md` · `docs/user-guide/binary-firmware-scanning.md` | correlated binary BOM family and bounded binary/mobile/WASM behavior |
| `docs/END-TO-END-ARCHITECTURE.md` · `docs/DATAFLOW.md` | how data moves between services |
| `docs/enterprise-readiness.md` | capability matrix with honest gaps |
| `docs/PLATFORM-STATUS.md` | every planned capability vs what ships |
| `docs/user-guide/sbom-supply-chain-gate.md` | the SBOM gate end to end |
| `docs/architecture/sbom-scanner-architecture.md` | SBOM target architecture vs this repo |
| `docs/api-reference/rest-api.md` | 725 operations in the 2026-09-25 generated snapshot; later endpoints must be regenerated into the reference |
