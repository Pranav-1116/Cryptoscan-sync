# Documentation status and coverage map

**Review date:** 2026-10-16
**Repository:** CryptoScan
**Purpose:** identify which documentation is authoritative, which material is historical, and which product areas still require evidence or deeper guides.

This file is a navigation and documentation-quality control. It is not a
production approval, customer certification, legal commitment, or claim that
every documented capability is generally available.

## 1. Repository-wide inventory

The `docs/` tree currently contains **346 files**, including **286 Markdown
files**, plus generated diagrams, JSON/CSV evidence, templates, and scoped
qualification artifacts. The files cover product behavior, architecture, user
workflows, deployment, security, operations, company diligence, commercial
planning, and historical evidence.

Counts are a documentation snapshot. They should be regenerated rather than
copied into a product claim when files change.

## 2. Source-of-truth order

When two documents disagree, use this order:

1. **Running code, tests, and API schemas** for behavior.
2. **`shared_models/capability_maturity.py` and generated
   `docs/CAPABILITY-MATURITY.md`** for GA/Beta/Preview labels.
3. **`frontend/src/components/Layout.tsx` and `frontend/src/App.tsx`**, with
   `docs/NAVIGATION-FEATURE-REFERENCE.md` updated in the same change, for
   navigation and route coverage.
4. **`docs/api-reference/rest-api.md`** for the generated API snapshot. Its
   header contains the generation date and count; it is not a promise that an
   old snapshot contains later endpoints.
5. **Root `PRODUCTION-READINESS.md` and
   `docs/readiness-evidence/bank-readiness.{json,md}`** for the current
   evidence gate.
6. **`docs/PRODUCT-CAPABILITIES-END-TO-END.md`, product manuals, and
   `docs/PLATFORM-STATUS.md`** for explanatory context. Historical updates in
   those files must retain their original date and commit context.
7. **Market, pricing, roadmap, pilot, company, and policy documents** for
   planning or templates. They must not be read as proof of revenue, valuation,
   certification, customer count, market share, or production qualification.

The current API reference snapshot is generated on **2026-09-25** and reports
**659 paths / 725 operations** across 86 tagged groups. The current maturity
snapshot reports **33 GA, 30 Beta, and 10 Preview surfaces** (73 classified
console surfaces). The dates and scope matter: do not merge historical counts
with the current snapshot.

## 3. Documentation family map

| Family | Entry point | Coverage |
|---|---|---|
| Product narrative | [product/README.md](product/README.md) | Product thesis, features, architecture, dataflow, scan trace, engines, glossary, readiness |
| Cryptography Threat Intelligence | [product/cryptography-threat-intelligence-roadmap.md](product/cryptography-threat-intelligence-roadmap.md) | Current foundation; planned intelligence, detection, response, defence, and research boundaries |
| Market and commercial | [market/global-cryptography-threat-intelligence-market-value.md](market/global-cryptography-threat-intelligence-market-value.md), [business-model.md](business-model.md), [price-model.md](price-model.md) | Market context, customer value, illustrative pricing/revenue, valuation boundaries and commercial assumptions |
| User workflows | [user-guide/](user-guide/) | Scanning, inventory, CBOM, PQC, certificates, cloud, binary, network, vendor, evidence, reports and operations |
| Vendor/network evidence | [user-guide/vendor-network-inventory.md](user-guide/vendor-network-inventory.md) | Versioned vendor profiles, network inventory sections, endpoint lifecycle, provenance, tenant isolation and no-secret rules |
| Administration | [admin-guide/](admin-guide/) | Installation, production, air-gap, hardening, policy, scanners, backup/restore, integrations and system configuration |
| Architecture and decisions | [architecture/](architecture/), [decisions/](decisions/) | Service boundaries, dataflow, evidence, tenancy, scanners, BOMs, graph, roadmap and ADRs |
| API and developer | [api-reference/rest-api.md](api-reference/rest-api.md), [plugin-sdk.md](plugin-sdk.md), [dev/](dev/) | Generated API snapshot, plugin extension, testing, live scanning and developer workflows |
| Security and privacy | [security/](security/), [company/security-architecture.md](company/security-architecture.md), [company/privacy-documentation-index.md](company/privacy-documentation-index.md) | Threat model, hardening, network controls, dependency audit, privacy and assurance material |
| Operations and qualification | [operations/](operations/), [ops/](ops/), [runbooks/](runbooks/), [production-qualification-runbook.md](production-qualification-runbook.md) | Production procedures, vendor due diligence, scanner qualification, recovery, DR, telecom, monitoring and support |
| Readiness evidence | [readiness-evidence/README.md](readiness-evidence/README.md), [root production gate](../PRODUCTION-READINESS.md) | Timestamped PASS/FAIL/SKIP artifacts; synthetic or skipped checks are not approvals |
| Pilots and adoption | [pilot-standard.md](pilot-standard.md), [pilot-duration-and-phases.md](pilot-duration-and-phases.md), [poilet/README.md](poilet/README.md), [proposals/](proposals/) | Pilot scope, acceptance, market entry, first customers, demo and engagement material |
| Company and compliance | [company/README.md](company/README.md), [compliance/](compliance/), [enterprise-readiness.md](enterprise-readiness.md) | Templates, questionnaire answers, control mappings, external-readiness gaps and boundaries |
| Accuracy and validation | [accuracy/](accuracy/) | Detector benchmarks, external validation, synthetic estate results and bank-readiness limitations |

## 4. Gaps identified by the documentation review

### 4.1 Route and maturity reconciliation

The primary **`/vendor-due-diligence`** route now has an explicit generated
**Preview** row in the maturity inventory. Its profile/provenance machinery is
implemented, but approval completeness and external vendor qualification remain
unverified; it must not be described as GA.

### 4.2 Structured vendor and network workflows

The generated API reference snapshot predates or does not enumerate the
structured network-inventory endpoint family. The dedicated
[user guide](user-guide/vendor-network-inventory.md) now documents the vendor
profile and network inventory contracts while the API reference is regenerated.
The implementation still requires authorized sources, evidence, tenant scope,
and reviewer qualification; a schema or endpoint is not proof of complete
network visibility or vendor assurance.

### 4.3 Cryptography threat detection and defence

CBOM, PQC, policy, drift, evidence, vendor context, and deterministic
correlation form the current foundation. Cryptography-specific threat feeds,
attack-path analysis, cryptographic abuse detection, autonomous blocking,
response orchestration, and continuous cryptographic defence remain planned or
research capabilities in the roadmap. They must not be described in user guides
as shipped detections.

### 4.4 External assurance and customer evidence

The repository contains controls, tests, templates, and qualification runbooks.
It does not by itself establish ISO 27001 or SOC 2 attestation, independent
penetration testing, multi-site DR, 24/7 support, customer count, customer ROI,
market share, or a current CryptoScan valuation. The company, customer, and
qualified assessor still own those actions.

### 4.5 Historical evidence needs dates

Load tests, soak runs, dependency audits, product-surface audits, readiness
reports, and market reports are time-scoped. Keep the original date and result;
add a newer dated artifact rather than silently rewriting an old pass/fail record.
Historical documents that contain obsolete counts should link back to the current
source of truth and label the old measurement as historical.

## 5. Required documentation invariants

All new or updated docs must preserve:

- no fabricated scanner, vendor, certification, incident, financial, customer,
  compliance, production, or ROI claims;
- explicit `UNKNOWN`, `UNVERIFIED`, `INCOMPLETE`, `STALE`, `UNAVAILABLE`, and
  `SKIP` states where evidence is missing;
- evidence provenance, capture time, source, hash, limitation, and reviewer
  where applicable;
- tenant isolation for reads, writes, history, exports, and events;
- no passwords, tokens, credentials, private keys, raw secrets, or key material
  in profiles, CBOMs, logs, examples, or evidence artifacts;
- safe, authorized, approval-gated production actions with rollback evidence;
- clear separation between shipped behavior, planned roadmap, research, and
  external/company actions;
- links to the current readiness gate when quoting production status.

## 6. Documentation update procedure

When a capability changes:

1. Update the code and tests first.
2. Regenerate the API reference and capability-maturity output from the running
   application/source-of-truth scripts.
3. Update the navigation reference if a route or sidebar item changed.
4. Update the relevant user guide, admin/runbook, architecture, and enterprise
   documentation, not only the release note.
5. Add or update evidence under `docs/readiness-evidence/` with a timestamp and
   explicit PASS/FAIL/SKIP result.
6. Run a repository-local Markdown link check and `git diff --check`.
7. Review claims for tenant scope, provenance, no-secret behavior, unknown
   handling, and production qualification before publishing.

The documentation index is [docs/README.md](README.md). This status file should
be updated when a review discovers a new family, source-of-truth conflict, or
material documentation gap.
