# BOM Workspaces — UI Product Specification

Six Bill-of-Materials workspaces — SBOM · CBOM · HBOM · NBOM · VBOM · TechBOM — plus the
shared asset-detail page, shared BOM functionality and cross-BOM reconciliation.

Status: authoritative build spec (user-provided, 2026-11-13). The embedded external
screenshots (Fuse Inventory, SBOM Manager, RackPlane, Luna HSM, NetMonitor, vendor-risk
tools, Node Map 3D, Device42, Apptio, Peakworks, QCecuring, ISARA, Fortanix, Palo Alto,
G2, Firefly, WeOps) are look references only — unreachable from the build sandbox and
never data sources.

The rules in this document govern the product. They are internal working rules and are
**not drawn on screen as narration**; they are implemented as behaviour, state
vocabularies and evidence links. Honest state labels and status vocabularies rendered
from the server are operational data, not rule narration.

---

## 1. SBOM UI — Software Bill of Materials

Purpose: Show what software exists, which components it contains and how software
components depend on each other.

Navigation:

- SBOM Overview
- Software Inventory
- Package & Component Explorer
- Dependency Tree
- License Intelligence
- Vulnerability Intelligence
- Version & Lifecycle
- Container SBOM
- Binary SBOM
- SBOM Evidence
- SBOM History
- Export & Validation

Inventory columns:

| Column | Information |
|---|---|
| Component | Package/library name |
| Version | Detected version |
| Ecosystem | npm, PyPI, Maven, Go, OS package |
| Application | Associated software asset |
| Source | Repository, image, binary, import |
| License | Detected license |
| Vulnerability | Linked vulnerability status |
| Evidence | Evidence reference |
| Last observed | Collection timestamp |

Component detail page — when a user clicks a component:

- Component identity and package URL (PURL).
- Version and supplier.
- Direct and transitive dependencies.
- License and vulnerability references.
- Source repository, image or binary.
- Related CBOM cryptographic findings.
- Evidence and collection timestamps.
- Version history and drift.

> **Working rule (not UI copy).** A package existing in an SBOM does not prove that its
> cryptographic algorithms are used at runtime. Link to CBOM findings only when supported
> by evidence.

---

## 2. CBOM UI — Cryptography Bill of Materials

Purpose: Show cryptographic assets, algorithms, libraries, certificates, providers and
evidence of cryptographic usage.

Navigation:

- CBOM Overview
- Cryptographic Asset Inventory
- Algorithm Intelligence
- Crypto Library & Provider Inventory
- Certificate & PKI Inventory
- Key Metadata Inventory
- Cryptographic Operations
- TLS / SSH / IPsec Cryptography
- PQC Readiness
- Crypto Dependencies
- Evidence & Provenance
- CBOM History
- Export & Validation

Inventory columns:

| Column | Information |
|---|---|
| Crypto asset | Unique cryptographic record |
| Algorithm | RSA, AES, SHA-256, ML-KEM etc. |
| Operation | Encrypt, decrypt, sign, verify, exchange |
| Implementation | Library/provider |
| Location | Application, host, endpoint |
| Key metadata | Type, size, parameter set |
| Evidence status | Measured, imported, inferred, unknown |
| PQC status | Assessment state |
| Last observed | Timestamp |

CBOM detail page:

- Algorithm and parameter details.
- Library/provider and version.
- Cryptographic operation.
- Associated software/hardware/network assets.
- Certificate metadata and validity, if collected.
- Key metadata only; never key material.
- Actual evidence and observation method.
- PQC migration relevance.
- Historical changes.
- Linked TechBOM and dependency records.

> **Working rule (not UI copy) — essential status distinction:**
>
> - `capability_detected` — implementation supports an algorithm.
> - `configuration_observed` — algorithm is configured.
> - `operation_observed` — an operation was actually observed.
>
> Do not present these three states as equivalent. A library supporting ML-KEM does not
> prove that the application is using ML-KEM. The three states are rendered as distinct
> operational badges wherever crypto usage is claimed.

---

## 3. HBOM UI — Hardware Bill of Materials

Purpose: Show hardware assets, firmware, hardware security components and physical or
virtual infrastructure dependencies.

Navigation:

- HBOM Overview
- Hardware Inventory
- Servers & Compute
- HSM Inventory
- TPM & Secure Elements
- Network Hardware
- Storage Hardware
- Firmware Intelligence
- Hardware Crypto Capabilities
- Hardware Lifecycle
- Evidence & Provenance
- HBOM History
- Export & Validation

Inventory columns:

| Column | Information |
|---|---|
| Asset ID | Canonical hardware identity |
| Manufacturer | Hardware vendor |
| Model | Device model |
| Serial reference | Masked or bank-controlled identifier |
| Firmware | Version |
| Category | Server, HSM, TPM, storage, network |
| Location | Data center, site or environment |
| Crypto capabilities | Supported hardware features |
| Lifecycle | Supported, end-of-life, unknown |
| Evidence | Source and timestamp |

Hardware detail page:

- Manufacturer, model and device category.
- Firmware and lifecycle status.
- CPU cryptographic acceleration.
- TPM and secure boot capabilities.
- HSM capabilities and approved metadata.
- Hardware dependencies.
- Related CBOM and TechBOM assets.
- Firmware change history.
- Evidence and collection coverage.

> **Working rule (not UI copy).** Do not expose HSM key material, private keys, secrets
> or sensitive device credentials in the HBOM.

---

## 4. NBOM UI — Network Bill of Materials

Purpose: Show network endpoints, protocols, connections and network cryptographic
configuration.

Navigation:

- NBOM Overview
- Network Asset Inventory
- Endpoint Inventory
- Service & Port Inventory
- TLS Intelligence
- SSH Intelligence
- IPsec / VPN Intelligence
- Certificate Exposure
- Network Dependencies
- Network Change History
- Evidence & Provenance
- NBOM History
- Export & Validation

Inventory columns:

| Column | Information |
|---|---|
| Endpoint | Hostname/IP, subject to access policy |
| Port | Observed service port |
| Protocol | HTTPS, SSH, IPsec etc. |
| Service | Identified service |
| TLS version | Observed version, if available |
| Cipher suite | Negotiated/configured evidence |
| Certificate | Certificate reference |
| Source | Collector or approved import |
| First / last observed | Observation history |

Network asset detail:

- Endpoint and service identity.
- Protocol and port.
- TLS/SSH/IPsec observations.
- Certificate metadata.
- Cipher suite and handshake details when actually observed.
- Connection and dependency relationships.
- First and last observation.
- Evidence source and collection method.
- Related CBOM and TechBOM records.

> **Working rule (not UI copy).** A port scan or endpoint inventory alone does not prove
> the negotiated cryptographic configuration. Show `unknown` when the collector cannot
> establish it.

---

## 5. VBOM UI — Vendor Bill of Materials

Purpose: Show which suppliers provide technology and how supplier products affect the
bank's technology and cryptographic estate.

Navigation:

- VBOM Overview
- Vendor Registry
- Vendor Product Inventory
- Supplier Relationships
- Product & Version Lifecycle
- Vendor Security Intelligence
- Vendor Crypto Dependencies
- Vendor PQC Roadmaps
- Supply Chain Exposure
- Contract & Support Metadata
- Evidence & Provenance
- VBOM History
- Export & Validation

Vendor columns:

| Column | Information |
|---|---|
| Vendor | Supplier name |
| Product | Product/service |
| Version | Product version |
| Category | Software, hardware, cloud, service |
| Bank assets | Verified linked assets |
| Support lifecycle | Supported, EOL, unknown |
| Crypto dependency | Known cryptographic dependency |
| PQC roadmap | Confirmed, reported, unknown |
| Evidence | Source and validation |
| Last reviewed | Review date |

Vendor detail page:

- Legal and display name.
- Product and version catalogue.
- Supplier relationship and contract metadata, if authorized.
- Bank assets that use the product.
- SBOM/CBOM/HBOM links.
- Product support and end-of-life status.
- Vendor-published PQC roadmap and evidence.
- Known supply-chain exposure.
- Evidence freshness and approval history.

> **Working rule (not UI copy).** Do not infer that a bank uses a vendor product just
> because that vendor is publicly associated with the bank. Mark publicly reported,
> imported, confirmed and unknown relationships separately.

---

## 6. TechBOM UI — Technology Bill of Materials

Purpose: Give the complete technology-estate view, linking software, cryptography,
hardware, network and vendors.

Navigation:

- TechBOM Overview
- Technology Inventory
- Application & Service Registry
- Infrastructure Inventory
- Technology Layers
- Six-BOM Reconciliation
- Technology Relationships
- Lifecycle Intelligence
- Evidence & Provenance
- TechBOM History
- Export & Validation

Technology inventory columns:

| Column | Information |
|---|---|
| Asset ID | Canonical ID |
| Asset name | Technology or system name |
| Category | Software, hardware, network, cloud etc. |
| Vendor | Manufacturer/provider |
| Product/version | Technology details |
| Environment | Production, UAT, development |
| Related BOMs | SBOM/CBOM/HBOM/NBOM/VBOM |
| Dependencies | Verified relationship count |
| Evidence | Evidence quality/status |
| Last observed | Timestamp |

TechBOM provides the cross-estate entry point. Clicking an asset opens the same
canonical asset in all six BOM views where applicable.

---

## 7. Shared asset detail UI

One of the most important screens. Every BOM record follows a consistent detail-page
structure.

Header record (example — the example relationships below are illustrative, not claims
about an actual payment application):

- `ASSET-0001` — Example technology asset — Verified example — Payment API Server —
  Production — TechBOM — SBOM linked · CBOM linked

Asset information fields: Asset ID · Environment · Category · Owner · Source ·
Last observed.

Cross-BOM relationships panel: SBOM · CBOM · HBOM · NBOM · VBOM · TechBOM — each shown
as linked / not established / unknown / primary record, never conflated.

Detail tabs:

- Overview
- Components
- Cryptography
- Hardware
- Network
- Vendors
- Dependencies
- Evidence
- History

---

## 8. Shared BOM functionality

Every BOM uses the same interaction patterns so users do not have to learn six
different interfaces.

| Shared feature | Expected behaviour |
|---|---|
| Search | Search by asset, component, vendor, version and ID |
| Filters | Environment, source, type, owner, status |
| Sorting | Name, version, freshness, risk |
| Asset detail | Open canonical asset record |
| Evidence | Inspect source, timestamp and digest |
| History | Compare snapshots and changes |
| Relationships | Open verified dependency paths |
| Export | Export authorized BOM records |
| Reconciliation | Identify duplicate, unmatched and conflicting records |
| Coverage | Show what was collected and what was not |
| Access control | Enforce bank roles and asset scope |

Evidence status vocabulary — one common vocabulary across the BOMs:

- **Measured** — directly observed by an authorized collector.
- **Imported** — supplied by an approved external source.
- **Inferred** — derived from indirect evidence and requires validation.
- **Unknown** — evidence is insufficient.
- **Contradicted** — available sources disagree.

Also display collection freshness: current, stale, expired or not collected, based on an
explicit policy. Do not use a generic green status to imply that an asset is secure.

---

## 9. Cross-BOM reconciliation UI

This is where the six BOMs become much more useful than six isolated inventories.

Reconciliation screens:

1. Duplicate asset detection.
2. Unmatched SBOM components.
3. CBOM assets without a mapped software or hardware owner.
4. HBOM devices without an approved system mapping.
5. NBOM endpoints without a known service owner.
6. VBOM products without a verified bank-asset relationship.
7. Conflicting versions and metadata.
8. Missing evidence.
9. Stale BOM records.
10. Cross-BOM relationship validation.

Example (working rule, not UI copy): a cryptographic library appears in the SBOM, while a
CBOM finding identifies AES support in that library. The reconciliation engine connects
them only if the evidence establishes the relationship. It must not assume that the
application actually performs AES operations.
