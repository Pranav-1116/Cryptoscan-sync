# The original45: implementation gaps, not a completed-capability score

**2026-10-24 — follow-up to the bank's correction.** The previous pass mainly
made claims safer. Mapping45 questions and adding12 questions did **not** build
all45 capabilities. This follow-up changes executable export, classification,
accuracy, API and existing-screen behavior, and provides an actual synthetic
CBOM/report. It still does not make the original questionnaire fully satisfied.

## Subsequent bounded implementation

[Controlled historical CBOM decisions](controlled-historical-cbom.md) now handle
unassigned and mixed-source histories in the existing screen/API, and
[qualification evidence corrections](qualification-evidence-boundaries.md)
include actual disposable PostgreSQL/Redis execution. Neither update closes the
original45 or supplies independent bank acceptance. Historical evidence below
remains tied to its original increment, not silently refreshed.

The subsequent [scoped rescan inspection](scoped-rescan-inspection.md) checks actual
local-source job/receipt/content commitments in the existing CBOM panel. It does
not supply a complete independent denominator, clear partial histories, qualify
runtime discovery or close the remaining platform/migration/acceptance gaps.

The subsequent [worker dispatch repair and drill](worker-dispatch-boundaries.md)
reproduces and fixes memory-only outbox publication and expiring drain leases.
An actual API-created development job now runs through real Redis and a fresh
worker into PostgreSQL evidence; controlled dispatch remains fail-closed without
a provisioned isolation runtime. This narrows parts of D2/I2/I4, not all45:
controlled execution success, deployed security/recovery/capacity, complete
six-BOM coverage and independent bank acceptance remain open.

The [long-running worker-pool repair](worker-pool-lifecycle.md) additionally
bounds completion bookkeeping and prevents cancelled queued work from permanently
consuming local slots, without allowing cancel/resubmit to bypass queue limits.
This is a bounded resource/liveness correction, not representative bank scanner
capacity or p95/p99 qualification. Redis atomic orphan recovery remains open.

## Implemented in this follow-up

| Original question | Actual implementation change | Evidence |
|---|---|---|
| O1: standard CBOM | Native1.6 JSON metadata profile; full pinned upstream schema and offline reference validation; malformed/duplicate/dangling references refused | `services/cbom/tests/test_cyclonedx16.py` |
| O4: business context | Application/owner/classification/retention properties from supplied records and persisted systems; shared assets have one reference and multiple declared contexts | `services/api/tests/unit/test_bank_native_cbom.py` |
| O5: dependency meaning | Native record conversion does not invent dependency links from inventory membership; selected-system exports include tenant-visible neighboring components and preserve edge direction | Same API tests and native CBOM tests; not replacement-interoperability evidence |
| M4: measurement | Undefined legacy triage precision/recall/F1 stay null; FPR is unavailable without true negatives; invalid workbooks return422; CLI no longer calculates a different answer or crashes on null | `test_field_accuracy_denominators.py`, `test_field_accuracy_api.py` |
| M5/R1: algorithm parameters | Catalog byte lengths distinguished from bits; all12 full FIPS205 SHA2/SHAKE variants recognized; native parameter identifiers not confused with public-key byte counts | `shared/shared_models/tests/test_bank_pqc_parameters.py` |
| R1: conservative policy | FN-DSA/Falcon/HQC/McEliece names do not become approved policy merely because a catalog describes a draft, selection or family | Same registry tests; no claim about latest publication state |
| D1/D2: safe exports | Native profile excludes raw snippets/key values/arbitrary detector payloads; both scan CBOM export paths obey quarantine; tenant filters remain in place | Native/API tests with actual tenant sessions |
| I4/G2: usable output | Existing CBOM button downloads a validated CBOM rather than catalog JSON; existing CLI supports explicit native1.6 JSON; actual synthetic CBOM/report committed | Frontend download regression and [example](../examples/bank-pqc-discovery/README.md) |
| M4: screen truth | Existing Accuracy screen shows missing metrics as unmeasured, averages only defined metrics, and does not equate corpus results with bank-wide/deployed PQC qualification | `frontend/src/pages/Accuracy.truth.test.tsx` |
| O2/O3: planning language | Migration summary separates migration-review candidates from Shor-only claims; Mosca prose also describes an assumption rather than an estimated arrival forecast | `services/quantum/tests/test_plan.py` |

No new dashboard, collector or service was created. Existing compatibility
exports remain available; they have not been retroactively schema-qualified.

## Every original question still has a specific closure requirement

**Local change** means this follow-up changed a bounded part, not that the whole
question is satisfied. **Not requalified** means existing code was previously
mapped, but this pass did not establish that capability across bank platforms.
**External facts** cannot be supplied by writing code. There is intentionally no
percentage complete, no claim that45 features were built, and no bank approval.

| ID | Original question | This pass | Remaining engineering or acceptance requirement |
|---|---|---|---|
| S1 | Certificates, keys, libraries, TLS/SSH/IPsec/SAML, code, HSM, DB, API, cloud | Not requalified | Protocol/platform/version matrix; end-to-end positive/negative discovery cases; explicit unsupported combinations. Metadata adapters are not proof of negotiated use. |
| S2 | On-prem, multicloud, SaaS, z/OS/COBOL, legacy/EOL | Not requalified | Actual permitted platform/version/access tests, platform owners and denied-access outcomes; do not call arbitrary SaaS or z/OS covered. |
| S3 | Vendor-embedded core banking, payment, SWIFT/card crypto | Not requalified | Product/version-specific sanctioned exports or instrumentation; observed-vs-supplier-declared evidence per finding. |
| S4 | OT/IoT, ATM, POS, appliances | Not requalified | Owner-approved method and fragile-device lab; passive/export preference; witnessed stop/no-disruption tests. |
| S5 | Hardcoded keys, proprietary crypto, compiled binaries | Not requalified | Ground-truth corpus across architectures, packers, stripped/static binaries and wrappers; secret-handling validation. Binary indicators are not universal recovery. |
| M1 | Agent, agentless, network, SAST and binary methods | Not requalified | Reproducible method/access matrix and supported deployment/runtime combinations, not just a list of modules. |
| M2 | Crypto in transit, at rest and code | Not requalified | Per-source provenance and actual channel/storage/use evidence; configuration and names must not become observed execution. |
| M3 | Segmented/encrypted/opaque traffic | Not requalified | Authorized vantage points, exports and exclusions; unreachable/opaque cases remain unknown, not clean. |
| M4 | False-positive/false-negative rates and validation | Local change | Bank-approved independent/frozen denominator and held-out exercise; precision is not FPR. Legacy review units are not all-estate recall. |
| M5 | Algorithm, key length, mode and quantum classification | Local change | Field-level ground truth, units and source evidence across every collector; byte/bit correction does not requalify all consumers or observed usage. |
| M6 | Actual hybrid/PQC usage such as ML-KEM TLS | Not requalified | Captured negotiated groups and permitted runtime checks, downgrade/negative cases and implementation versions. A recognized hybrid name is not an observed handshake. |
| O1 | CycloneDX CBOM | Local change | Independent consumer interoperability and bank export acceptance; full native XML and arbitrary certificate/material document conversion remain outside this profile. |
| O2 | Sensitivity, shelf life, HNDL, exposure and criticality | Local change, prose only | Bank-approved scoring assumptions, input quality, sensitivity validation and decisions. Existing heuristic scores are not calibrated bank risk. |
| O3 | Mosca inequality | Local change, prose only | Agreed threat scenarios and measured migration effort; no forecast or invented legal deadline. |
| O4 | Applications, owners and classifications | Local change | Authoritative CMDB/owner reconciliation, classification review and evidence freshness; context import is not an automatic ownership authority. |
| O5 | What breaks when an algorithm changes | Local change | Observed/reviewed dependency semantics and replacement-specific interoperability tests; source relationships do not prove what will break. |
| R1 | FIPS203/204/205, FN-DSA and HQC | Local change | Current authoritative publication/policy review and exact implementation/module qualification; names, public-key sizes and parameter sets are different evidence. |
| R2 | SP800-131A and2030/2035 timelines | Not requalified | Versioned current policy with jurisdiction/algorithm/use applicability and reviewer approval; dates cannot be copied as universal mandates. |
| R3 | Central bank, PCI, DORA, EBA, MAS, FFIEC, BIS | Not requalified | Bank/legal interpretation and control-by-control evidence acceptance; a mapping is not regulatory approval. |
| R4 | Standards/guidance updates | Not requalified | Owned source-monitoring/review cadence, signed-off policy revisions and adverse-regression evidence; not a claimed autonomous update service. |
| D1 | Residency and key/secret/sensitive-data egress | Local change, native profile | Actual deployment/log/backup/subprocessor data-flow review and metadata redaction. Allowlisted labels/paths can themselves be sensitive. |
| D2 | Scanner privilege, control and audit | Local change, export gate | Collector-specific least-privilege credentials, revocation/expiry, audit verification and segregation-of-duties exercise. |
| D3 | Fully on-prem and air-gapped | Not requalified | Real offline installation/update/restore drill with bundled dependencies, trust material and no hidden egress; docs alone are insufficient. |
| D4 | ISO27001, SOC2, pentest reports | External facts | Genuine issuer/auditor evidence with scope, dates, exclusions and controlled disclosure. No certificate was manufactured. |
| D5 | Production impact on payment/trading | Not requalified | Owner-approved workload, latency/resource limits, baseline, abort and no-disruption exercise on representative systems. No production throughput metric was invented. |
| I1 | CMDB/SIEM/GRC/PKI/secrets/ServiceNow/Jira | Not requalified | Each actual product/version/auth/permission mapping, retry/idempotence/redaction/rate-limit tests and bank acceptance. A generic webhook does not qualify every named integration. |
| I2 | Continuous discovery | Not requalified | Actual scheduler/event/run evidence, missed/failed sweeps, freshness and detection-delay targets. Configuration is not proof of continuous operation. |
| I3 | HSM/KMS integrations | Not requalified | Exact model/firmware/mechanism/API permission lab; real read-only discovery and explicit denied/unsupported behavior. |
| I4 | APIs and reports | Local change | Bank client/version contract qualification, pagination/truncation review, reporting/data-residency approval. |
| P1 | Roadmap, agility and remediation guidance | Not requalified | Reviewed application-specific changes, dependencies, exceptions, pilot evidence and owners; suggested replacements are not successful migrations. |
| P2 | Actual PQC latency, packets, certificates, HSM throughput | Not built/qualified by this pass | Native implementation/protocol/HSM benchmark with agreed workload and units. Do not substitute algorithm-size tables, simulator output or these test runtimes. |
| P3 | PKI/CLM transition, hybrid certificates, pilots | Not requalified | Actual CA/client/version interoperability and rollback exercise; a certificate label is not a valid hybrid chain. |
| P4 | HSM/PKI/network vendor partnerships | External facts | Verifiable partner agreements and exact scope; no code change creates a partnership. |
| P5 | Governance policy and agility framework | Not requalified | Appointed accountable bank/vendor roles, approved policy/exception/change process and actual operating evidence. |
| C1 | Timeline and bank effort | External engagement facts | Inventory/access prerequisites, jointly scoped pilot and measured effort; no universal bank-size estimate invented. |
| C2 | Comparable references | External facts | Permissioned references and verifiable relevant scope; the synthetic example is explicitly not one. |
| C3 | Pricing and cost growth | External commercial decision | Approved pricing/metering/limits and contract terms; no financial quote invented. |
| C4 | SLA, support, residency | External commitments plus operations evidence | Signed service terms, actual staffed responders and tested alert receipt; no24/7 staffing/SLA created by tests. |
| C5 | Exit and data/CBOM ownership | Not requalified | Reviewed contract plus verified export/delete/backup-retention and key-revocation exercise on the actual deployment. |
| C6 | Financial stability and vendor's own PQC transition | External facts plus product transition plan | Genuine financial review and qualified product trust/key/transport transition with recovery; an inventory does not PQC-proof the platform itself. |
| C7 | Third-party/open-source supply chain | Local dependency addition, not full qualification | New validator dependencies pinned and checked; authenticated release SBOM/image/source binding and independent review remain required. |
| G1 | Known blind spots | Not requalified | Versioned observed limitations, failures, unsupported platforms and unknowns after a real bank pilot. |
| G2 | Comparable CBOM/report | Local synthetic example | Comparable customer evidence and independent review still absent; sample input conversion is not a scan. |
| G3 | Inaccessible third-party SaaS | Not requalified | Supplier evidence/attestations and contractual access where possible; unresolved opacity must stay outside measured completeness. |
| G4 | Auditor/regulator completeness proof | Not requalified | Independently approved expected population, source/account/vantage reconciliation, exclusions, failures, freshness, sampled misses and reviewer sign-off. No finite test total proves universal completeness. |

## Use the implemented output

Authenticated requests to the existing API (use the deployment's origin and
existing cookie/token flow; never paste credentials into documentation):

- `GET /api/v1/cbom/portfolio?fmt=cyclonedx16`
- `GET /api/v1/cbom/system/{system_id}?fmt=cyclonedx16`
- `GET /api/v1/cbom/scan/{scan_id}?fmt=cyclonedx16`
- `GET /api/v1/scans/{scan_id}/cbom?spec_version=1.6`
- `POST /api/v1/cbom/validate` with `{"bom": <native document>}`

The first family converts before signing, if signing is requested, then validates
the signed document. Unknown `fmt` values return422, not silently mislabeled
JSON. Quarantined scan evidence returns409; foreign/missing scans remain404.
The download control uses the existing authenticated request path, not a public
anchor. Selected-system native exports fail closed on unresolved system context.

Existing CLI: `scripts/export_cbom.py` accepts `--spec-version 1.6 --format json`.
Native1.6 XML is explicitly refused, not emitted under a1.5 namespace.
Legacy1.5 defaults stay for compatibility. The new native profile is not a
lossless converter for arbitrary vulnerability, certificate or crypto-material
payloads; review its [explicit limits](../examples/bank-pqc-discovery/README.md).

## Still a partial product, not a qualified bank solution

The remaining work above includes **real engineering**, not just paperwork:
protocol/version coverage, collector fidelity, observation-vs-declaration,
product-specific integrations, production-impact qualification, actual PQC/HSM
performance and PKI interoperability. Those were not secretly completed by adding
this audit or by producing a valid JSON document. Activities requiring a bank,
HSM, vendor contract or independent reviewer were not fabricated.

[Executed changes, tests and compatibility limits](../readiness-evidence/bank-original45-2026-10-24.md).

## 2026-10-25 follow-up: functional hybrid / operation / package truth

[Guide 81](../bank-environment/81-actual-hybrid-operation-and-software-truth.md) and [retained engineering evidence](../readiness-evidence/hybrid-operation-software-2026-10-25.md) supersede the earlier blanket “no actual hybrid execution” state for **owned Linux loopback only**: the product collector completes X25519MLKEM768 TCP with exact peer pin. Public operation signatures and separately pinned signed logs can now be checked, with physical HSM/application execution still UNKNOWN/unattested. All agreed package inputs can be reconciled against exact expected records; a real 283-record dpkg comparison is not whole-host software completeness. Original I3/native/customer/independent-acceptance/performance gates stay open; the 45-question ledger is not declared complete.
