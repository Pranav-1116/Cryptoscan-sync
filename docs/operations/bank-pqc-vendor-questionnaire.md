# Bank PQC vendor questionnaire —45 original questions plus12 missing controls

**2026-10-23 · source-backed gap register, not a claim of full support.**
All45 questions supplied by the bank are mapped below.12 additional acceptance
questions are included, giving57 items. Existing source references identify
implementation surfaces; **file presence is not demonstrated capability**.
`PARTIAL` means a bounded implementation exists but the stated bank acceptance
is not established. `EXTERNAL` requires real corporate/customer/legal/assessor
facts or decisions that code cannot manufacture.

Read the [acceptance playbook](bank-pqc-vendor-acceptance-playbook.md) for safe
qualification procedures and the [executed change/evidence report](../readiness-evidence/bank-vendor-questionnaire-2026-10-23.md)
for the defects actually fixed. Machine source: [JSON register](bank-vendor-questionnaire.json).
No new screen, service, collector or deployed bank integration is claimed.

## Executable integrity review

```bash
# Validates all57 IDs, required answers, permitted status and safe source paths;
# hashes referenced files. Exit0 means register integrity, not bank acceptance.
python scripts/bank_vendor_questionnaire.py

# Deliberately exits1 while acceptance requirements remain open.
# Invalid register/unsafe/missing source exits2, never a successful approval.
python scripts/bank_vendor_questionnaire.py --strict
```

Every report keeps `bank_approved:false` and
`discovery_completeness_proven:false`. Source hashes prove byte identity only;
they do not authenticate tests, actual deployment or independent review.
This register does not accept self-entered QUALIFIED status as evidence.

## 1. Scope and coverage

### S1 — Which certificates, keys, libraries, protocols, code, HSMs, databases, APIs and cloud services are discovered?

**Status: PARTIAL.**

- **Existing surface:** Separate source/network/cloud/hardware/vendor inventories and receipt-based assurance.
- **Honest boundary:** Presence of an adapter is not qualified support for every protocol/version or deployment. Metadata is not key extraction.
- **Acceptance still required:** Approved asset/protocol/version/access matrix with positive and negative fixtures and independent expected denominator.
- **Source navigation, not proof:** [platform_scope.py](../../shared/shared_models/shared_models/platform_scope.py) · [coverage.py](../../services/api/api/assurance/coverage.py)

### S2 — What on-prem, multi-cloud, SaaS, mainframe and legacy environments are covered?

**Status: PARTIAL.**

- **Existing surface:** Cloud collectors, COBOL parser and operator-produced RACF/ICSF extracts.
- **Honest boundary:** No universal z/OS access, arbitrary SaaS visibility, legacy executable coverage or live multi-cloud qualification.
- **Acceptance still required:** Run permitted representative platforms and denied/segmented/offline cases; record exclusions and versions.
- **Source navigation, not proof:** [cobol_parser.py](../../services/scanner/scanner/parsers/cobol_parser.py) · [banking.py](../../services/cbom/cbom/banking.py) · [collector.py](../../services/cloud_scanner/cloud_scanner/enterprise/live/collector.py)

### S3 — What third-party embedded crypto in core banking, payment switches, SWIFT and card systems is covered?

**Status: PARTIAL.**

- **Existing surface:** Payment metadata, vendor profiles, supplier evidence and reviewed dependency relationships.
- **Honest boundary:** A vendor declaration, product label or signed document is not observed embedded implementation.
- **Acceptance still required:** Product/version-specific vendor evidence and authorized exports; bank-reviewed unknowns for inaccessible components.
- **Source navigation, not proof:** [payment_crypto.py](../../services/api/api/routers/payment_crypto.py) · [relationships.py](../../services/api/api/assurance/relationships.py) · [vendor-due-diligence.md](../../docs/operations/vendor-due-diligence.md)

### S4 — How are OT/IoT, ATMs, POS and network appliances handled?

**Status: PARTIAL.**

- **Existing surface:** OT scanners, hardware inventory and network metadata surfaces exist.
- **Honest boundary:** No unrestricted probing or safe-scan certification for fragile payment/OT devices.
- **Acceptance still required:** Device-owner-approved passive/export method, lab baseline, rate/stop limits and witnessed no-disruption test.
- **Source navigation, not proof:** [ot.py](../../services/api/api/routers/ot.py) · [hbom.py](../../services/api/api/routers/hbom.py) · [network.py](../../services/api/api/routers/network.py)

### S5 — Can you find hardcoded keys, custom crypto and compiled-binary crypto?

**Status: PARTIAL.**

- **Existing surface:** Source detectors and binary fingerprint/control-flow analysis paths exist.
- **Honest boundary:** Obfuscation, stripped/static binaries, wrappers and proprietary primitives create false negatives; signatures are indicators.
- **Acceptance still required:** Representative sanctioned source/binary corpus, ground truth, unsupported packers/architectures and secret-redaction review.
- **Source navigation, not proof:** [binary_scan.py](../../services/devsecops/devsecops/binary_scan.py) · [binary_engine.py](../../services/universal_crypto/universal_crypto/binary_engine.py) · [safe_finding.py](../../shared/shared_models/shared_models/safe_finding.py)

## 2. Methodology and technical approach

### M1 — Which discovery methods are used and what access is needed?

**Status: PARTIAL.**

- **Existing surface:** Static parsers, active metadata probes, imported extracts and binary analysis.
- **Honest boundary:** Method and production-profile admission differ; no single agentless method sees everything.
- **Acceptance still required:** Per-source architecture/data-flow/access plan, least-privilege grant and actual deployment qualification.
- **Source navigation, not proof:** [platform_scope.py](../../shared/shared_models/shared_models/platform_scope.py) · [assurance_boundary.py](../../services/api/api/routers/assurance_boundary.py)

### M2 — How are transit, at-rest and in-code crypto distinguished?

**Status: PARTIAL.**

- **Existing surface:** Source findings, network observations, cloud/key metadata and reviewed relationships.
- **Honest boundary:** An algorithm string does not prove encryption at rest, negotiated transport or key use.
- **Acceptance still required:** Purpose-bound evidence including actual transport negotiation, storage setting and source site; disclose inferred links.
- **Source navigation, not proof:** [adapters.py](../../services/api/api/assurance/adapters.py) · [relationships.py](../../services/api/api/assurance/relationships.py)

### M3 — What happens when traffic is encrypted, segmented or inaccessible?

**Status: PARTIAL.**

- **Existing surface:** Expected-estate coverage supports unresolved targets, exclusions and unavailable evidence.
- **Honest boundary:** No decryption bypass; inaccessible scope cannot be silently counted observed.
- **Acceptance still required:** Approved vantage points or offline metadata exports; explicit inaccessible targets and review/expiry of exceptions.
- **Source navigation, not proof:** [coverage.py](../../services/api/api/assurance/coverage.py) · [assurance.py](../../shared/shared_models/shared_models/assurance.py)

### M4 — What are false-positive/false-negative rates and how are they validated?

**Status: PARTIAL.**

- **Existing surface:** Existing approved/frozen sample workflow plus corrected legacy triage denominators, explicit unmeasured metrics, validated workbooks and consistent CLI scoring.
- **Honest boundary:** Reviewed file/algorithm units are not all-bank recall. No true-negative denominator is supplied by legacy workbooks, so no false-positive rate is claimed. Existing separate corpus evaluator conventions are not globally requalified.
- **Acceptance still required:** Bank-agreed corpus/version/method, confusion matrix, missed classes, confidence intervals and independent retest.
- **Source navigation, not proof:** [accuracy.py](../../services/api/api/assurance/accuracy.py) · [accuracy_benchmark.py](../../scripts/accuracy_benchmark.py)

### M5 — Can algorithm, key size, mode and quantum vulnerability be distinguished?

**Status: PARTIAL.**

- **Existing surface:** Shared classifier plus explicit PQC public-key byte units, native FIPS parameter-set identifiers and all twelve full SLH-DSA parameter names.
- **Honest boundary:** Algorithm recognition and catalog sizes are not observed key usage, implementation correctness, module validation or global current-policy approval. Legacy input key_size units remain unverified for PQC.
- **Acceptance still required:** Known/unknown/alias/suite/key-size fixtures and independently checked observations for the bank workload.
- **Source navigation, not proof:** [algorithm_registry.py](../../shared/shared_models/shared_models/algorithm_registry.py) · [quantum_classify.py](../../shared/shared_models/shared_models/quantum_classify.py) · [test_bank_vendor_questionnaire_boundaries.py](../../services/api/tests/unit/test_bank_vendor_questionnaire_boundaries.py)

### M6 — Can existing hybrid/PQC implementations such as ML-KEM in TLS be detected?

**Status: PARTIAL.**

- **Existing surface:** Registry recognizes hybrid names; inventory/planning now separates candidates from verified readiness.
- **Honest boundary:** A library, group name, supported-groups advertisement or vendor roadmap is not negotiated hybrid traffic.
- **Acceptance still required:** Capture permitted actual handshake/group and authentication evidence; test fallback/downgrade and unsupported peers.
- **Source navigation, not proof:** [inventory.py](../../services/api/api/routers/inventory.py) · [risk.py](../../services/quantum/quantum/risk.py) · [pqc_readiness.py](../../services/network_scanner/network_scanner/enterprise/pqc_readiness.py)

## 3. Output and prioritization

### O1 — Which CBOM formats and schema versions are available?

**Status: PARTIAL.**

- **Existing surface:** Legacy compatibility exporters plus native CycloneDX1.6 JSON with pinned full upstream schema, offline validation and local reference integrity.
- **Honest boundary:** Native1.6 is an allowlisted metadata profile, JSON only; not lossless arbitrary-document conversion. Legacy1.5 JSON/XML are not newly standard-qualified. Schema validity is not bank or third-party tooling acceptance.
- **Acceptance still required:** Validate requested schema/version and all six semantics; customer import round trip, provenance, unsupported fields and signing trust.
- **Source navigation, not proof:** [generator.py](../../services/cbom/cbom/generator.py) · [export_service.py](../../services/cbom/cbom/export_service.py) · [test_six_bom_current_evidence.py](../../services/api/tests/unit/test_six_bom_current_evidence.py)

### O2 — How are sensitivity, shelf life, HNDL, exposure and criticality prioritized?

**Status: PARTIAL.**

- **Existing surface:** Deterministic risk and business context; unknown retention remains unknown and signing-only use is not ciphertext HNDL.
- **Honest boundary:** Model defaults and inferred data classes are not bank-approved classifications; public-key signature migration remains important.
- **Acceptance still required:** Bank owner supplies confidentiality retention, purpose, exposure/criticality and validates resulting ordering.
- **Source navigation, not proof:** [risk.py](../../services/quantum/quantum/risk.py) · [banking.py](../../services/cbom/cbom/banking.py)

### O3 — Can findings be mapped to Mosca inequality?

**Status: PARTIAL.**

- **Existing surface:** Validated finite nonnegative scenario inputs, explicit assumption labels and zero-margin handling.
- **Honest boundary:** Threat year is an assumption, not a prediction, regulatory date or SLA; year resolution is coarse.
- **Acceptance still required:** Bank-approved retention/migration/threat scenarios and sensitivity analysis, with missing-input outcomes retained.
- **Source navigation, not proof:** [plan.py](../../services/quantum/quantum/plan.py) · [quantum.py](../../services/api/api/routers/quantum.py)

### O4 — Can findings map to applications, owners and classifications?

**Status: PARTIAL.**

- **Existing surface:** Existing business-system links plus native export of supplied application, owner, classification and retention context; shared assets retain multiple contexts without duplicate references.
- **Honest boundary:** Business context is supplied metadata, not independently verified ownership/classification; import does not automatically create CMDB mappings.
- **Acceptance still required:** CMDB reconciliation, active owners, classification approval and unmatched/ambiguous mapping review.
- **Source navigation, not proof:** [systems.py](../../services/api/api/routers/systems.py) · [business.py](../../services/api/api/routers/business.py) · [operator.py](../../services/api/api/assurance/operator.py)

### O5 — Do dependencies show what breaks if an algorithm is replaced?

**Status: PARTIAL.**

- **Existing surface:** Evidence-bound relationship paths and graph/impact surfaces.
- **Honest boundary:** A dependency path or simulation is not causal proof or a change-safety guarantee.
- **Acceptance still required:** Trace exact source/build/deployment and perform isolated interoperability/failure/rollback tests.
- **Source navigation, not proof:** [relationships.py](../../services/api/api/assurance/relationships.py) · [test_bank_dependency_qualification.py](../../services/graph_engine/tests/test_bank_dependency_qualification.py)

## 4. Standards and regulatory alignment

### R1 — How are FIPS203/204/205 and evolving FN-DSA/HQC standards handled?

**Status: PARTIAL.**

- **Existing surface:** Registry screens ML-KEM/ML-DSA/SLH-DSA families and full FIPS205 variants; FN-DSA/Falcon/HQC/McEliece do not receive automatic policy approval from draft/selected labels.
- **Honest boundary:** No live NIST publication refresh or regulator interpretation was performed. Conservative registry status is not a claim about the latest legal publication state or implementation certification.
- **Acceptance still required:** Record exact standard/revision/final status, implementation parameters and independent compatibility/validation evidence.
- **Source navigation, not proof:** [algorithm_registry.py](../../shared/shared_models/shared_models/algorithm_registry.py) · [banking.py](../../services/cbom/cbom/banking.py)

### R2 — How are SP800-131A and2030/2035 transition statements handled?

**Status: PARTIAL.**

- **Existing surface:** Legacy roadmap explicitly labeled historical draft planning; general framework dates no longer become PQC mandates.
- **Honest boundary:** Do not conflate SP800-131A, draft IR8547 targets, threat scenarios and institution-specific obligations.
- **Acceptance still required:** Compliance owner approves current publication/version, jurisdiction, primitive/use and applicability before deadlines bind.
- **Source navigation, not proof:** [banking.py](../../services/cbom/cbom/banking.py) · [risk.py](../../services/quantum/quantum/risk.py)

### R3 — Does output support central bank, PCI DSS, DORA, EBA, MAS, FFIEC and BIS expectations?

**Status: PARTIAL.**

- **Existing surface:** Evidence exports, control/register and banking action-plan surfaces.
- **Honest boundary:** Mapping and reports are not regulator acceptance, certification or a universal legal interpretation.
- **Acceptance still required:** Bank compliance/legal review of each applicable obligation and evidence sufficiency, including unresolved exceptions.
- **Source navigation, not proof:** [banking.py](../../services/api/api/routers/banking.py) · [control-register.json](../../docs/readiness-evidence/control-register.json)

### R4 — How are evolving standards/guidance kept current?

**Status: PARTIAL.**

- **Existing surface:** Version-controlled registry/policy definitions and reviewed release procedures.
- **Honest boundary:** A static catalog cannot promise live legal updates or silent safe changes.
- **Acceptance still required:** Named policy steward, authoritative-source/version/change log, review schedule and regression/customer notification process.
- **Source navigation, not proof:** [algorithm_registry.py](../../shared/shared_models/shared_models/algorithm_registry.py) · [operator-install-upgrade-recover.md](../../docs/runbooks/operator-install-upgrade-recover.md)

## 5. Security and data handling

### D1 — Where is data stored and can sensitive material leave the environment?

**Status: PARTIAL.**

- **Existing surface:** Evidence storage boundaries, safe-finding shaping and deployment residency controls.
- **Honest boundary:** Metadata-only intent is not proof: source/log extracts can contain secrets; end-to-end collection/export must be reviewed.
- **Acceptance still required:** Bank-approved data-flow/residency map, minimization/redaction samples, retention, egress controls and incident obligations.
- **Source navigation, not proof:** [safe_finding.py](../../shared/shared_models/shared_models/safe_finding.py) · [assurance_boundary.py](../../services/api/api/routers/assurance_boundary.py) · [threat-model.md](../../docs/security/threat-model.md)

### D2 — What privileges are required and how are they controlled/audited?

**Status: PARTIAL.**

- **Existing surface:** RBAC, durable human sessions, audit and explicit controlled execution policy.
- **Honest boundary:** Dedicated dispatcher/daemon access is privileged; a read-only collector label does not remove host risks.
- **Acceptance still required:** Least-privilege identity per source, scoped secrets, approval/revocation audit and hostile/denied-access exercise.
- **Source navigation, not proof:** [rbac.py](../../services/api/api/security/rbac.py) · [execution_controls.py](../../services/api/api/routers/execution_controls.py) · [scanner-isolation.md](../../docs/dev/scanner-isolation.md)

### D3 — Can deployment be fully on-prem or air-gapped?

**Status: PARTIAL.**

- **Existing surface:** On-prem reference profile, offline package verification and air-gap guidance.
- **Honest boundary:** Reference procedures are not a qualified customer installation or a complete offline update/supply chain.
- **Acceptance still required:** Witness install/upgrade/restore with approved offline images/wheels/trust keys and no unauthorized egress.
- **Source navigation, not proof:** [air-gap-install.md](../../docs/admin-guide/air-gap-install.md) · [operator_release.py](../../scripts/operator_release.py)

### D4 — Which ISO27001/SOC2 certifications and pentest reports can be supplied?

**Status: EXTERNAL.**

- **Existing surface:** Existing independent security report intake and declared evidence review.
- **Honest boundary:** No corporate certification, assessor independence or actual pentest is invented.
- **Acceptance still required:** Actual current scoped certificate/report, authorized disclosure, findings and independent retests.
- **Source navigation, not proof:** [launch.py](../../services/api/api/assurance/launch.py) · [pen-test-scope.md](../../docs/security/pen-test-scope.md)

### D5 — What production scan impact is demonstrated, particularly payments/trading?

**Status: PARTIAL.**

- **Existing surface:** Bounded execution budgets, explicit limits and selected benchmark tooling.
- **Honest boundary:** No bank-shaped latency/throughput/SLO qualification from tiny local tests; active OT/payment probes may be unsafe.
- **Acceptance still required:** Agree targets and noninterference limits before measurement; representative peak/failure workload, abort and cleanup proof.
- **Source navigation, not proof:** [execution_controls.py](../../services/api/api/routers/execution_controls.py) · [benchmark_scan.py](../../scripts/benchmark_scan.py) · [quality-trace-performance-2026-10-23.md](../../docs/readiness-evidence/quality-trace-performance-2026-10-23.md)

## 6. Integration and operations

### I1 — Which CMDB/SIEM/GRC/PKI/secrets/ticketing integrations work?

**Status: PARTIAL.**

- **Existing surface:** Integration/event/export and business-context surfaces.
- **Honest boundary:** A connector name/API scaffold is not a bank-tested bidirectional workflow or reliable delivery.
- **Acceptance still required:** Version/auth/data mapping, least privilege, idempotency, timeout/delivery receipt, retry/dead-letter and revocation tests.
- **Source navigation, not proof:** [integrations.py](../../services/control_plane/control_plane/integrations.py) · [bus.py](../../services/api/api/events/bus.py)

### I2 — Is discovery continuous or point-in-time?

**Status: PARTIAL.**

- **Existing surface:** Monitor scheduling/drift and retained point-in-time records.
- **Honest boundary:** Scheduled execution is not uninterrupted monitoring, coverage completeness or staffed incident response.
- **Acceptance still required:** Define observation freshness, missed windows, drift recheck, downtime/recovery and operational response ownership.
- **Source navigation, not proof:** [monitor.py](../../services/api/api/routers/monitor.py) · [accountable-operations-handoff-2026-10-23.md](../../docs/operations/accountable-operations-handoff-2026-10-23.md)

### I3 — Which HSM/key-management interfaces are supported?

**Status: PARTIAL.**

- **Existing surface:** PKCS11 metadata and HSM/cloud KMS inventory surfaces.
- **Honest boundary:** A model/family or declared mechanism does not prove installed firmware, FIPS scope, permission or live throughput.
- **Acceptance still required:** Exact vendor/model/firmware/provider/mechanism matrix; authorized no-key-export test and separate runtime qualification.
- **Source navigation, not proof:** [hsm_pkcs11.py](../../services/cbom/cbom/hsm_pkcs11.py) · [hsm_scans.py](../../services/api/api/routers/hsm_scans.py) · [inventory_cloud.py](../../services/api/api/routers/inventory_cloud.py)

### I4 — What APIs and reporting capabilities are offered?

**Status: PARTIAL.**

- **Existing surface:** Authenticated API schemas, assurance history and export/report surfaces.
- **Honest boundary:** No blanket API compatibility, pagination completeness or delivery assurance without contract tests.
- **Acceptance still required:** Customer API contract, scopes, limits, pagination/error semantics, export verification and version lifecycle.
- **Source navigation, not proof:** [main.py](../../services/api/api/main.py) · [export.py](../../services/api/api/routers/export.py) · [rest-api.md](../../docs/api-reference/rest-api.md)

## 7. Beyond discovery: remediation and roadmap

### P1 — Is there a migration roadmap, agility assessment and remediation guidance?

**Status: PARTIAL.**

- **Existing surface:** Deterministic workstreams/waves, agility and evidence-bound remediation.
- **Honest boundary:** A recommendation or reported completion is not a verified fix; migration needs deployment and interoperability evidence.
- **Acceptance still required:** Named owner, exact before/after predicate, representative rescan, independent verification and rollback boundary.
- **Source navigation, not proof:** [plan.py](../../services/quantum/quantum/plan.py) · [remediation.py](../../services/api/api/assurance/remediation.py) · [agility.py](../../services/api/api/routers/agility.py)

### P2 — Can PQC latency, packets/certificates and HSM throughput be benchmarked?

**Status: PARTIAL.**

- **Existing surface:** PQC impact and performance tools exist.
- **Honest boundary:** Estimates/simulation are not measured negotiated payload size, real HSM throughput or production SLO.
- **Acceptance still required:** Pre-agreed matched classical/hybrid/PQC workloads on exact versions/hardware; percentile/distribution, failure and size observations.
- **Source navigation, not proof:** [pqc_impact.py](../../services/universal_vendor/universal_vendor/hardware/live/pqc_impact.py) · [perf_benchmark.py](../../scripts/perf_benchmark.py)

### P3 — Can PKI/CLM transitions, hybrid certificates and pilots be supported?

**Status: PARTIAL.**

- **Existing surface:** Certificate lifecycle, composite-name handling and bounded pilot records.
- **Honest boundary:** Parsing a hybrid name is not valid certificate-chain/client interoperability or production key ceremony qualification.
- **Acceptance still required:** Approved test CA and clients, chain/path/downgrade/revocation/expiry cases, rollback and separate pilot acceptance.
- **Source navigation, not proof:** [certificates.py](../../services/api/api/routers/certificates.py) · [composite_certificates.py](../../shared/shared_models/shared_models/composite_certificates.py) · [launch.py](../../services/api/api/assurance/launch.py)

### P4 — Which HSM, PKI or network vendor partnerships are established?

**Status: EXTERNAL.**

- **Existing surface:** Vendor due-diligence evidence can be retained.
- **Honest boundary:** No partnership, joint support or certification is inferred from compatibility code or a vendor name.
- **Acceptance still required:** Actual agreements, named contacts, supported versions and authorized joint-test/support evidence.
- **Source navigation, not proof:** [vendor-due-diligence.md](../../docs/operations/vendor-due-diligence.md)

### P5 — Can crypto-governance policy and an agility framework be developed?

**Status: PARTIAL.**

- **Existing surface:** Policy definitions, owners, evidence registers and review workflow.
- **Honest boundary:** Software cannot appoint authority or determine legal policy for the bank.
- **Acceptance still required:** Bank-approved decision rights, cryptographic use policy, exceptions/expiry, changes, training and governance minutes.
- **Source navigation, not proof:** [policy.py](../../services/api/api/routers/policy.py) · [launch.py](../../services/api/api/assurance/launch.py)

## 8. Delivery, commercials and risk

### C1 — What delivery timeline and bank effort are realistic?

**Status: EXTERNAL.**

- **Existing surface:** Scope/qualification/runbook structure for a bounded pilot.
- **Honest boundary:** No typical bank duration or effort claimed without size, access, integration and approval inputs.
- **Acceptance still required:** Joint scope and resource estimate with prerequisites, milestones, acceptance, dependencies and change control.
- **Source navigation, not proof:** [launch-assurance-handoff.md](../../docs/runbooks/launch-assurance-handoff.md)

### C2 — Which comparable regulated references can be contacted?

**Status: EXTERNAL.**

- **Existing surface:** Evidence/profile records can hold authorized references.
- **Honest boundary:** No bank customer, testimonial or reference is invented.
- **Acceptance still required:** Consent-based actual comparable references and independently confirmed delivery scope/results.
- **Source navigation, not proof:** [vendor-due-diligence.md](../../docs/operations/vendor-due-diligence.md)

### C3 — How is pricing structured and what drives cost growth?

**Status: EXTERNAL.**

- **Existing surface:** Operational limits and workload concepts are available.
- **Honest boundary:** No fabricated price, subscription entitlement or commercial commitment.
- **Acceptance still required:** Signed pricing basis, asset dedup/revision counting, scans/API/storage/egress/connector limits and overage/exit costs.
- **Source navigation, not proof:** [vendor-due-diligence.md](../../docs/operations/vendor-due-diligence.md)

### C4 — What SLA, support and data-residency commitments are agreed?

**Status: EXTERNAL.**

- **Existing surface:** Accountable-duty and residency review boundaries.
- **Honest boundary:** Intended24/7 and weekly review are not staffed support or a contractual SLA.
- **Acceptance still required:** Actual primary/backup roster, support hours/timezone, escalation/response commitments, residency and legal agreement.
- **Source navigation, not proof:** [accountable-operations-handoff-2026-10-23.md](../../docs/operations/accountable-operations-handoff-2026-10-23.md)

### C5 — What happens to bank data/CBOM at exit?

**Status: EXTERNAL.**

- **Existing surface:** Exports, offboarding/retention duties and backup procedures.
- **Honest boundary:** Export success does not prove completeness, deletion from backups/subprocessors or revocation of every consumer.
- **Acceptance still required:** Witness portable verified export, trust/signature handling, restore/readability, revocation and retention/deletion evidence.
- **Source navigation, not proof:** [export_service.py](../../services/cbom/cbom/export_service.py) · [accountable-operations-handoff-2026-10-23.md](../../docs/operations/accountable-operations-handoff-2026-10-23.md)

### C6 — What financial stability and product PQC transition roadmap are demonstrated?

**Status: EXTERNAL.**

- **Existing surface:** Supplier profile can retain finance/succession evidence; product crypto is separately inventoried.
- **Honest boundary:** No audited accounts, escrow/succession guarantee or own-product PQC compliance is created by a registry entry.
- **Acceptance still required:** Actual finance/continuity evidence and source/image/protocol/key/signing inventory with tested product transition plan.
- **Source navigation, not proof:** [vendor-due-diligence.md](../../docs/operations/vendor-due-diligence.md) · [threat-model.md](../../docs/security/threat-model.md)

### C7 — What third-party/open-source scanning supply-chain risks exist?

**Status: PARTIAL.**

- **Existing surface:** Dependency locks, source/image binding and parser isolation.
- **Honest boundary:** Pinned inputs are not signed build provenance, license clearance, zero CVEs or safe upstream code.
- **Acceptance still required:** Reviewed SBOM/licenses/advisories, patched immutable images, provenance, independent review and offline update path.
- **Source navigation, not proof:** [requirements.lock.txt](../../requirements.lock.txt) · [package-lock.json](../../frontend/package-lock.json) · [operator_release.py](../../scripts/operator_release.py)

## 9. Probing and gotcha questions

### G1 — What are known limitations and blind spots?

**Status: PARTIAL.**

- **Existing surface:** Scope declarations, coverage blockers and accuracy blind spots.
- **Honest boundary:** No claim of universal scanning, proprietary primitive identification or full-bank completeness.
- **Acceptance still required:** Sign the allowed methods/platform matrix and retain unobserved/unsupported/stale/inconclusive classes.
- **Source navigation, not proof:** [platform_scope.py](../../shared/shared_models/shared_models/platform_scope.py) · [coverage.py](../../services/api/api/assurance/coverage.py)

### G2 — Can a comparable sample CBOM/report be shown?

**Status: PARTIAL.**

- **Existing surface:** A committed synthetic banking-like eight-record native1.6 CBOM and actual planning-engine report are reproducible locally.
- **Honest boundary:** Synthetic supplied inputs are not a comparable customer engagement or scanner execution; no bank reference or independent discovery accuracy follows.
- **Acceptance still required:** Consent-based comparable evidence or labeled synthetic six-BOM sample validated by the bank consumer.
- **Source navigation, not proof:** [export_service.py](../../services/cbom/cbom/export_service.py) · [test_export_service.py](../../services/cbom/tests/unit/test_export_service.py)

### G3 — How is inaccessible third-party SaaS handled?

**Status: PARTIAL.**

- **Existing surface:** Supplier evidence and expected-estate registers retain unknown/excluded scope.
- **Honest boundary:** No visibility is fabricated through proprietary SaaS or a vendor signature.
- **Acceptance still required:** Authorized provider exports/assessor evidence, service/version scope, contractual cooperation and explicit residual risk.
- **Source navigation, not proof:** [relationships.py](../../services/api/api/assurance/relationships.py) · [coverage.py](../../services/api/api/assurance/coverage.py)

### G4 — How is discovery completeness proved to auditors/regulators?

**Status: PARTIAL.**

- **Existing surface:** Independent expected-estate denominator and scoped receipts with current evidence checks.
- **Honest boundary:** Zero findings, signed CBOM,100% of returned records or a successful scan cannot prove an unknown universe complete.
- **Acceptance still required:** Reconcile independently maintained CMDB/cloud/network/application/vendor sets, permitted methods, freshness and omissions; separately review.
- **Source navigation, not proof:** [coverage.py](../../services/api/api/assurance/coverage.py) · [test_six_bom_current_evidence.py](../../services/api/tests/unit/test_six_bom_current_evidence.py)

## 10. Additional controls missing from the original list

### A1 — Authorization and rules of engagement

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Explicit per-target permission, access windows, identity and stop authority; no unauthorized scan.
- **Source navigation, not proof:** [execution_controls.py](../../services/api/api/routers/execution_controls.py)

### A2 — Completeness denominator and inaccessible scope

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Bank-owned expected inventory; unresolved, stale, excluded and unsupported targets stay visible.
- **Source navigation, not proof:** [coverage.py](../../services/api/api/assurance/coverage.py)

### A3 — Evidence freshness and provenance

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Capture time, exact artifact/source/method, integrity and expiry; historic verification is not current proof.
- **Source navigation, not proof:** [store.py](../../services/api/api/assurance/store.py)

### A4 — Non-disruption, abort and uncertain outcomes

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Agreed scan budgets and emergency stop; no retry of UNKNOWN external outcome without reconciliation.
- **Source navigation, not proof:** [execution_controls.py](../../services/api/api/routers/execution_controls.py)

### A5 — Tenant isolation and privileged insider threats

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Cross-bank read/write/export/cache/session tests and dedicated privileged worker boundary.
- **Source navigation, not proof:** [adversarial-tenant-isolation.md](../../docs/security/adversarial-tenant-isolation.md)

### A6 — Incident disclosure, breach notification and vulnerability handling

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Actual reporting route, bank notification obligations, accountable responders and reviewed retests.
- **Source navigation, not proof:** [accountable-operations-handoff-2026-10-23.md](../../docs/operations/accountable-operations-handoff-2026-10-23.md)

### A7 — CBOM schema, portability and licensing

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Exact format/version, stable IDs, provenance, six-BOM semantics, license terms and consumer round trip.
- **Source navigation, not proof:** [export_service.py](../../services/cbom/cbom/export_service.py)

### A8 — Exit verification including backups and subprocessors

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Export validation, key/access revocation, legal retention/deletion limits and processor attestations.
- **Source navigation, not proof:** [vendor-due-diligence.md](../../docs/operations/vendor-due-diligence.md)

### A9 — Policy source status and applicability

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Current authoritative publication/revision, draft versus final, jurisdiction and bank-approved effective dates.
- **Source navigation, not proof:** [risk.py](../../services/quantum/quantum/risk.py)

### A10 — Observed versus inferred dependencies

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Evidence class for each edge; no causal impact or safe migration guarantee from graph reachability.
- **Source navigation, not proof:** [relationships.py](../../services/api/api/assurance/relationships.py)

### A11 — Hybrid/PQC interoperability and downgrade resistance

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Actual negotiation and authentication, fallback, chain/packet size, middlebox and legacy-client cases.
- **Source navigation, not proof:** [pqc_downgrade.py](../../services/keyassure/keyassure/pqc_downgrade.py)

### A12 — Product self-transition and recovery of trust

**Status: PARTIAL.**

- **Existing surface:** Existing control/evidence surfaces; no new service or screen.
- **Honest boundary:** This control requires explicit bank acceptance, not a product-name assertion.
- **Acceptance still required:** Own TLS/SSO/artifact/report signatures and long-lived evidence keys; rotation, offline verification and backup restore.
- **Source navigation, not proof:** [operator_release.py](../../scripts/operator_release.py)

## Original45 implementation follow-up —2026-10-24

The [original-question gap audit](bank-original45-engineering-gaps.md) separates
actual code changes in the second pass from remaining engineering and external
qualification. [Synthetic native CBOM and report](../examples/bank-pqc-discovery/README.md)
are available now; they are not comparable-customer evidence. New source
references are included in the machine-readable register. All57 bank acceptance
requirements remain open; this is not a count of completed capabilities.
