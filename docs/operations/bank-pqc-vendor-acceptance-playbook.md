# Bank PQC vendor acceptance: evidence to request and execute

**2026-10-23.** Companion to the [57-question register](bank-pqc-vendor-questionnaire.md).
This is a practical acceptance procedure, **not an executed customer engagement,
a certification, a commercial offer or a support contract**. No new collectors,
services or screens were added for the questionnaire.

## Additional questions missing from the original list

The original45 questions cover nine major areas well. Add these12 controls as
explicit acceptance questions, rather than letting them hide inside a sales answer:

1. **Authorization and rules of engagement:** exact targets, source owner,
   approved credentials/methods/windows, prohibited operations and stop authority.
2. **Completeness denominator:** independently maintained expected estate,
   inaccessible/unsupported/stale targets, exclusions, sampling and reconciliation.
3. **Evidence lifecycle:** source/method/identity, timestamps, freshness, hashes,
   retention, withdrawal and the difference between historical and current proof.
4. **Non-disruption and uncertain outcomes:** budgets, deadlines, backpressure,
   emergency stop, UNKNOWN outcomes and reconciliation before retrying.
5. **Isolation and insiders:** cross-bank read/write/export/session/cache tests,
   privileged dispatcher boundaries and separation of human duties.
6. **Incidents and vulnerability disclosure:** real contact paths, notification
   obligations, containment authority, defect ownership and independent retests.
7. **CBOM interoperability and licensing:** exact schema/version, stable IDs,
   extensions, export/import round trips, ownership/licensing and six-BOM semantics.
8. **Verifiable exit:** complete portable export, keys/trust needed to read it,
   access revocation and honest deletion limits for backups/subprocessors.
9. **Standards provenance/applicability:** authoritative source, publication
   revision/date, draft versus final, exact use/jurisdiction and approved deadlines.
10. **Dependency semantics:** observed versus declared/inferred edges; what is
    actually tested versus a graph-only prediction of what might break.
11. **Hybrid/PQC interoperability:** negotiated group and authentication, downgrade,
    fallback, middleboxes, legacy clients, certificate chains and payload limits.
12. **Vendor's own product transition:** TLS/SSO, code/report/artifact signatures,
    long-lived evidence, rotation and recovery of historical verification trust.

## 1. Agree scope before collecting or measuring

Maintain a bank-owned expected inventory separate from scan output. For each
application/system/service, record owner, criticality, data classification and
confidentiality retention, source/version, permitted method, credential identity,
region/destination, evidence freshness and acceptance predicate. Include:

- On-prem/cloud accounts and subscriptions, SaaS/provider dependencies, mainframe
  environments, legacy/EOL systems and inaccessible third-party products.
- TLS, SSH, IPsec and application identity/signature uses such as SAML, rather
  than equating one protocol/library finding with all protocol coverage.
- Core banking, payments/SWIFT/card ecosystems, databases/APIs, HSM/KMS, ATMs,
  POS and OT/appliances, with product/firmware/protocol versions.
- Source, dependency/package and binary inputs, including wrappers, custom
  primitives, stripped/obfuscated binaries and unsupported architectures.

Do not bypass encryption or segmentation. Obtain authorized vantage points,
operator exports, provider evidence or a recorded unresolved/excluded target.
A supplier document or signature proves provenance, not implementation truth.
The controlled production profile has narrower permitted acquisition than the
presence of general discovery code implies; review its actual admission policy.

## 2. Prove observation quality, not a universal accuracy percentage

Agree a labeled positive/negative corpus representative of the intended methods
and versions. Include aliases, unknown names, compiled variants, wrappers,
multiple algorithms at a site, declared-but-unused libraries, intentionally
missing methods and denied access. Retain actual confusion matrices by source
class, confidence intervals where justified, false negatives and limitations.

No single global precision/recall rate is supplied by this work. A detector
recognizing a name cannot establish all of:

- Correct algorithm/parameter/mode/purpose and key identity.
- Correct implementation, approved policy and module validation.
- Actual negotiated transport or encryption at rest/in use.
- Complete observation across the expected estate.

FIPS203/204/205 algorithm identity is separate from a FIPS140 validated module.
A manufacturer/model/family match and a vendor-supplied certificate number are
review leads. Verify exact module/firmware/operational environment, certificate
scope and current authoritative status. Do not turn a roadmap, negative text
such as “ML-KEM not supported,” or a boolean capability key into verified PQC
readiness.

## 3. Validate outputs and assumptions

Keep the six BOMs distinct:

| BOM | What acceptance must establish | What it does not establish |
|---|---|---|
| **SBOM** | Exact packages/versions and original document bound to the release/estate. | Installed or invoked runtime solely from package presence. |
| **CBOM** | Crypto observation, parameters/purpose/location and supporting provenance. | Correct use everywhere, full discovery or verified remediation. |
| **NBOM** | Exact authorized endpoint/job/phase, actual protocol/identity observations. | Universal live network truth from a binary capability string. |
| **TechBOM** | Reviewed source/package/build/deployment relationships with evidence classes. | Causal dependency, invocation or safe-change guarantee by graph reachability. |
| **HBOM** | Exact device/model/firmware and evidence/verification state. | FIPS/PQC readiness inferred from a model name. |
| **VBOM** | Exact supplier/product/build claims, source document and signer lifecycle. | Independent truth merely because the supplier signed it. |

Ask for the actual exported schema/version, validation result, unsupported fields,
consumer round trip, stable identities, hashes and signing trust. Product exports
and synthetic fixtures exist, but this increment does **not** present a real
comparable bank's CBOM or an independently validated new CycloneDX sample. Obtain
consent-based comparable evidence or explicitly labeled synthetic samples;
validate them against the exact intended consumer/schema before acceptance.

Mosca inputs must be bank-approved scenarios: confidentiality shelf life,
estimated migration duration and an explicitly assumed threat year. Negative,
boolean, nonfinite and unexpected inputs must be refused. Zero slack is not a
safe margin; missing retention/migration stays unknown. A threat year is not a
forecast or legal deadline. Signature-only use requires authenticity migration
but is not, by itself, harvestable encrypted data.

Do not treat general PCI DSS/DORA effective dates as PQC algorithm retirement
dates. Do not conflate SP800-131A revisions, historical IR8547 draft targets,
CNSA/institution policy and quantum threat scenarios. A bank compliance owner
must review the exact current authoritative publication and applicability.
This pass did not independently fetch/verify current regulator or NIST updates;
registry entries are versioned local policy inputs, not a live legal service.

## 4. Execute a safe pilot and performance qualification

Agree success criteria **before measurement**. Define permitted payment/trading
and OT windows, peak/concurrency/workload distribution, latency/throughput/error
budgets, device limits, scan rate, retention/egress and emergency abort. Use the
same workload/environment for matched classical/hybrid/PQC comparisons.

Measure actual negotiation and packet/certificate sizes, CPU/memory/network,
latency distributions, HSM mechanism throughput, error/fallback behavior and
unsupported peers. Simulation or library presence is not runtime throughput.
Start on authorized disposable/lab systems; do not send unapproved load to
production payment systems. Include failure and recovery, not only happy paths.

A bounded pilot should preserve source/image/schema/permission identity,
expected-estate coverage, raw observations, before/after change predicates,
independent reviewer and rollback boundary. Reported completion is not verified
resolution. UNKNOWN external outcomes require reconciliation, not blind replay.

## 5. Security, integration and operational acceptance

Witness actual least-privilege grants, session/credential revocation,
residency/egress and export boundaries. Review collection artifacts: static
source and imported logs can contain secrets even when the intended inventory
is metadata-only. Sample and minimize/redact collected and exported content;
never rely on a blanket marketing statement that no sensitive material can
enter any path.

For each CMDB/SIEM/GRC/PKI/secrets/ticketing integration, test actual authentication,
data mapping, idempotency, stale/out-of-order events, delivery receipts, retry/
dead-letter behavior, revoked permission and outage recovery. Do not infer full
ServiceNow/Jira or vendor support from a connector/API name.

On-prem/air-gap qualification needs approved immutable OCI artifacts and offline
dependencies/trust, no unauthorized egress, populated upgrade, incompatible
rollback refusal and a witnessed restore. Signed package integrity is not image
build provenance or bank installation acceptance.

Appoint actual primary/backup owners and test alert receipt, acknowledgement,
action and backup escalation. Agree support hours/timezone/staffing and response
commitments. Hold the intended weekly joint review of errors, failed backups,
capacity, expiring credentials, unresolved defects and retests. Urgent incidents
must use the agreed immediate path, not wait for that meeting. See the
[accountable operations handoff](accountable-operations-handoff-2026-10-23.md).

## 6. Commercial and independent decisions: cannot be built into truth

Require actual authorized documents/decisions for:

- Corporate ISO27001/SOC2 scope, actual assessor reports and independent retests.
- Consent-based comparable bank references and real vendor partnerships.
- Financial stability, continuity/succession, licensing, escrow and product roadmap.
- Joint delivery effort/timeline; pricing basis, limits, overages and growth costs.
- Residency, subprocessors, liability, breach notification, support/SLA and exit.
- Export/readability, revocation, legal retention and deletion from live systems,
  backups and subprocessors, including what cannot be deleted immediately.

No names, contracts, references, certifications, prices or SLA have been invented.
A current source file, passing test or reviewed declaration is not a substitute.
Full questionnaire completion and bank/regulator acceptance remain open until
actual authorized evidence is reviewed and the bank accepts the residual gaps.
