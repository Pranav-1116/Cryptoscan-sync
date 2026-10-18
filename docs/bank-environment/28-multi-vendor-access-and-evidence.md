# 28 — Multi-vendor access, evidence contracts and supplier blind spots

[Program](27-international-bank-scan-program.md) · [Guide index](README.md) ·
[Pipeline](30-evidence-pipeline-identity-and-coverage.md)

**Status:** operating requirements and proposed improvements. Existing vendor
inventory/import and VBOM functions are starting points, not certification of
any supplier or the full contract described here.

## 1. Distinguish the supplier roles

A single service can involve a product manufacturer, reseller, implementation
partner, managed-service operator, hosting provider and subcontractor. Record
those roles separately. “Vendor A” is not a deployment identity and is not proof
that every product from that vendor shares the same crypto implementation.

| Situation | What the bank can reasonably request | Boundary |
|---|---|---|
| Bank-hosted licensed software | Build-specific BOMs, approved binaries/configuration, interface metadata | License and vendor support terms still apply |
| Managed appliance in bank site | Approved management metadata or operator-produced export | Physical presence does not authorize administrative actions |
| SaaS | Tenant-scoped API evidence, contractual assertions, assessor reports | Public endpoints do not expose provider internals or other customers |
| Outsourced HSM service | Partition-scoped public metadata and operational attestations | No master keys, PIN data, wrapped key payloads or other tenants' objects |
| Subcontractor/fourth party | Provenance chain, service dependency, permitted assurance evidence | No inherited right to scan the subcontractor |
| Unsupported/end-of-life product | Available exports, source/binary evidence where licensed, explicit exception | Do not label the product clean because the adapter is absent |

Shared ownership makes the authorization question more important, not less.

Real-world product families might include IBM mainframe environments,
Oracle/database platforms, Temenos/FIS/Finacle application products,
Thales/Utimaco/Entrust HSM families and Cisco/F5/Palo Alto network appliances.
These are examples of heterogeneous suppliers, **not** a tested adapter list,
partnership claim or description of a particular bank. Product/version, hosting,
operator and contractual permissions decide the collection design.

## 2. Create a supplier evidence schedule before onboarding

Procurement and service owners should agree on a schedule containing:

1. Exact supplier legal entity, product family, version/build and customer scope.
2. Production, staging, DR and regional variants included or excluded.
3. Delivery format, schema/version, frequency and freshness expectation.
4. Required software/crypto/hardware/configuration evidence and known omissions.
5. Build/artifact digest or other exact binding; a product-name match is insufficient.
6. Who produced the evidence, when, with which tool/version and permitted method.
7. Signer authority and verification procedure if signed; unsigned evidence policy.
8. Confidentiality, permitted locations/recipients and retention/deletion terms.
9. Vulnerability/crypto-change notification, remediation and dispute arrangements.
10. Subcontractor disclosure and the limits of the supplier's own visibility.
11. Approved test interfaces, rate limits, support windows and emergency contact.
12. Exit/renewal arrangements when the supplier stops supplying evidence.

These are negotiated requirements, not a universal legal entitlement or a new
CryproScan API. A supplier unable to meet them creates a documented risk and
collection limitation, not permission to bypass its controls.

## 3. Use graduated collection options

### Option A — authorized direct metadata collection

Use a supplier-approved, tenant-scoped read identity and documented API. Review
actual API calls; a role called “viewer” may expose more than needed. Capture
pagination completion, account/partition/region selection and permission errors.
Never reuse an operator's personal admin session as a permanent connector.

### Option B — supplier-executed collection

The supplier runs an agreed collector in its own boundary and supplies an
approved evidence bundle. Record the collector version, configuration, scope,
clock and omitted checks. Establish how the bank can challenge the output.
A supplier-run tool is not automatically an independent observation by the bank.

### Option C — sanitized offline import

Transfer approved BOMs, public certificates, configuration facts or metadata
exports through the bank's review process. Validate in quarantine before normal
inventory ingestion. Air-gap transfer is a transport choice, not authenticity.

### Option D — questionnaire or third-party report only

Retain the assertion's scope, report period, assessor, restrictions and age.
Do not convert a statement such as “AES encryption supported” into “AES enabled
for this bank's data.” Mark unsupported internal checks unknown and escalate
where the service's criticality makes that evidence insufficient.

Multiple options can corroborate one deployment, but one must not overwrite
conflicting evidence from another without an auditable resolution.

## 4. Proposed evidence envelope

The following **illustrative contract is not an existing request schema**:

```json
{
  "contract_kind": "PROPOSED_SUPPLIER_EVIDENCE_ENVELOPE",
  "supplier_ref": "supplier-A",
  "product_ref": "payments-switch",
  "release_ref": "release-2026-10",
  "customer_environment_ref": "bank-region-1-production",
  "scope_register_revision": "scope-17",
  "evidence_kind": "supplier-declared-sbom",
  "observation_time": "2026-10-18T01:00:00Z",
  "producer_ref": "supplier-approved-build-service",
  "tool_version": "supplier-recorded-version",
  "artifact_digest_ref": "verified-digest-record-42",
  "bundle_digest_ref": "verified-bundle-record-43",
  "verification_status": "NOT_YET_VERIFIED",
  "omissions": ["runtime-loaded plugins not included"],
  "handling_class": "restricted-regional-evidence"
}
```

Digest references here are placeholders for real verified records, not invented
SHA-256 values. The schema intentionally contains no credentials or key values.
Do not post it to an API that has not implemented this contract.

A production design needs canonical bytes, algorithms, explicit signature
coverage, a trust store, revocation/rotation handling and replay policy. A hash
proves a byte comparison, not who produced it. A valid signature proves the
verified key signed particular bytes; authority to speak for a product and
truth/completeness of those bytes require separate checks.

## 5. Admission and reconciliation of supplier packages

1. **Receive into quarantine:** bind the delivery to its authenticated channel
   and approved contract; allocate an immutable receipt ID.
2. **Inspect safely:** enforce compressed/uncompressed size, file-count, nesting,
   encoding and parser limits; reject traversal, symlinks and unexpected executable
   content. Do not run supplier installers or build scripts to inspect a BOM.
3. **Verify:** compare digests and any supported signatures against approved
   identities. Distinguish invalid, unsigned, unknown-signer and expired evidence.
4. **Validate scope:** confirm the intended bank, deployment, version and date.
   A legitimate document for another customer must not populate this bank's view.
5. **Normalize without guessing:** preserve original IDs and raw source refs;
   unknown versions or dependency relationships remain unknown.
6. **Compare:** relate the imported SBOM to admitted artifact bytes and explicit
   deployment assertions, then compare permitted observations.
7. **Publish a qualified projection:** expose allowed fields and scope/verification
   status, retaining the original evidence under appropriate access controls.
8. **Record gaps/disputes:** partial delivery must not refresh every previous
   supplier assertion or remove absent components as though a full census ran.

Do not imply the current import paths enforce every proposed quarantine rule.
Validate each path or restrict it until engineering and qualification are complete.

## 6. Resolving conflicting evidence

| Conflict | Safe interpretation and action |
|---|---|
| Supplier SBOM says version X; admitted image contains Y | Keep both with dates/provenance; check image digest, delivery scope and extraction support |
| Questionnaire says PQC-ready; installed firmware is not evidenced | Readiness is declared; installed capability/enablement remains unknown |
| API reports no keys but includes permission errors | Partial/failed access, not an empty key estate |
| Two vendor documents share a product name but different builds | Separate releases until an authorized exact mapping exists |
| Old export arrives after a newer one | Retain history; do not make it current solely because ingestion was later |
| Vendor omits a transitive library under confidentiality terms | Record explicit omission and residual risk; do not silently assume absence |
| Same provider supports multiple banking applications | A shared supplier is not proof of a shared region, runtime, partition or failure domain |

No universal confidence score can replace these distinctions. Current VBOM
includes provenance and readiness fields, but some representations are boolean;
a missing readiness value must not be presented to reviewers as tested failure
or tested safety. Preserve the richer uncertainty in the assessment evidence,
and improve schema/UI semantics through a reviewed migration where necessary.

## 7. Supplier service levels and change events

Agree how quickly the supplier must notify relevant changes, with bank-specific
values rather than invented universal deadlines. Triggers can include a crypto
library update, certificate authority change, HSM firmware release, region move,
new subprocessor, compromised signing key, end of support or changed API scope.

Each event should start an applicability review, not an automatic production
change. Determine whether the bank actually uses the affected build/configuration.
Supplier PSIRT and advisory feeds may require commercial access and regional
mirrors; an offline or stale feed cannot establish “no vulnerabilities.”

## 8. What good vendor acceptance looks like

For every critical supplier, retain a named owner, approved evidence method,
exact covered deployments, accepted freshness, known exclusions, unresolved
questions and a renewal/escalation date. Demonstrate one positive import, one
wrong-bank/wrong-build rejection, one malformed/oversized rejection and one
stale/incomplete update that does not erase valid history.

Approval is per supplier/product/version/method. Passing one supplier adapter
does not qualify all products from that company or every fourth party.

### Current implementation starting points

- [Vendor/BOM assembler](../../services/vendor_intel/vendor_intel/vbom.py).
- [Vendor/profile APIs](../../services/api/api/routers/business.py).
- [Connector extension base](../../services/connector_sdk/connector_sdk/base.py).
- [Vendor risk guide](../user-guide/vendor-risk.md).
- [Package/artifact/deployment identity](19-package-artifact-deployment-identity.md).

These references establish useful building blocks. They do not establish
supplier consent, trusted supplier signatures or a globally complete inventory.
