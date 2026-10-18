# 30 — Evidence pipeline, exact identity and whole-estate coverage accounting

[Guide index](README.md) · [Vendor evidence](28-multi-vendor-access-and-evidence.md) ·
[Worked assessment](34-worked-international-bank-assessment.md)

**Status:** current building blocks plus explicit enterprise design requirements.
Existing Step 1–10 semantics remain authoritative for implemented analysis.
Additional receipts, scope fields and orchestration below are proposed unless
linked to an existing contract; this is not a new API specification.

## 1. Separate five questions that are often collapsed

1. **Authorization:** were we allowed to inspect this exact target by this method?
2. **Execution:** did a collector run and what did it successfully read?
3. **Persistence:** were accepted facts committed to the intended evidence store?
4. **Interpretation:** what do those facts justify, with which limitations?
5. **Estate coverage:** how does that scope compare with what the bank expected?

An HTTP 200, queued job, emitted event, nonempty BOM or hash chain cannot answer
all five. A secure enterprise workflow needs a linked record at each boundary.

## 2. Recommended ingestion-to-assessment pipeline

```text
Approved scope revision + target identity + valid execution permission
 -> regional scheduling and credential lease
 -> isolated, bounded collection / quarantined import
 -> raw-evidence receipt with limits, errors and observation time
 -> integrity/authenticity and schema validation
 -> normalized records with original identity/provenance references
 -> durable transaction + collection-completeness receipt
 -> owner-reviewed identity and relationship bindings
 -> six scoped BOM projections + dependency analysis
 -> qualified regional/global reports and gap reconciliation
 -> remediation/change approval -> new verification evidence
```

A rejection or partial result must remain visible in the target ledger. Retrying
a job should not duplicate accepted evidence or fabricate a second observation.
Delivery retries and genuinely new observations need different identifiers.

## 3. Identity must survive mergers, regions and naming collisions

| Object | Suitable identity evidence | Inadequate identity alone |
|---|---|---|
| Business application | Bank-authoritative stable system ID and legal-entity context | `payments` display name |
| Source | Repository identity plus admitted commit/tree digest | Branch name such as `main` |
| Software component | Ecosystem-qualified package identity/version and relevant qualifiers | Library name; CPE/PURL guessing |
| Release artifact | Measured digest of admitted bytes plus type/architecture | Tag or supplier release label |
| Deployment | Explicit system/environment/region binding to release evidence | Artifact present in a registry |
| Network observation | Scope/vantage + endpoint/port + SNI/protocol + time | IP address without namespace; reused private address |
| Certificate | Exact encoded-certificate fingerprint | Subject/CN, serial without issuer context, matching name |
| Cloud resource | Provider/account/region/resource identity | Friendly resource name |
| Hardware/partition | Verified device ID within owner scope plus partition identity | Model number or manufacturer |
| Vendor/product | Supplier legal entity, product/release and approved customer scope | One global vendor display name |

Identical private IPs in different branches/VRFs must not merge. The same
certificate can serve several endpoints; that does not collapse all endpoints
into one application. A shared hash proves equal bytes, not ownership or an
authorization to share evidence across banks.

Some proposed compound identities require additional schema and adapter work.
Do not stuff them into an existing exact-ID field in a way that violates its
length/format contract. Preserve original IDs and a reviewed mapping instead.

## 4. Build explicit six-BOM joins

For a vendor-provided switch, establish each link separately:

1. Supplier document describes **SBOM document D** and its stated omissions.
2. Verify the document's own bytes/digest; that digest is not the release digest.
3. Bind D to **artifact A** only with explicit assertion/evidence.
4. Measure A's actual bytes where available, retaining producer vs measured claims.
5. Bind A to **deployment P** through an authorized deployment assertion.
6. Associate P with bank **system S**, not merely the same display name.
7. Relate S to approved **NBOM** listener observations and exact certificate IDs.
8. Link relevant **CBOM** crypto facts with source/runtime/declaration distinctions.
9. Associate **HBOM** device/partition through an explicit service-owner mapping.
10. Associate **VBOM** supplier/product/contract through a specific relationship.
11. Use **TechBOM** for the qualified technology view, not a substitute for D.

If step 5 is absent, report “artifact-to-deployment binding missing.” Do not
invent it from matching product/version strings. If only the supplier can see
A, classify that release identity as supplier-asserted, not bank-measured.

Existing starting point:
[package/artifact/deployment identity](19-package-artifact-deployment-identity.md).
Not all enterprise deployment sources are automatically integrated.

## 5. Preserve epistemic state, not just a confidence number

Every finding/relationship should retain its origin, evidence reference,
observation time, ingestion time, freshness rules, collector/tool version,
source scope and any uncertainty. Distinguish:

- **Observed:** a collector saw a defined fact at a defined place/time.
- **Measured:** particular bytes/metadata were measured by a specified method.
- **Declared:** bank or vendor asserts a fact; record the authority and date.
- **Inferred/modelled:** a rule derived a conclusion from known inputs.
- **Unknown/conflicting:** available evidence cannot establish one conclusion.

A new ingestion timestamp must not refresh an old observation. A currently
reachable listener does not refresh old hardware or supplier evidence. One
field's verified state must not promote the entire document to verified truth.

Cryptographic integrity, signer trust, collection authorization, freshness,
completeness and semantic accuracy are independent properties. A high score
must not hide failure in any one of them.

## 6. The expected-estate ledger

Maintain a versioned expected set per class and scope. Sources can include CMDB,
cloud organization inventory, deployment controllers, procurement, IPAM/DNS,
certificate management, HSM inventories and service-owner declarations.
Reconcile disagreements instead of treating the CMDB as unquestionable truth.

At an assessment cut-off, assign one primary operational outcome per target:

| Primary outcome | Meaning |
|---|---|
| Fresh accepted complete-for-declared-scope | Required collection for this target's declared scope met its contract |
| Stale | Previously accepted evidence exists but misses the agreed freshness rule |
| Partial | Some required collection was accepted; known portions were not obtained |
| Failed | Attempt did not achieve an accepted collection result |
| Blocked | Permission, window, residency or safety gate refused execution |
| Unsupported | No admitted/qualified method for the required evidence |
| Not yet attempted | Registered work without an accepted attempt |
| Excluded | Explicit approved exclusion, with owner and residual risk |

These are **proposed assessment-ledger categories**, not the current `ScanJob`
status enumeration. Preserve all underlying attempt events even when presenting
one primary status. Apply a documented precedence to mixed conditions and show
secondary reasons; a partial/stale export should not appear fresh/complete.

Unknown targets outside the register remain a separate inventory-discovery gap.
A fully reconciled register is not proof that the register is complete.

## 7. Metrics that do not overclaim

For 12 expected TLS listener targets, suppose 9 meet the agreed observation
contract, 1 is partial, 1 blocked and 1 unattempted. Report **9/12 target contracts
met**, naming that denominator and scope revision. Do not call it “75% of bank
security,” “75% of applications” or “75% of all network paths.”

Report per-class/per-region units separately:

- Expected accounts and account-region/API slices actually examined.
- Expected deployments with an exact admitted artifact binding.
- Expected supplier products with fresh, scoped evidence.
- Expected HSM partitions with approved metadata coverage.
- Expected listeners with required SNI/protocol/vantage observations.
- Unknown register completeness, unresolved identity and unsupported methods.

An account is not a listener; do not sum them into a security completeness score.
Work-item counts can help scheduling, but must be labelled operational counts.
Exclusions stay visible and must not make dashboards look artificially clean.

## 8. Completeness receipts and reconciliation safety

A proposed collection receipt should bind scope revision, collector identity,
observation interval, selected resources, continuation/pagination completion,
known omissions, errors, source capability and persisted result references.

Only an authoritative, successful complete collection of the **same declared
source scope** may justify source-owned disappearance reconciliation. Permission
loss, pagination failure, sampling, a cap or a changed account selection must
not tombstone previously seen assets. One source cannot delete another source's
assertion merely because it did not see it.

Existing lifecycle/receipt semantics provide useful protection:
[guide 20](20-relationship-lifecycle-and-reconciliation.md). Extend collectors
to those semantics through explicit tests; do not assume every importer already
produces an adequate enterprise completeness receipt.

## 9. Keep analysis limits independent from estate coverage

Step 9 already distinguishes source-read omissions, traversal horizon, detail
limits and missing links. Preserve those contracts:

- A read cap can omit actual rows even when the graph engine is correct.
- A horizon limit can omit reachable nodes even when source input is complete.
- A witness/explanation cap need not change compact membership counts.
- Missing mappings create unknown connectivity, not confirmed absence.
- Native extension with `NOT_EVALUATED`/null is unknown, not zero.

A graph answer can be complete for its admitted input and still incomplete for
the expected bank estate. Display both qualifications before impact metrics.
See [guide 25](25-coverage-truncation-and-missing-link-qualifications.md).

## 10. Historical comparisons and remediation verification

Compare only compatible identities, clocks, scope/policy versions and coverage
profiles. An expanded scope can increase findings without deterioration; lost
access can reduce findings without improvement. Withhold unsupported removals
or “unchanged” conclusions, retaining the old baseline and reason.

Operational modes HARD/OPTIONAL/FAILOVER/ASYNC_BUFFERED express conditional
relationships. They do not predict a real payment failure, successful failover,
queue survival time or financial loss. A process revenue figure is contextual,
not a modeled loss estimate. Preserve direct exposure, consumers, supporting
context and uncertain/potential paths separately.

A verified remediation needs a new permitted observation for the changed target,
a supported exact identity and compatible scope—not just a closed ticket, new
vendor questionnaire or automatically recomputed historical answer.
