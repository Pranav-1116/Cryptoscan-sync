# Data model, evidence, and data flow

## 1. The data contract

CryptoScan keeps a distinction between an observation, an asset, a finding, a
risk decision, and an export. Combining these concepts would make it
impossible to explain why a result exists or whether it has changed.

| Object | Meaning | Can it be changed? |
|---|---|---|
| Observation | What a collector saw at a source and time | New observations are appended; original provenance is retained |
| Evidence record | Canonical, redacted, hashed representation of an observation | Integrity fields are not edited in place |
| Crypto asset | Normalized identity representing one algorithm, key, certificate, library, or related object | Relationships and later observations evolve; provenance remains |
| Finding | Policy or detector result for an asset in a scope | Re-evaluated by new evidence or policy; historical result remains traceable |
| System | Owned application, service, account, or estate boundary | Owner, criticality, and tags may be maintained by authorized users |
| Baseline | Approved reference state for drift comparison | New approvals create new versions; old versions remain evidence |
| Work item | Remediation, review, exception, or migration action | Lifecycle is audited |
| Snapshot/export | Point-in-time materialization for reporting or exchange | New versions are created; delivered package is retained |

## 2. Canonical evidence chain

The evidence process is conceptually:

```text
raw observation
  -> privacy classification and redaction
  -> canonical JSON representation
  -> content hash
  -> chain hash with previous record
  -> evidence row and scan manifest
  -> verification record
```

The exact hash formula and fields are defined in the [evidence-chain design](../../architecture/evidence-chain.md)
and implementation. The important guarantees are:

- a later database edit should be detectable;
- a missing or reordered record should break the chain;
- a report can cite stable evidence identifiers;
- the original secret or private value is not required in the record; and
- an auditor can verify the package without trusting a UI screenshot.

Hashing does not make a false observation true. It proves the bytes that were
hashed and linked; source authorization, parser correctness, and deployment
scope still require review.

## 3. Normalization and identity

Collectors use different names and vocabularies. Normalization maps aliases
such as library spellings, protocol names, modes, key sizes, certificate
properties, and provider fields into a canonical model.

Deduplication combines observations only when the identity rules support it.
The merged asset retains links to each source observation. A source scan and a
runtime report may refer to one asset, but they must not erase the fact that
two independent observations existed.

When identity is ambiguous:

- keep separate records or mark the match uncertain;
- expose the reason and confidence;
- request operator confirmation where appropriate; and
- do not inflate coverage by merging unrelated assets.

## 4. Data flow by stage

### Collection

The source or connector returns observations plus scope, source, revision,
parser/scanner, timestamps, and any reachability or permission warnings.

### Evidence

The privacy layer removes or fingerprints sensitive values according to
policy. The evidence layer canonicalizes and chains the safe representation.

### Inventory

The normalized asset, system, certificate, dependency, vendor, hardware, and
key metadata relationships are persisted. The inventory supports both current
state and historical observations.

### Assessment

The policy engine evaluates each applicable rule against the evidence and
scope. Drift compares the current inventory with an approved baseline. Graph,
business, PQC, agility, and anomaly services add analysis without replacing
source evidence.

### Workflow

Finding results can create remediation work, SLA clocks, alerts, tickets,
exceptions, migration tasks, or CI gates. Each action has its own owner and
approval; it does not mutate the underlying observation.

### Export

Reports and BOMs select a declared time range, scope, policy version, and
format. The export should include a manifest, source references, content hash,
signature where configured, and limitations.

## 5. Technology BOM family

CryptoScan uses one underlying inventory and bounded scan evidence with multiple
correlated views:

- **SBOM:** software components and dependencies;
- **CBOM:** cryptographic algorithms, libraries, keys, protocols, and usages;
- **HBOM:** hardware and firmware context;
- **NBOM:** authorized network observations when a network scan supplies them;
  binary-derived NBOM records are static capability candidates and carry
  `observed: false` until separately corroborated;
- **VBOM:** vendors, products, services, and supply-chain relationships;
- **Vulnerability BOM:** a separate normalized findings view for weak or
  deprecated algorithms, hardening failures, malformed/truncated/refused
  artifacts, and supplied advisory/package matches; it is not VBOM; and
- **Technology-BOM snapshot:** the deterministic, tenant-scoped correlation of
  stable component references, evidence states, provenance, fingerprints and
  per-layer bundle diffs.

These are not independent truths. A CBOM component should link back to bounded
source or binary evidence and the owning system; a vendor relationship should
not be treated as proof that every vendor product is deployed; and imported
socket/TLS APIs must not be represented as live network exposure.

## 6. Retention and deletion

Retention is a deployment and contract decision. Define separate periods for:

- raw input or temporary workspace;
- redacted evidence;
- findings and workflow records;
- audit logs;
- exported reports and delivered packs;
- backups and immutable copies; and
- customer deletion or legal hold.

Deletion must record scope, trigger, systems, exceptions, backup behavior, and
verification. Immutable evidence or legal holds may require a documented
exception rather than an unsupported claim of immediate deletion everywhere.

## 7. Data quality states

Every collection and analysis path should be able to express:

- `PASS` — the evaluated condition passed for the declared scope;
- `FAIL` — the condition failed and evidence supports the result;
- `WARN` — a condition needs attention but is not a hard failure;
- `UNKNOWN` — required evidence or interpretation is missing;
- `SKIPPED` — the object was intentionally not evaluated, with reason;
- `BLOCKED` — authorization, safety, or policy stopped collection;
- `NOT_EVALUATED` — no applicable rule or source data was available; and
- `ERROR` — processing failed and requires operator action.

Consumers must preserve these states. Replacing them with zero, empty, or
PASS makes a report less reliable than the underlying scan.

## Current-reading update — 2026-10-22

Keep SBOM, CBOM, NBOM, TechBOM, HBOM and VBOM distinct. Source receipt completeness applies only to primary discovered files, not the whole estate. Migration **0105** widens monitor event types; it does not change launch-approval or evidence truth semantics.

See [current implementation status](../../CURRENT-IMPLEMENTATION-STATUS.md),
[CI/build contract](../../CI-WORKFLOW-AND-PRODUCT-BUILD-PLAN.md) and
[operator install/upgrade/recover](../../runbooks/operator-install-upgrade-recover.md).
