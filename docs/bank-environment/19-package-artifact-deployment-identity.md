# 19 — Implemented step 3: package SBOM, release artifact and application identity

[Guide index](README.md) · [Shared relationship policy](18-shared-dependency-semantics.md) ·
[Engineering plan](../dev/dependency-intelligence-roadmap.md)

## 1. The join is explicit, not a filename guess

The implemented chain is:

```text
versioned package PURL in a stored SBOM
  -> pinned SBOM-to-release assertion (document SHA-256 and component references)
  -> release artifact identified by sha256:<64 hex characters>
  -> explicit deployment assertion (revision key, environment, registered System ID)
  -> application/system dependency consumers and supporting context
```

This is an additive relational/twin/unified-cascade feature using
`cryptoscan.software-supply-chain/1`. It does not replace the standalone SBOM
workflow or redefine the existing TechBOM application-oriented `sbom` layer as a
package inventory. Package nodes are not silently turned into registered systems
or injected into the raw Neo4j/memory visualization. The Cross-BOM panel is the UI
for the joined cascade evidence; declaration authoring is through the new API.

A source tree, executable filename, image tag, package name or coincident scan
path does **not** create this chain. An SBOM alone has no implied bank consumers.

## 2. Three independent identities and evidence boundaries

| Identity | Stored fields | What it does and does not establish |
|---|---|---|
| Package | Exact version-bearing `package_identity`/PURL, version/ecosystem, original CycloneDX `bom-ref` or SPDX `SPDXID` | Declared membership in that document; not executed code, exploit reachability or an installed production package by itself |
| SBOM document | Existing artifact-store ID, SHA-256 of exact stored plaintext bytes, pinned normalized component projection | Which document was checked when bound; its SHA is **not** an executable/image digest |
| Release artifact | Separate `software_artifacts.id`, canonical `sha256:…`, media type, identity source, optional measured byte count, evidence reference | Immutable content identifier, either declared or actually computed over uploaded bytes; neither authenticates a supplier nor proves deployment |
| Deployment assertion | Release ID, exact registered `system_id`, required environment, immutable API binding under a deployment/revision key, source/evidence/actor | An explicit declared association, not independently observed current runtime state |

Evidence sources are not interchangeable:

- `SUPPLIER_DECLARED`: an authorized operator records a supplier assertion. No
  supplier-signature or external-attestation verification is implied.
- `OPERATOR_DECLARED`: the bank operator supplies a digest or linkage assertion.
  A well-formed digest does not prove the server has inspected the release bytes.
- `CONTENT_HASHED`: the measurement endpoint computes the release digest from
  actual uploaded bytes. This label is available only from that endpoint, not a
  declaration request. It does not upgrade SBOM linkage or deployment to observed.

Evidence references are required, nonblank references supplied by the authorized
caller. Their external contents/approval are not fetched or verified. Timestamps
record creation, not a fabricated observation or freshness guarantee.

## 3. Persistent models and migration

Migration **0098** adds:

1. `software_artifacts`: tenant-scoped unique content digest, distinct from the
   older binary-scan index's SBOM-document digest.
2. `release_sbom_bindings`: release-to-stored-SBOM assertion with document hash,
   component copy and unresolved-identity count.
3. `software_deployments`: release-to-registered-System assertion with explicit
   environment and deployment/revision identity.

No alternate deployment database or process-memory registry is introduced. The
existing artifact store retains SBOM documents; SQL retains the join records and
component projection so a twin replay need not reread a live file.

After the bank's normal backup/change approval, apply the repository migration:

```bash
python -m alembic -c services/database/migrations/alembic.ini upgrade head
```

Database connection configuration must already be provided through the approved
runtime configuration. Do not put credentials in chat or command examples.
Production initialization requires current migrations; it does not backfill
these joins from old filenames, tags or package-name guesses.

Identical writes are idempotent and retain the original record/actor. Conflicting
identity, source/evidence, SBOM content or deployment-key reuse returns **409**;
the record is not overwritten. A concurrent unique-key race also returns 409;
retrying allows inspection of the committed assertion. There is no update/delete
API in this delivery. This is write-once **API behavior**, not a claim privileged
SQL administrators cannot alter the database.

New rollout revisions require new deployment keys. [Step 4](20-relationship-lifecycle-and-reconciliation.md)
now adds explicit lifecycle/reconciliation while retaining old assertion identity;
these declarations must not be sold as a verified list of deployments running now. A declaration cannot silently become
`CONTENT_HASHED` by retrying through another endpoint.

**Downgrade is destructive for these three new tables.** Export/review the
assertions before any approved rollback; the migration preserves older system
rows but deliberately drops the new join records.

## 4. API contract

All paths below are under the authenticated API ingress.

| Method/path | Meaning |
|---|---|
| `POST /api/v1/software-supply-chain/sboms` | Store an external CycloneDX/SPDX JSON SBOM in the existing tenant artifact store; no release or deployment inferred |
| `POST /api/v1/software-supply-chain/artifacts` | Register a canonical SHA-256 release digest declaration with required source/evidence |
| `POST /api/v1/software-supply-chain/artifacts/measure` | Stream raw `application/octet-stream` bytes, compute SHA-256, discard bytes and retain measured identity; required `evidence_ref` query parameter |
| `POST /api/v1/software-supply-chain/artifacts/{artifact_id}/sboms` | Bind an existing authorized SBOM, checking actual bytes against both manifest SHA and caller's expected SHA; pin components |
| `POST /api/v1/software-supply-chain/artifacts/{artifact_id}/deployments` | Declare an exact application/system/environment/revision binding |
| `GET /api/v1/software-supply-chain/artifacts` | Exact-estate artifact list, default 100, maximum 500, explicit truncation flag |
| `GET /api/v1/software-supply-chain/artifacts/{artifact_id}` | Release identity, bounded SBOM-binding metadata and deployment declarations |

New writes require admin/superadmin/security-analyst roles. Inspection uses the
same authenticated, selected-estate read policy as twin/cascade/history, rather
than pretending a stricter artifact-list gate also protects those existing
surfaces. Read-only/auditor/developer principals can inspect their selected
estate, but cannot author these joins. Per-system ownership/resource-grant
qualification is still step 10; this is not an own-systems-only authorization
claim. Write gates use existing RBAC, including its documented legacy
unprovisioned-role fallback; no universal bank-approval workflow is claimed.

Rows and artifact-store reads use the exact selected tenant, including an exact
platform estate for callers without a selected tenant. Shared platform visibility
elsewhere in the ORM does **not** authorize a bank to adopt a platform release or
system into these joins. Scope-key checks and composite release foreign keys
also constrain persisted ownership. Unknown/foreign release, SBOM or System IDs
are 404s; a known system's conflicting environment is a 409.

The existing source/container SBOM writer now stamps its selected tenant and
uses tenant-prefixed storage keys. Session callers whose tenant was selected by
middleware no longer need an explicit tenant header just to keep files and SQL
in the same estate. Legacy unstamped SBOMs remain platform artifacts; they are
not automatically transferred to a bank.

### Request shapes

An illustrative release declaration (the digest here is illustrative, not a
measured bank binary):

```json
{
  "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "media_type": "application/octet-stream",
  "assertion_source": "OPERATOR_DECLARED",
  "evidence_ref": "approved-build-record/release-17"
}
```

SBOM binding requires the **SBOM document** SHA from the actual returned manifest,
not the release digest. Deployment requires the actual registered System ID,
its environment and the approved revision key. The executable example below
builds those requests from real returned IDs.

## 5. Practical operator sequence

Use the restricted evidence directory and `bank_api` HTTPS helper from
[05](05-practical-bank-walkthrough.md). The following commands do real writes;
obtain authorization first. Do not enable shell tracing around credentials.

Set these variables from approved real inputs, not illustrative IDs: `SBOM_JSON`
(the supplier SBOM JSON file), `RELEASE_FILE` (the corresponding release bytes),
`SYSTEM_ID` (returned by registered-system creation/listing), `ENVIRONMENT`
(exact case/spelling), `DEPLOYMENT_KEY` (revision-specific deployment identity),
and the three evidence references. Select `PACKAGE_PURL` from that document's
exact versioned PURLs; do not substitute a broad library name.

```bash
: "${SBOM_JSON:?actual approved supplier SBOM JSON file}"
: "${RELEASE_FILE:?actual corresponding release file}"
: "${SYSTEM_ID:?actual registered System ID}"
: "${ENVIRONMENT:?exact registered environment}"
: "${DEPLOYMENT_KEY:?approved revision-specific deployment identity}"
: "${SUPPLIER_EVIDENCE_REF:?actual supplier assertion reference}"
: "${BUILD_EVIDENCE_REF:?actual build/release evidence reference}"
: "${DEPLOYMENT_EVIDENCE_REF:?actual deployment evidence reference}"
: "${PACKAGE_PURL:?exact versioned PURL selected from the SBOM}"

python3 - "$SBOM_JSON" "$SUPPLIER_EVIDENCE_REF" <<'PY' > store-sbom-request.json
import json, sys
print(json.dumps({"doc": json.load(open(sys.argv[1])),
                  "assertion_source": "SUPPLIER_DECLARED", "evidence_ref": sys.argv[2]}))
PY
bank_api POST /api/v1/software-supply-chain/sboms \
  --data-binary @store-sbom-request.json > stored-sbom.json

python3 - "$RELEASE_FILE" "$BUILD_EVIDENCE_REF" <<'PY' > release-request.json
import hashlib, json, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
print(json.dumps({"digest": "sha256:" + h.hexdigest(),
                  "assertion_source": "OPERATOR_DECLARED", "evidence_ref": sys.argv[2]}))
PY
bank_api POST /api/v1/software-supply-chain/artifacts \
  --data-binary @release-request.json > registered-release.json
RELEASE_ID=$(python3 -c 'import json; print(json.load(open("registered-release.json"))["id"])')

python3 - "$SUPPLIER_EVIDENCE_REF" <<'PY' > sbom-binding-request.json
import json, sys
s = json.load(open("stored-sbom.json"))
print(json.dumps({"sbom_artifact_id": s["artifact_id"],
                  "expected_sbom_sha256": s["manifest"]["sha256"],
                  "assertion_source": "SUPPLIER_DECLARED", "evidence_ref": sys.argv[1]}))
PY
bank_api POST "/api/v1/software-supply-chain/artifacts/$RELEASE_ID/sboms" \
  --data-binary @sbom-binding-request.json > sbom-binding.json

python3 - "$SYSTEM_ID" "$ENVIRONMENT" "$DEPLOYMENT_KEY" "$DEPLOYMENT_EVIDENCE_REF" <<'PY' > deployment-request.json
import json, sys
print(json.dumps({"system_id": sys.argv[1], "environment": sys.argv[2],
                  "deployment_key": sys.argv[3], "assertion_source": "OPERATOR_DECLARED",
                  "evidence_ref": sys.argv[4]}))
PY
bank_api POST "/api/v1/software-supply-chain/artifacts/$RELEASE_ID/deployments" \
  --data-binary @deployment-request.json > deployment-binding.json

python3 - "$PACKAGE_PURL" <<'PY' > package-cascade-request.json
import json, sys
print(json.dumps({"target": sys.argv[1], "kind": "package", "max_depth": 6}))
PY
bank_api POST /api/v1/technology-bom/cascade \
  --data-binary @package-cascade-request.json > package-cascade.json
```

The client-computed release digest above is still `OPERATOR_DECLARED` at the
server. Use the raw-byte measurement endpoint instead when server-side content
measurement is required and the release fits its limit; do not pretend the
JSON digest-declaration endpoint measured that file.

Source/container/binary scan-generated SBOMs can also be bound using their
existing returned artifact ID and manifest SHA; importing a supplier document
is not required for every workflow. The older stateless SBOM import endpoint
continues to normalize only; it does not silently persist or deploy anything.

## 6. Cascade behavior, counts, history and UI

`kind=package` requires an exact, usable version-bearing PURL from a bound SBOM.
Case, ecosystem, version, qualifiers and subpath remain significant; this is not
a general PURL-equivalence resolver. Missing/range/conflicting versions, mutable
version tokens and PURLs over the existing 500-character cascade input limit
remain unresolved. Their component rows/references are retained for review.
CycloneDX nested components are flattened within explicit depth/count bounds;
SPDX package identities and SPDX references are preserved. No component lacking
a usable PURL is guessed from its name.

`kind=artifact` accepts the registered release ID or `sha256:…`. Auto-detection
recognizes exact versioned package PURLs and prefixed artifact digests. Artifact
UUIDs require explicit kind so they cannot steal an existing system's auto target.

For `mobile -> payments -> ledger`, with the package bound only to the payments
release/deployment:

- Direct exposure: payments (1).
- Dependent consumers: mobile (1).
- Supporting context: ledger (1).
- Modeled exposure: 2; full review scope: 3.

Multiple replicas/SBOM assertions retain their evidence rows without counting
the same system repeatedly. Package rows identify declared document membership,
not automatic dependency exploit reachability. Current system relationship
propagation still follows [step 2](18-shared-dependency-semantics.md).

| Situation | Result boundary |
|---|---|
| Stored SBOM not bound to a release | No package auto-adoption; package target may be NOT_FOUND in the joined twin |
| Bound package/release, no valid deployment | INSUFFICIENT_DATA, zero known systems, explicit unbound release IDs; **not safe** |
| Deployment has missing system or conflicting environment in the supplied snapshot | Declaration retained for review but cannot seed system exposure |
| Explicit release/deployment, no package SBOM | Artifact target can name the linked system; package presence is not invented |
| Software input truncated | Coverage flag/warning; absent package/link is not proof of absence |

New results include `layers.software` with release digests, SBOM hashes and
binding references, package identities, deployment IDs/environments/sources,
unbound/unlinked IDs and coverage metadata. System targets also show the release
context explicitly associated with that system. The UI separates these digests
and declarations and warns about unbound/truncated data. It shows at most 20
rows per software collection, explicitly labeled; the returned evidence remains
in the full stored result.

New captures pin these collections for replay. A captured unbound release stays
unbound when replayed after a later live deployment declaration. Old captures
without software collections are not retroactively enriched. Cascade uses the
pinned component projection; it does **not** revalidate live artifact-store bytes
on every run. Hash checks at binding time are not a freshness guarantee.
Historical results and classified counts retain their existing immutability and
review-versus-exposure meaning. This step does not add software-specific
history/watch alert taxonomies.

## 7. Bounds and validation boundary

- Server-side raw artifact measurement: nonempty content, maximum **16 MiB**,
  bytes discarded after hashing. Large artifacts may use an explicit declared
  digest; that is not server-measured identity or authenticated registry evidence.
- Stored/imported binding SBOM: maximum **8 MiB** canonical/stored plaintext and
  **5,000** components, nested CycloneDX depth at most **32**; excessive input
  refuses binding instead of silently attaching a partial component set.
- Twin software projection: at most **2,000 artifacts**, **5,000 deployment
  assertions**, **200 SBOM bindings**, **20,000 component rows**; collection totals,
  returned counts and truncation are recorded. Core twin/system caps also apply.
- Artifact detail: at most 200 binding metadata rows and 500 deployment rows,
  with explicit truncation. It does not load all component documents for detail.

Local tests exercise real SQLite, the actual artifact store/importers and
session-authenticated tenant middleware, including foreign/platform IDs,
forged tenant selection, read-only denial, byte hashing, SHA mismatch/tampering,
conflicting identity, idempotence, nested components, unknown versions, capture
replay and migration upgrade/downgrade. This is **not** live PostgreSQL/registry,
Neo4j, browser, availability or bank production qualification.

Recorded local validation:

- **1,911 backend tests passed** across shared-model, CBOM, graph-engine,
  DevSecOps, database-unit and selected SBOM/binary/twin/cascade API suites.
  The final **96 focused checks** were re-run after tightening raw SBOM-owner
  validation; a normalized legacy bucket cannot authorize a foreign-owner join.
- One `pg_virtualenv`-dependent check was skipped; seven live PostgreSQL checks
  were deselected. The separate CI-workflow-contract module was excluded;
  no CI or live PostgreSQL success is claimed and no workflow was changed.
- **352 frontend tests passed across 37 files**, including release/SBOM hash
  separation, declared provenance and unbound/truncated software UI cases.
- TypeScript typecheck, production frontend build and documentation checks
  passed. The illustrative artifact request validates against its actual API
  model; the five Python request builders compile. Existing bank fixtures passed.
- Existing Pydantic/Starlette/Alembic deprecations and React test `act` warnings
  remain. No warning cleanup, browser certification or load claim is made.

Focused regression command:

```bash
export PYTHONPATH="$(find services shared -mindepth 1 -maxdepth 1 -type d | paste -sd:)"
python -m pytest -q -p no:xdist \
  shared/shared_models/tests/test_software_identity.py \
  services/devsecops/tests/test_software_identity.py \
  services/cbom/tests/test_software_cascade.py \
  services/api/tests/unit/test_software_supply_chain_api.py \
  services/database/tests/unit/test_software_supply_chain_migration.py
```

Source entry points:

- [Identity policy](../../shared/shared_models/shared_models/software_identity.py)
- [Persistent models](../../services/database/db/models/software_supply_chain.py)
  and [migration 0098](../../services/database/migrations/versions/0098_software_supply_chain.py)
- [API](../../services/api/api/routers/software_supply_chain.py) and
  [twin projection](../../services/api/api/software_supply_chain.py)
- [Pure joins](../../services/cbom/cbom/software_cascade.py) and
  [API regressions](../../services/api/tests/unit/test_software_supply_chain_api.py)

## 8. Still pending

[Step 4](20-relationship-lifecycle-and-reconciliation.md) now implements expiry,
supersession, stale/deleted deployments and conservative source reconciliation.
[Step 5](21-traversal-provenance-evidence-and-freshness.md) now carries bounded
path evidence/freshness and explicit software seed assertions.
[Step 6](22-business-process-impact-and-inclusion-reasons.md) now adds process
closure/inclusion reasons. Steps 7–10 cover general exact/ambiguous identity resolution, operational dependency
modes, broad coverage UX and bank-negative/backend qualification. This delivery
adds a usable explicit join, not automated discovery or verified current runtime
placement of every software release.
