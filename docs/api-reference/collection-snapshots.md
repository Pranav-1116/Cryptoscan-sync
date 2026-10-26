# Collection snapshots and metadata drift API

Base path: `/api/v1/collection`. Existing authentication, exact selected-estate history access and residency checks apply. POST additionally requires a current typed human session with `assurance.manage`. Platform administrators must explicitly select the estate. No endpoint executes a collector or enables controlled production.

[Architecture / identity semantics](../bank-environment/85-shared-collection-snapshots-and-drift.md) · [Runbook](../runbooks/collection-snapshots.md) · [Executed evidence](../readiness-evidence/collection-snapshots-2026-10-26.md).

## Endpoints

| Method / path | Result |
|---|---|
| `POST /snapshots` | 201 immutable assurance record containing common snapshot, six views, metadata graph and approved-input coverage counts |
| `GET /snapshots?limit=10&cursor=…` | Bounded source-revalidated summaries; `next_cursor` is null on the final page |
| `GET /snapshots/{snapshot_id}` | Immutable record after original-source and deterministic-view revalidation |
| `POST /metadata-drift` | 201 immutable comparison record after reopening both snapshots |
| `GET /metadata-drift/{drift_id}` | Immutable comparison after reopening sources and recomputing drift |

IDs in paths are assurance **subject IDs**, not the internal revision row's `id`. POST returns `subject_id`; preserve that for subsequent requests. GET responses use `Cache-Control: no-store` through the existing history middleware.

## Create snapshot

Only committed sources are accepted:

- `family="host"`: a completed/partial/failed `/collection/jobs/{job_id}` whose original host intake and envelope commitment remain valid. This is not arbitrary standalone `/host-evidence` or scan ingestion.
- `family="oci"`: a completed/partial/failed `/collection/oci/jobs/{job_id}` with an original bound OCI return, verified authorization/job/evidence/consumption chain and source digest.

```json
{
  "family": "host",
  "job_id": "11111111-1111-1111-1111-111111111111",
  "expected_source_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

The UUID/hash above are placeholders, not usable evidence. Resolve the exact real source commitment before POST:

- Host: `GET /api/v1/collection/jobs/{job_id}/evidence` → `envelope_sha256`. This is the canonical validated envelope **excluding** its `envelope_sha256` field.
- OCI: `GET /api/v1/collection/oci/jobs/{job_id}/evidence` returns the original `OciJobReturn` directly → SHA256 of its canonical typed `.evidence`, using `shared_models.host_collection.digest`. This is **not** the capture-binding digest, whole-return digest, registry revision hash or raw HTTP JSON byte hash.

Request keys are exact; extra observations, raw files, claims or caller-provided graph nodes are refused with 422. The server alone constructs references from retained source evidence. A mismatched expected source digest returns 409 without persisting anything.

### Stored payload shape

```text
assurance record
  subject_id / revision=1 / payload_sha256 / created_by
  payload
    snapshot
      schema_version = cryptoscan.collection-snapshot/v1
      family / job_id / target_id / system_id / environment
      source_sha256 / started_at / finished_at
      inputs[]
        input_id / kind / path / status / reason / input_basis
        asset_absence_proven=false
      observations[]
        observation_id / identity_slot / identity_basis
        input_id / fact_kind / fact_sha256 / evidence_id
        provenance=IMPORTED / local_basis / domains[]
      whole_asset_coverage_verified=false
      source_authenticity_verified=false
      runtime_use=UNKNOWN / production_execution_qualified=false
    snapshot_sha256
    domains.{SBOM,CBOM,NBOM,HBOM,VBOM,TechBOM}
      observation_ids[] / complete=false / state
    coverage
      basis=APPROVED_INPUTS_ONLY / approved_inputs / parsed_inputs
      whole_asset_percent=null
    metadata_graph
      nodes[] / edges[] / operational_relationships_inferred=false
    standard_document=false / materialized_without_collection=true
```

The immutable revision commits the complete payload, including derived views. `snapshot_sha256` commits the normalized `snapshot` object; it is not interchangeable with `source_sha256` or the revision's `payload_sha256`.

Observation references preserve local `OBSERVED` versus `DECLARED` basis separately from imported provenance. `identity_basis=SCOPED_METADATA_SLOT_NOT_ATTESTED_ASSET` deliberately disclaims physical identity. The graph includes only `HAS_METADATA_REFERENCE`; it does not populate the separate operational dependency graph.

OCI vendor context has an `oci-declaration:` reference derived from the retained evidence and declaration state, supported by the pinned image config. It is not a SQL evidence-record UUID. Its `PINNED_IMAGE_CONFIG` source is excluded from the selected-file coverage denominator. A missing vendor remains unknown, not an assured supplier absence.

## Pagination

`limit` defaults to 10, range 1–20. `cursor` is the previous `next_cursor`, ordered by subject ID, not collection time. Each summary includes:

```text
snapshot_id / snapshot_sha256 / family / job_id / target_id
system_id / environment / started_at / finished_at
source_revalidated=true
```

A failed original-source revalidation fails the page rather than silently omitting a corrupted snapshot. Revalidation reflects that read, not a future integrity guarantee. There is no offset-based or cross-estate listing.

## Create metadata drift

```json
{
  "baseline_snapshot_id": "11111111-1111-1111-1111-111111111111",
  "candidate_snapshot_id": "22222222-2222-2222-2222-222222222222"
}
```

Use actual subject IDs returned from snapshot creation. The two snapshots must be distinct, same family/registered target/system/environment, with candidate capture starting no earlier than baseline capture finishes. Choosing a baseline here does not approve a business baseline or create a remediation task/alert.

The stored payload pins both snapshot revision hashes and contains:

- report schema `cryptoscan.collection-drift/v1`;
- baseline/candidate normalized snapshot hashes;
- `unchanged_slots` and `changes[]`;
- per-change slot, state, baseline/candidate observation IDs and full fact-hash **counts**;
- original baseline/candidate input dispositions;
- false whole-asset coverage and installation/removal/absence claims; operational use `UNKNOWN`.

States: `CHANGED_METADATA_RECORD`, `NEW_METADATA_RECORD`, `NEWLY_OBSERVABLE_METADATA`, `NOT_REOBSERVED_IN_PARSED_INPUT`, `UNRESOLVED_COLLECTION_GAP`, `OUT_OF_COMPARISON_SCOPE`. Equal fact multisets contribute only to `unchanged_slots`. See Guide 85 for exact meanings and examples. An unavailable input never becomes a removed-asset event.

## Refusal and retry behavior

| Status | Examples |
|---|---|
| 401 / 403 | Authentication/current human permission failure; readers cannot POST |
| 404 | Root job/snapshot/drift not in the exact selected estate |
| 409 | Nonterminal source; expected hash mismatch; original closure changed; immutable duplicate; incompatible/reversed comparison; changed graph/report even after local resealing; controlled-production boundary |
| 413 | Existing 1.5 MB assurance payload budget exceeded; no truncation/partial materialization |
| 422 | Invalid body/UUID/hash/family, unknown fields, same snapshot IDs, list limits outside 1–20 |

On duplicate POST, use GET with the subject ID from the successful creator or snapshot listing. Do not retry by changing the expected source hash or forging an earlier collection timestamp. Audit/storage failures roll back the transaction; unexpected server errors are not success receipts.

Historical snapshots may be created/read after collection authorization is revoked: this authorizes no new collection. Existing handoff/intake authority and separate OCI truth review are unchanged. A snapshot is not truth approval, production qualification or independent bank acceptance.

## Contracts

- [Snapshot schema](../../shared/shared_models/shared_models/schemas/collection-snapshot-v1.schema.json)
- [Snapshot request schema](../../shared/shared_models/shared_models/schemas/collection-snapshot-request-v1.schema.json)
- [Drift request schema](../../shared/shared_models/shared_models/schemas/collection-drift-request-v1.schema.json)
- [Shared model / deterministic materialization](../../shared/shared_models/shared_models/collection_views.py)
- [Existing-store adapter](../../services/api/api/assurance/collection_views.py)
- [Router](../../services/api/api/routers/collection_views.py)

Schemas validate structure; cross-reference, source commitment, time ordering and non-promotion invariants also require the typed model and retained-source checks. Hashes are unsigned integrity, not authenticity.
