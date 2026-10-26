# Offline OCI image evidence contracts

This increment adds a local typed candidate and pure materializer. **No HTTP endpoint, database migration, scheduler profile or production allowlist entry is added.** Existing `/collection` host target/job contracts retain their existing behavior; an `OciTarget` is not accepted as a `TargetSpec` or `HostSnapshot`.

## Versioned models

| Model | Schema | Purpose |
|---|---|---|
| `OciTarget` | [oci-target-v1](../../shared/shared_models/shared_models/schemas/oci-target-v1.schema.json) | Exact local layout, immutable manifest SHA256, architecture, declared system/environment, authorization reference, time window and metadata inputs |
| `OciEvidence` | [oci-evidence-v1](../../shared/shared_models/shared_models/schemas/oci-evidence-v1.schema.json) | Original target and canonical commitment, timestamps, ordered blob commitments/diff IDs, declarations, typed receipts, status and coverage |
| `OciProjection` | [oci-six-bom-projection-v1](../../shared/shared_models/shared_models/schemas/oci-six-bom-projection-v1.schema.json) | Deterministic six-view result over retained evidence; not CycloneDX and not graph persistence |

Schemas match `model_json_schema()` exactly and are checked with Draft 2020-12. Python model validators additionally enforce timestamp awareness/order/window, target commitment, exact ordered input coverage, blob roles/identities, layer source membership, status/fact consistency and no claim promotion. JSON Schema alone does **not** run those relational validators or establish source truth.

## Python runtime

```python
from inventory.oci_evidence import OfflineOciCollector
from shared_models.oci_collection import OciTarget
from shared_models.oci_projection import materialize_oci
from shared_models.host_collection import digest

# Parse approved plan bytes; agreed_target_digest was independently provisioned.
target = OciTarget.model_validate_json(approved_plan_bytes)
adapter = OfflineOciCollector(agreed_target_digest)
adapter.validate_scope(target)
evidence = adapter.collect(target)  # exact local blobs only, no BOM generation

# Retain evidence before a separate review/materialization step.
# agreed_evidence_digest must identify the reviewed retained object.
views = materialize_oci(evidence, agreed_evidence_digest)
```

`digest` is the existing canonical model/JSON digest function. It is not a signature or authenticity mechanism. Do not derive the approval from an untrusted return and treat the equality as independent review.

The runtime does not expose a generic command, tag resolver, arbitrary URL, credential loader, daemon socket or image execution option. `health()` reports `OFFLINE_CANDIDATE_NOT_SERVER_ADMITTED` and `production_execution_qualified=false`.

## Evidence rules

- Top-level provenance is `IMPORTED`; typed `HostFact` preserves its local `OBSERVED` metadata or `DECLARED` configuration basis.
- Each selected input has exactly one ordered `ImageReceipt` with content/layer SHA256 where available; raw bytes are omitted.
- `PARSED` requires nonempty typed facts and original source commitments. Failed receipts have no facts and never prove asset absence.
- `COMPLETED` = every approved input parsed; `PARTIAL` = some; `FAILED` = none.
- `coverage.basis` is `APPROVED_METADATA_INPUTS_ONLY`; its counts must match receipts. `whole_image_percent=null` always.
- Ordered blob references are manifest, config, then each layer. The collector checks actual blob bytes, descriptor sizes and uncompressed diff IDs; result validation checks internal consistency, not original-byte execution or producer authenticity.
- Original OCI config environment, commands, arbitrary labels, file contents and private keys are never output. Only allowlisted bounded public vendor/base labels and declared ports are emitted.
- Caller mutation of nested model lists is revalidated at collection/materialization boundaries.

## Projection rules

`materialize_oci` is pure: no file/network/database/collector calls. It revalidates the typed retained object and exact agreed canonical digest. Shared facts have the same image-scoped `evidence_id`, path, layer/content commitments and provenance in every view.

- SBOM: `SOFTWARE` and `BINARY` metadata.
- CBOM: `CERTIFICATE` and `TLS_CONFIGURATION` only, not algorithm capability or invocation inferred from package names.
- NBOM/HBOM: unknown for this image-only evidence.
- VBOM: explicit vendor label as declared-only, not verified vendor identity.
- TechBOM: all of the same metadata references, with `CONTAINS_METADATA_RECORD`, not runtime `USES` edges.

All views set `complete=false`; `cyclonedx_export=false`, `graph_persisted=false`, `runtime_use=UNKNOWN`, `pqc_readiness=UNKNOWN`. Base-image claims and exposed ports remain declarations in original evidence and do not create live endpoints/hardware or resolve another image.

See [Guide 68](../bank-environment/68-offline-oci-image-collection.md) for bounds and unsupported formats, [the operator runbook](../runbooks/offline-oci-image-evidence.md) for commands, and [engineering evidence](../readiness-evidence/offline-oci-image-2026-10-25.md) for what actually ran.
