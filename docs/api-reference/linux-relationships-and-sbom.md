# Linux relationship graph and CycloneDX software export

These read-only routes reuse the exact completed collection job, historical approved target and verified original intake. They do not collect or mutate evidence. Both use existing authenticated estate selection and the collection `host_read` rate bucket. Non-Linux/inconsistent/uncompleted evidence returns 409; foreign/unselected estate returns 404. Private/no-store response rules apply.

## Graph

`GET /api/v1/collection/jobs/{identifier}/relationships/linux`

Returns typed `LinuxRelationships`, schema version `cryptoscan.linux-relationships/v1`:

| Field | Meaning |
|---|---|
| `coverage` | Original `CoverageReport`, including all eight surface outcomes, exact approved-input failures and all six BOM reference counts |
| `nodes` | Every original `Observation`, not merged by path/package/name; maximum 1,000 |
| `edges` | Exact unambiguous metadata joins; maximum 1,000; each carries source/target observation IDs, supporting observation IDs, evidence IDs and a job-scoped deterministic digest ID |
| `edges[].local_basis` | Always INFERRED: deterministic derivation from captured fields, not a new OBSERVED fact or AI discovery |
| `edges[].basis` | EXACT_CAPTURED_FIELDS_NOT_ATTESTED_USAGE |
| `edges[].runtime_use`, `production_traffic_proven` | UNKNOWN / false |
| `unresolved` | Per-observation join outcomes: missing evidence, ambiguous evidence or no reported unit; no asset-absence inference |
| `unresolved[].candidate_count` | Actual candidate count, up to 1,000 |
| `unresolved[].candidate_observation_ids` | At most first 20 sorted IDs, with explicit `candidate_list_truncated` |
| `unsupported_relationships` | Fixed six unsupported patterns documented below |
| `provenance` | IMPORTED; does not change nodes' original OBSERVED/DECLARED basis |
| `relationship_completeness_proven`, `host_identity_attested`, `production_execution_qualified` | Always false |
| `materialized_without_collection` | Always true |

Supported edges:

- `PROCESS_HAS_MAPPED_PATH`: exact `(boot_id, pid, process_start_ticks)` match to exactly one captured process observation.
- `PROCESS_REPORTS_SERVICE_UNIT`: non-null captured process service-unit name exactly matches one captured service observation. MainPID is never used as the correlation key.

Unsupported patterns: service MainPID → process incarnation; listener → process; configuration → service; certificate → listener; hardware → application/key; package → binary/library. Same host, path similarity or equal PID alone cannot justify these edges. Separate input captures do not prove simultaneous operation. Missing observations stay gaps.

The typed response reconciles all input node counts and all six BOM reference counts, checks fact digests/domain/source consistency, and recomputes the allowed edges/unresolved outcomes. These checks are consistency guards, not cryptographic proof of host truth. The API additionally verifies stored originals and exact authorized target binding before projection.

## Standard software document

`GET /api/v1/collection/jobs/{identifier}/software/linux/cyclonedx-1.6`

Returns a raw standard CycloneDX 1.6 JSON document, **not a custom response wrapper**:

- `Content-Type: application/vnd.cyclonedx+json`
- `Content-Disposition: attachment; filename="linux-software.cdx.json"`
- `X-CryptoScan-Validation: CYCLONEDX_1_6_OFFICIAL_SCHEMA_AND_REFERENCES`
- private/no-store caching behavior.

Builds from the existing `LinuxSoftwareInventory`. Unambiguous package groups become components with known version only; unknown software nature uses the official specification's `application` fallback, explicitly annotated as **not an observed application classification**. Approved binary presence becomes `file`. Ambiguous groups and mapped paths are omitted with metadata counts/references. No license/purl/package artifact hash, artificial dependency, root fanout or dependency-free leaf is created.

Native `compositions` declares aggregate `incomplete`. Namespaced properties retain source/evidence/fact/envelope bindings, approved/failed package-input counts and statuses, local-vs-transport basis, omissions and unknowns. Deterministic references/serial number support repeatable historical reads, not global asset attestation.

The document is validated on **every return** using the existing pinned official BOM/SPDX/JSF schemas and offline reference registry. Missing/modified schemas or invalid output returns **503**, with no standard document and no successful download. The header is a server validation statement, not a signature, production clearance or proof of inventory completeness.

The original `/software/linux` endpoint remains an intermediate nonstandard response; its schema/flags are unchanged. The graph's metadata joins are never reinterpreted as SBOM dependencies.

See [guide 71](../bank-environment/71-linux-relationships-and-validated-sbom.md) for practical interpretation and engineering/external qualification gates.
