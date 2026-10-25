# Read-only collection surface coverage

```text
GET /api/v1/collection/jobs/{job_id}/coverage/surfaces
```

New typed response: **`cryptoscan.collection-surface-coverage/v1`** (`CoverageReport` in `shared_models.collection_coverage`). The existing flat `/coverage` endpoint and the committed `cryptoscan.collection-evidence/v1` envelope are unchanged. OpenAPI exposes the new response model.

## Boundary

Uses the existing authenticated selected-estate read/residency boundary and development-only universal collection admission. A foreign job (including an unselected platform administrator looking for tenant data) returns 404. Production universal-adapter admission remains blocked. There is no POST, arbitrary command/address, credential parameter, network discovery, new scan, implicit retry or remote execution on this route.

The job must have committed COMPLETED/PARTIAL/FAILED evidence. The platform reopens and verifies that evidence, then resolves **the job's exact authorized target revision**, not the target's newer edited scope. It checks the target/envelope commitments and validates observations, approved input identities, source kind/path/host binding, fact hashes, deterministic domain assignment, error membership, duplicate IDs/ordinals and denominators. Invalid/mutated evidence refuses with 409, never a stale-success fallback.

Withdrawal does not erase valid historic evidence or authorize new work. A report is explicitly tied to the original claimed collection window, target revision and envelope hash; it is not live estate inventory or source authentication. A hash alone is not authenticity.

## Response

| Field | Meaning |
|---|---|
| `job_id`, `target_id`, `target_revision`, `target_sha256` | Exact committed collection scope |
| `system_id`, `environment` | Original scoped system context |
| `started_at`, `finished_at` | Retained aware collection window, not attested UTC |
| `envelope_sha256` | Same evidence commitment used by the six projections |
| `provenance` | IMPORTED transport provenance |
| `basis` | EXACT_AUTHORIZED_MANIFEST_INPUTS_NOT_ESTATE_INVENTORY |
| `surfaces` | All eight supported input-surface states, including NOT_REQUESTED |
| `bom_observation_counts` | All six BOM reference counts; one observation can feed several domains |
| `whole_host_percent` | Always null; no complete inventory denominator exists |
| `whole_host_coverage_verified`, `asset_absence_proven`, `production_execution_qualified` | Always false |
| `materialized_without_collection` | Always true |

Surfaces: `os`, `software`, `certificates`, `crypto_configuration`, `processes_and_libraries`, `services`, `network_listeners`, `hardware_metadata`. The mapping covers every current typed host input kind exactly once; a new input kind without explicit mapping fails the engineering contract test. This is not a capability claim for future container/cloud/vendor/OT adapters.

The Windows [TPM device-info candidate](windows-tpm-device-info-candidate.md) maps only to `hardware_metadata`, with HBOM/TechBOM reference classification. This adds no attestation/firmware/key-use truth and does not bypass blocked universal Windows admission.

The [bounded Windows metadata extension](windows-bounded-metadata.md) maps CAPI default selection to `crypto_configuration` and TCP table metadata to `network_listeners`. TCP table observation count is not endpoint-row count; even an empty observed table cannot prove absence. These mappings do not enable universal Windows admission.

Each surface contains:

- `approved_inputs`, `parsed_inputs`, `failed_inputs`, `fact_count`.
- `outcome`: NOT_REQUESTED, FAILED, PARTIAL, PARSED_WITH_FACTS or PARSED_NO_FACTS.
- `approved_input_parse_percent`: rounded parsed/approved input ratio, **null when not requested**. It measures successful parsing of explicitly approved inputs only, not actual asset discovery/completeness/confidence. A 100% value still keeps `complete_surface_coverage_verified=false`.
- `inputs`: original input ID/kind/status/reason, fact count, unique retained evidence IDs, separate local OBSERVED/DECLARED counts and `asset_absence_proven=false`.

Every surface reconciles its totals to input rows. Failed inputs cannot have facts. Evidence/local-basis counts reconcile to facts. All six BOM keys must be present; reference counts cannot exceed facts or manufacture additional TechBOM observations. The result is deterministic for unchanged committed evidence and contains no inferred software usage, negotiated TLS, hardware origin or vendor relationship.

### Important distinctions

- IMPORTED transport does not make a source declaration OBSERVED.
- Missing, DENIED, UNAVAILABLE, UNSUPPORTED, INVALID and BUDGET_EXCEEDED inputs remain explicit gaps, never NO_ASSET.
- NOT_REQUESTED has no denominator; it is different from an approved input that failed.
- PARSED_NO_FACTS is not absence proof, even if input parsing reports 100%.
- Six reference counts are not six collectors, six complete BOM documents or six independent inventories. No CycloneDX conformance claim is made by this endpoint.
- Library/package/mapped-path presence does not establish algorithm invocation. Listener metadata does not establish TLS. Hardware co-existence does not establish application HSM use. VBOM references require actual supported vendor evidence/relationships.

The console section is in the existing CBOM host-evidence area. It is read-only, never auto-loads/retries, bounds reads at 20 seconds and clears/fences old state on job/tenant/auth/storage/resume/history changes. No new dashboard or service is introduced.

See [phase-wise build and advancement gates](../bank-environment/69-phasewise-universal-collection-build.md) and [validation record](../readiness-evidence/phasewise-foundation-2026-10-25.md).
