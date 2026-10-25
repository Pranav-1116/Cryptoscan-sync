# Linux software inventory (intermediate metadata)

`GET /api/v1/collection/jobs/{identifier}/software/linux`

Uses the same authenticated estate selection, `host_read` rate bucket, historical authorized target and original-evidence verification as the existing collection evidence/coverage routes. There is no write endpoint, collector call or automatic refresh. Returns `LinuxSoftwareInventory` (`cryptoscan.linux-software-inventory/v1`); unsupported scope or evidence inconsistency returns 409, unselected/foreign estate returns 404.

| Field | Contract |
|---|---|
| `coverage` | Existing `CoverageReport` with original job/target/revision/envelope bindings and approved-input outcomes |
| `package_inputs` | Package input outcomes only: DPKG_STATUS, APK_INSTALLED, RPM_SQLITE; retains failures/reasons |
| `packages` | Scoped metadata groups; dpkg/apk/rpm name, known version or null, full original observations |
| `identity_status` (group) | SINGLE_RECORD or MULTIPLE_RECORDS_UNRESOLVED; latter always has null version |
| `binary_presence` | Original BINARY / BINARY_METADATA observations, not package identities |
| `mapped_library_paths` | Original LOADED_LIBRARY / LINUX_PROCESS_MAPS observations, not invocation |
| `provenance` | IMPORTED, without changing observations' original local basis |
| `standard_document` | Always false; not a CycloneDX export |
| `dependencies_complete`, `installed_package_inventory_complete` | Always false |
| `host_identity_attested`, `production_execution_qualified` | Always false |
| `materialized_without_collection` | Always true |

All lists remain subject to existing approved-input / 1,000-fact limits. The total records across the three classes must reconcile to the same envelope's SBOM observation-reference count; that count is not inventory completeness. Groups are sorted by scoped metadata slot and preserve original record order. Multiple records are never deduplicated by choosing the latest version.

Per group, `architecture`, `licenses`, `dependencies`, `runtime_use` and `cryptographic_use` remain UNKNOWN; `purl` and `package_artifact_sha256` remain null. Source-content/fact/envelope hashes do not imply artifact hashes or authenticity. This is a deterministic evidence projection, not a rescan, an AI inference, an installed-package health assessment or production qualification.

See [guide 70](../bank-environment/70-linux-software-evidence-phase-two.md) for operator interpretation, interface use, source-lock impact and remaining Phase 2 gates.
