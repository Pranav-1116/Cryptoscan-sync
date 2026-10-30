# CryptoScan — scanner and six BOM projections

Language-aware crypto scanning plus six BOM projections, correlation, policy and
remediation, served by `services/api`. Every surface below reads the estate's own
observations; none of them reads a fixture.

## What it owns

| Surface | Module | Real entry |
|---------|--------|------------|
| Static scanner | `services/scanner/scanner/registry/language_scanners.py:scan_file` | Runs per file inside the hostile-input bounds in `services/scanner/scanner/core/sandbox.py`; records `collector_source_sha256` and the parse outcome per file. |
| CBOM | `services/cbom/cbom/generator.py:CbomGenerator` + `services/cbom/cbom/component_registry.py:cbom_crypto_component` | `CbomGenerator.from_records(..., specVersion 1.5/1.6)` with `compositions: INCOMPLETE`, `evidence.occurrences`, confidence propagation. |
| SBOM | `services/cbom/cbom/technology_bom.py` SBOM layer + `services/devsecops/devsecops/sbom.py`, `services/container_scanner` | SBOM layer as `app_component` projection; CycloneDX 1.5/1.6 validation via `services/cbom/cbom/cyclonedx16.py`, document integrity via `services/cbom/cbom/inventory.py:validate_document`. |
| TechBOM | `services/cbom/cbom/technology_bom.py:materialize_technology_bom` | One inventory → four layers (sbom/cbom/hbom/vendor) + deps, `fingerprint`/`snapshot_id`. |
| HBOM | `services/cbom/cbom/hbom.py:generate_hbom` | Unified `hardware_assets` → `Cryptoscan-HBOM` with `content_hash`, `hsm_fleet`/`tpm_fleet`, empty-deps declaration. |
| VBOM | `services/vendor_intel/vendor_intel/vbom.py:VbomGenerator` | Vendor → inventory entries → `zelinx-vbom` + CycloneDX (`vbom:*:…`). |
| NBOM | `services/cbom/cbom/nbom.py:build_nbom` | Endpoints/tunnels/devices → components + dependencies + `cascade` + `summarise` (unobserved excluded from verdicts). |
| Correlation | `services/correlation/` | Graph linking across the BOMs and the estate. |

## Entry points

The API is the product entry. Anything else is a client of it:

```bash
# queue a scan of a repository you own
POST /api/v1/scans/trigger   {"repo_url": "https://github.com/your-org/your-repo", "branch": "main"}

# read the projections and exports
GET  /api/v1/cbom            GET /api/v1/technology-bom
GET  /api/v1/assets          GET /api/v1/scans
```

Outputs are written to the configured snapshot/output directory; see
`docs/admin-guide/system-configuration.md`.

## Data boundary

- Scans read the target tree only. The scanner never receives the database, the
  policy engine's view of the target, or any pre-computed answer.
- BOM builders read stored findings and the estate's own records. A component is
  attributed no stronger provenance than the observation behind it.
- Network verdicts exclude `observed: false` (absence ≠ pass).

## Output honesty

- `cbom`/`techbom` components carry `source_basis: SCANNER_OBSERVED` when from a
  real `scan_file` result, otherwise `DECLARED`/`IMPORTED` with low confidence.
- `sbom`/`hbom`/`vbom`/`nbom` carry `vendor_declared`, `observed: false` where the
  estate marks a fact `UNKNOWN`.
- CycloneDX 1.6 CBOM, CycloneDX 1.5 SBOM, CycloneDX 1.5 HBOM and CycloneDX 1.6
  VBOM exports receive native schema checks. Native TechBOM/HBOM/VBOM/NBOM formats
  are separate outputs; the CycloneDX checks do not qualify those native formats.
