# Product 2 — CryptoScan (Scanner + Six BOMs)

CryptoScan is the existing product surface: language-aware crypto scanning plus six BOM projections and correlation. The lab exercises its real code paths — no forked detector.

## What it owns

| Surface | Module | Real entry |
|---------|--------|------------|
| Static scanner | `services/scanner/scanner/registry/language_scanners.py:scan_file` | Called inside the Landlock/seccomp child by `tools/banking_sandbox/scan_child.py`. Records `collector_source_sha256`, `guard.{oracle_read_denied,socket_creation_denied}`. |
| CBOM | `services/cbom/cbom/generator.py:CbomGenerator` + `services/cbom/cbom/component_registry.py:cbom_crypto_component` | `CbomGenerator.from_records(..., specVersion 1.5/1.6)` with `compositions: INCOMPLETE`, `evidence.occurrences`, confidence propagation. |
| SBOM | `services/cbom/cbom/technology_bom.py` SBOM layer + `services/devsecops/devsecops/sbom.py`, `services/container_scanner` | SBOM layer as `app_component` projection; CycloneDX/SPDX validation via `tools/banking_sandbox/documents.py` validators. |
| TechBOM | `services/cbom/cbom/technology_bom.py:materialize_technology_bom` | One inventory → four layers (sbom/cbom/hbom/vendor) + deps, `fingerprint`/`snapshot_id`. |
| HBOM | `services/cbom/cbom/hbom.py:generate_hbom` | Unified `hardware_assets` → `Cryptoscan-HBOM` with `content_hash`, `hsm_fleet`/`tpm_fleet`, empty-deps declaration. |
| VBOM | `services/vendor_intel/vendor_intel/vbom.py:VbomGenerator` | Vendor → inventory entries → `zelinx-vbom` + CycloneDX (`vbom:*:…`). |
| NBOM | `services/cbom/cbom/nbom.py:build_nbom` | Endpoints/tunnels/devices → components + dependencies + `cascade` + `summarise` (unobserved excluded from verdicts). |
| Correlation | `services/correlation/` | Graph linking (separate, not executed in offline static demo). |

## Entry in the lab

In production CryptoScan is served by `services/api`. In this lab the connector is the **hosted product entry** so the demo stays offline and boundary-enforced:

```bash
python -m products.connector.run --estate /tmp/estate --output /tmp/cryptoscan-out
# → scan/metrics.json + scan/findings.jsonl (real scanner)
# → boms/cbom.json, sbom.json, techbom.json, hbom.json, vbom.json, nbom.json
# → reports/validation.json (operator-side, not scanner-visible)
# → dashboard/index.html (product output)
```

## Data boundary

- During scan: allowed read set is exactly `scanner-inputs/` + `services/scanner` + `.venv` + `/usr` (Landlock). `control/ground_truth/ORACLE-SENTINEL.txt` read must fail.
- During BOM build: reads `CRYPTO_SCAN_OUTPUT/scan/*` (its own findings) plus `ESTATE/public/*` (public fixtures, provenance-tagged as `FIXTURE_DERIVED_NOT_LIVE_PROBED` where no scanner observed them). Never reads `control/`.
- During validation: separate operator step reads `control/ground_truth/*.jsonl` to compute precision/recall/coverage; results are written to `reports/` but never fed back to the scanner.

## Output honesty

- `cbom`/`techbom` components carry `source_basis: SCANNER_OBSERVED` when from `scan_file`, else `FIXTURE_DERIVED_NOT_LIVE_PROBED` with low confidence.
- `sbom`/`hbom`/`vbom`/`nbom` carry `lab:synthetic`, `vendor_declared`, `observed: false` where the estate marks `UNKNOWN`.
- Network verdicts exclude `observed: false` (absence ≠ pass). Load-balancer hop owner comes from controlled LB topology, not auto-detection — stated in the dashboard.
- Six BOM schema checks reuse the estate's `validators()` (CycloneDX + SPDX); results in `reports/validation.json`.
