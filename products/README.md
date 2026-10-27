# Two Products, One Local Connection

This repository contains **two separately runnable products** that exchange only staged public fixtures.

| Product | Code | Owns | Entry point | Data boundary |
|---------|------|------|-------------|---------------|
| **Product 1 — Banking Sandbox** | `tools/banking_sandbox/` | Deterministic synthetic estate generator, `LAB.json`, `manifest.json`, `public/*`, private `control/*` | `generate_sandbox.py`, `tools.banking_sandbox.cli validate/serve/scan/lb-scan/lb-live/drift/failures` | Estate directory passed as `--root`. Writes only there. Never reads `products/cryptoscan/output` or `products/connector/output`. |
| **Product 2 — CryptoScan** | `services/cbom/`, `services/scanner/`, `services/vendor_intel/`, `services/correlation/`, … | Real scanners (`scanner.registry.language_scanners.scan_file`), six BOM materializers (SBOM, CBOM, TechBOM, HBOM, VBOM, NBOM), correlation and policy engines | `services/*` APIs + `tools.banking_sandbox.connector` as hosted product entry for lab demos | Scan/BOM output directory passed as `--output`. Reads only staged `scanner-inputs` during scan. |
| **Connector** | `products/connector/` + `tools/banking_sandbox/connector/` | Hosts the isolated scan, translates public fixtures to BOM assembler inputs, writes honest validation | `python -m products.connector.run --estate <ESTATE> --output <CRYPTOSCAN_OUTPUT>` or `python -m tools.banking_sandbox.cli connect --estate <ESTATE> --output <OUTPUT>` | Reads only `public/*` after scan; reads `control/ground_truth` only for the separate operator-side validation step. |

## Data flow

```
[Sandbox] generate → ESTATE/public/*  (public fixtures only)  ↘
                    ESTATE/control/ground_truth (never staged) → [Connector: validation only]
                                                        ↓
                         Connector stages ESTATE/public/source → scanner-inputs
                         runs scan_file under Landlock+seccomp (oracle denied, socket denied)
                         → CRYPTOSCAN_OUTPUT/scan/findings.jsonl + metrics.json
                                                        ↓
                         Connector builds 6 BOMs from scan outputs + public inventory
                         via real generators (no truth shortcut)
                         → CRYPTOSCAN_OUTPUT/boms/{cbom,sbom,techbom,hbom,vbom,nbom}.json
                                                        ↓
                         Connector validates (precision/recall + coverage) reading ground truth
                         outside the scanner → reports/validation.json
                                                        ↓
                         Connector renders dashboard → dashboard/index.html
```

## Honesty invariants

- `UNKNOWN ≠ SAFE` — missing/unobserved stays unknown.
- `INSTALLED ≠ USED`, `SUPPORTED ≠ NEGOTIATED`, `CONFIGURED ≠ EXECUTED`, `SBOM ≠ PROOF`.
- Scanner never sees `control/ground_truth` (Landlock-enforced, `ORACLE-SENTINEL.txt` proof).
- Validation is a separate operator step that reads truth; it does not feed the scanner.
- All BOM provenance states whether a component came from `SCANNER_OBSERVED`, `FIXTURE_DERIVED_NOT_LIVE_PROBED`, or `SYNTHETIC_LAB`. No invented SLA or production-capacity claim.

## Quick demo — 10 banks

```bash
# 1. Sandbox generates a lab (Product 1)
.venv/bin/python generate_sandbox.py --banks 10 --scale small --profile worst-case-bank \
  --output /tmp/lab-estate-10

# 2. CryptoScan consumes the lab via the connector (Product 2 through the connector)
.venv/bin/python -m products.connector.run --estate /tmp/lab-estate-10 \
  --output /tmp/cryptoscan-output-10

# 3. Serve the connected output (dashboard and evidence under one origin)
python -m tools.banking_sandbox.cli serve-output \
  --output /tmp/cryptoscan-output-10 --host 127.0.0.1 --port 8080
# → /dashboard/, /boms/, /scan/, /reports/validation.json
```

See `products/sandbox/README.md`, `products/cryptoscan/README.md`, `products/connector/README.md`.
