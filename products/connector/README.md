# Connector — Local, Audited Bridge Between the Two Products

The connector is the **only place where the two products meet** and it does so through an audited, least-privilege pipeline. No shared DB, no shared credential, no truth leak to the scanner.

## What it runs

```
ESTATE (Product 1) ──public/source + public/load_balancers──► [scan_child under Landlock/seccomp]
                                                                guard proof: oracle_read_denied, socket_creation_denied
                                                                collector_source_sha256 recorded
                                                                → CRYPTOSCAN/scan/findings.jsonl + metrics.json (Product 2)

ESTATE/public/{banks,systems,applications,certificates,hsm,vendors,network,load_balancers}
 + CRYPTOSCAN/scan/* ──► Real generators (CbomGenerator, materialize_technology_bom,
                           generate_hbom, VbomGenerator, build_nbom)
                         provenance: SCANNER_OBSERVED vs FIXTURE_DERIVED_NOT_LIVE_PROBED
                         → CRYPTOSCAN/boms/{cbom,sbom,techbom,hbom,vbom,nbom}.json (+ .cyclonedx, .xml)

ESTATE/control/ground_truth ──► Validator only (operator) → reports/validation.json
                                precision/recall on static families; UNKNOWN stays UNKNOWN
                                → dashboard/index.html renders all three panes
```

## Why a connector module and not a monolith

- Each product keeps its code, data, and release boundary. The sandbox can evolve fixtures without editing CryptoScan; CryptoScan can evolve detection without editing the lab.
- The lab's `scanner-inputs` staging and seccomp guard stay in `tools/banking_sandbox/harness.py` — the connector calls it, not reimplements it.
- Six BOM generation reuses the **real** product generators. The connector only translates public rows to their expected input shapes — it never invents crypto properties.

## Commands

```bash
# Full connected run (scan + 6 BOMs + validation + dashboard)
.venv/bin/python -m products.connector.run --estate /tmp/lab-estate-10 --output /tmp/cryptoscan-output-10

# Or via sandbox CLI (same implementation)
.venv/bin/python -m tools.banking_sandbox.cli connect --estate /tmp/lab-estate-10 --output /tmp/cryptoscan-output-10

# Preview the product output
.venv/bin/python -m products.connector.serve --output /tmp/cryptoscan-output-10 --port 8080
# Also: tools.banking_sandbox.docs/load-balancers.md for lb-scan/lb-live/lb-compare
```

## Outputs (in order)

1. `scan/static/metrics.json` — wall/cpu/rss, files, failure_rate, boundary_receipt, scope
2. `scan/lb-config/metrics.json` — same for load-balancer configs (5 filenames only)
3. `boms/{cbom,sbom,techbom,hbom,vbom,nbom}.json` — each with `source_provenance` header, schema-checked
4. `boms/hbom.json` + `boms/hbom.cyclonedx.json`, `boms/vbom.cyclonedx.json`, `boms/cbom.xml`
5. `reports/validation.json` — precision/recall/FN, per-language, key_size/attribution UNKNOWN with reason, LB hop correlation accuracy
6. `dashboard/index.html` — Product 1 pane, Product 2 pane, Validation pane, honest limitations
7. `manifest.json` — sha256 of every output file, source estate LAB.json hash, connector version
8. `logs/connector.log` — replayable steps

## Safeguards

- Fresh-output guard: `--output` must not exist.
- One staged run per estate: `scanner-inputs` is created then removed between static and lb runs; a concurrent second connector is rejected.
- Private data: never copies `control/` into the scan output; dashboard never serves it.
- Provenance: every BOM component states whether it was observed or derived; derived network/hardware items are `VENDOR_DECLARED`/`CONFIGURED`, not `OBSERVED`.
