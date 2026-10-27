# Product 1 — Banking Sandbox (Lab)

Additive synthetic estate laboratory. Generates only `public/*` that a scanner is allowed to see and keeps `control/*` (ground truth, expected results) private.

## What it owns

- `tools/banking_sandbox/generator.py` — deterministic, bounded generation (1–2000 banks, seed/epoch reproducible)
- `tools/banking_sandbox/catalog.py` — 20 archetypes, profiles, 35 estate cases + 15 modes, LB 15 roles/35 cases
- `tools/banking_sandbox/pki.py`, `documents.py`, `sources.py`, `scenarios.py`, `load_balancers/`
- Estate layout: `LAB.json`, `manifest.json`, `public/`, `control/`, `generation-metrics.json`

## Entry points (Product 1 CLI)

```bash
.venv/bin/python generate_sandbox.py --banks 10 --scale small --output /tmp/estate
.venv/bin/python -m tools.banking_sandbox.cli validate --root /tmp/estate --full-schemas
.venv/bin/python -m tools.banking_sandbox.cli serve --root /tmp/estate --host 0.0.0.0 --port 8080
.venv/bin/python -m tools.banking_sandbox.cli drift --root /tmp/estate --output /tmp/estate-drift
.venv/bin/python -m tools.banking_sandbox.cli failures --output /tmp/fail-report
# Low-level scans (used by the connector, not operators directly):
.venv/bin/python -m tools.banking_sandbox.cli scan --root /tmp/estate --output /tmp/scan-out
.venv/bin/python -m tools.banking_sandbox.cli lb-scan --root /tmp/estate --output /tmp/lb-out
.venv/bin/python -m tools.banking_sandbox.cli lb-live --output /tmp/live.json
```

## Data boundary

- Reads: generation options, seed, bundled schemas/assets only.
- Writes: exactly one estate directory (fails if exists or escapes). Never writes to `products/cryptoscan` or `products/connector` outputs.
- Serves: `public/` only (read-only `PublicOnly` handler, no directory listing). Never serves `control/` or scanner outputs.

## Distinction

Declared `SUPPORTED` suites, vendor assertions, SBOM component lists, and simulated TLS versions are **fixtures** (`lab:synthetic=true`, `evidence_type: VENDOR_DECLARED | CONFIGURED`). Only `lb-live` negotiates real TLS — inside a `user+net+mount` namespace with a private tmpfs and Landlock oracle denial — and even then hop attribution is supplied by controlled topology, not auto-detected.
