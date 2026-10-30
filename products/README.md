# CryptoScan — the product

CryptoScan is one product: it discovers cryptography across your own estate — source code, hosts, containers, network endpoints, vendors — and projects what it finds into six BOMs with correlation, policy and remediation on top.

There is no bundled sample estate. The product reports what it can observe in *your* environment; when a surface has not been observed it says so rather than filling the gap with fixture data.

| Surface | Code | Entry point | Data boundary |
|---------|------|-------------|---------------|
| API + console | `services/api/`, `frontend/` | `uvicorn api.main:app` (see `RUN.md`) | Reads the estate database and the configured source roots only. |
| Static scanner | `services/scanner/` | Scan jobs queued through `POST /api/v1/scans` | Reads the target tree, inside a Landlock/seccomp child when the platform supports it. |
| Collectors | `services/network_scanner/`, `services/container_scanner/`, `services/devsecops/`, `services/hybrid_collector/` | Collector endpoints and the estate loop | Reads only what the operator points it at: targets, registries, hosts, vendors. |
| Six BOMs | `services/cbom/`, `services/vendor_intel/`, `services/correlation/` | `/api/v1/bom/*`, `/api/v1/cbom/*`, export endpoints | Built from stored findings and observations, never from a fixture. |

## Data flow

```
operator points CryptoScan at a real target (repo, host, registry, endpoint, vendor)
        ↓
collector / scanner observes it, and records what it could NOT observe
        ↓
findings + evidence rows land in the estate database (one row per observation)
        ↓
six BOM projections (SBOM, CBOM, TechBOM, HBOM, VBOM, NBOM) + correlation graph
        ↓
policy evaluation, gate decision, migration plan, exports
```

## Honesty invariants

- `UNKNOWN ≠ SAFE` — a missing or unobserved fact stays unknown, and the collector says which it is.
- `INSTALLED ≠ USED`, `SUPPORTED ≠ NEGOTIATED`, `CONFIGURED ≠ EXECUTED`, `SBOM ≠ PROOF`.
- No component is attributed a provenance stronger than the observation behind it.
- An empty result is reported as an empty result plus the reason, never as a pass.

## Getting started

```bash
# 1. Configure the instance (fail-closed in production)
cp .env.production.example .env

# 2. Start the API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# 3. Create your own estate: applications, assets, certificates, vendors
curl -X POST http://localhost:8000/api/v1/network \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"cidr": "10.20.0.0/24", "label": "corp-dc"}'

# 4. Scan a repository you own
curl -X POST http://localhost:8000/api/v1/scans/trigger \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/your-org/your-repo", "branch": "main"}'
```

Real context comes from your imports and collectors — see `docs/admin-guide/system-configuration.md`.

See `products/cryptoscan/README.md` for the surface-to-module map.
