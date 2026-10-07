# Cross-BOM cascade — "what breaks if X changes?"

One question, every layer. The unified cascade takes a single target — an
algorithm, a certificate, an endpoint, a system, a vendor, a hardware device
or a library — and fans the blast radius out across all BOM layers at once:

- **code** — evidence records, owning systems, files (CBOM layer)
- **network** — endpoints on the wire, TLS versions, cipher suites (NBOM layer)
- **system graph** — dependents and downstream via depth-bounded walks over
  registered `SystemDependency` edges (SBOM layer)
- **hardware** — device facts from the hardware fleet (HBOM layer)
- **vendor** — linked systems and vendor criticality (VBOM layer)

It runs over the same digital-twin snapshot the twin scenarios use, so the
cascade and the twin can never disagree about what the estate looks like.

## Run a cascade

```bash
curl -X POST /api/v1/technology-bom/cascade \
  -H 'Content-Type: application/json' \
  -d '{"target": "RSA-2048"}'
```

Optional fields:

| Field | Meaning |
|---|---|
| `target` | required — what might change |
| `kind` | optional hint: `algorithm`, `certificate`, `endpoint`, `system`, `vendor`, `device`, `library` |
| `max_depth` | system-graph hops, 1..12 (default 6 — same bound as `/graph/blast-radius`) |

Targets are auto-detected most-specific-first: a SHA-256 fingerprint is
matched as a certificate, `host:port` as an endpoint, an exact system name as
a system — a certificate subject is only used as a last resort so
`CN=payment-api` does not shadow the system named `payment-api`.

## The answer

```json
{
  "schema": "cryptoscan.unified-cascade/1",
  "verdict": "AFFECTED",
  "target": {"input": "payment-api", "kind": "system", "matched": {"...": "..."}},
  "layers": {
    "code": {"evidence_ids": ["..."], "systems": ["sys-pay"], "algorithms": ["RSA-2048"]},
    "network": {"endpoints": ["api.bank:443"]},
    "system": {"dependents_by_depth": {"1": ["sys-web"]},
               "downstream_by_depth": {"1": ["sys-db"]}},
    "hardware": {"devices": [], "inventory_only": true},
    "vendor": {"vendors": ["Thales"], "criticality": "HIGH"}
  },
  "impact": {"affected_systems": ["sys-pay", "sys-web", "sys-db"],
             "affected_system_count": 3, "max_propagation_depth": 1},
  "honest_unknowns": ["..."],
  "run_id": "..."
}
```

Verdicts:

- `AFFECTED` — at least one layer names something concrete.
- `NOT_FOUND` — the target matches nothing in the twin.
- `INSUFFICIENT_DATA` — the target exists but nothing concrete is reachable.

Every answer carries `honest_unknowns` — what the engine cannot know and
will not guess: crypto↔HSM linkage is not modelled (the hardware layer is
inventory, not a blast radius), network evidence is only as fresh as the last
authorized scan, code evidence is capped on very large estates, and system
propagation walks registered edges only.

## History (audit trail)

Every run is persisted with its full result, who asked, and when:

- `GET /api/v1/technology-bom/cascade/runs` — newest first
- `GET /api/v1/technology-bom/cascade/runs/{run_id}` — one past answer,
  exactly as it was returned

Runs are tenant-scoped like every other row: a tenant sees its own runs and
the un-attributed platform runs, never another tenant's.

## Related surfaces

- `GET /api/v1/scans/{scan_id}/cascade` — observed call-graph cascade from
  source scanning (multi-language, providers and migration waves)
- `POST /api/v1/cbom/nbom/cascade` — NBOM backwards walk over protocol
  dependencies
- `GET /api/v1/graph/blast-radius` — graph-engine blast radius (Cypher
  `CALLS*1..12` when Neo4j is live)
- System CBOMs (`GET /api/v1/cbom/system/{system_id}`) now carry real
  `dependencies[]`: the system depends on its crypto assets
  (`SystemAsset`) and its registered inter-system edges
  (`SystemDependency`), in both directions, marked
  `cryptoscan:dependencies=estate-linkage` in metadata.
