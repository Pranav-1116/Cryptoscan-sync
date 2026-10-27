# Cross-BOM cascade — "what breaks if X changes?"

> **Detailed bank interpretation and current limits:** read
> [dependency discovery](../bank-environment/12-dependency-discovery-and-evidence.md),
> [traversal mechanics](../bank-environment/13-cascade-and-blast-radius.md),
> [worked bank examples](../bank-environment/14-bank-cascade-examples.md),
> [API runbook](../bank-environment/15-dependency-cascade-api-runbook.md) and
> [limitations/acceptance](../bank-environment/16-dependency-limitations-and-acceptance.md).
> Modeled exposure is not a confirmed outage. The standalone package SBOM is
> distinct from the registered-system graph. Device linkage is supported when
> explicitly declared; absent linkage must remain unknown. Graph-backend and
> twin-input differences require qualification rather than an assumption of
> universal parity.

One question, every layer. The unified cascade takes a single target — an
algorithm, a certificate, an endpoint, a system, a vendor, a hardware device
or a library — and fans the blast radius out across all BOM layers at once:

- **code** — evidence records, owning systems, files (CBOM layer)
- **network** — endpoints on the wire, TLS versions, cipher suites (NBOM layer)
- **system graph** — dependents and downstream via depth-bounded walks over
  registered `SystemDependency` edges (application/system context, not the
  standalone package SBOM graph)
- **process** — business processes supported by the affected systems
  (real `SystemBusinessProcess` links)
- **hardware** — device facts from the hardware fleet (HBOM layer)
- **vendor** — linked systems, criticality, and the vendor's discovered
  crypto inventory with PQC readiness per use case (`VendorCryptoInventory`)
- **library** — for library targets: the fingerprint catalog's view (ADR-007)
  of what the library implements, alongside what the estate has observed

A certificate target also uses real `CertificateUsage` rows to name the
systems that run the certificate — stronger than matching subjects on the
wire. Certificate, endpoint, library, algorithm and device cascades walk the
system graph from everything they touch: owning systems, asset-linked
systems, their dependents and (where relevant) downstream — a shared key on
an HSM names the systems that use it and everyone who calls them, provided
the crypto-to-hardware link is declared (`POST /graph/hardware-links`).

It uses the digital-twin snapshot adapter also used by twin scenarios. Separate
live reads can reflect different collection times; graph-view and unified-cascade
input paths are not universally identical. Hold snapshot/input scope constant
when comparing answers.

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
| `kind` | optional hint: `algorithm`, `certificate`, `endpoint`, `system`, `vendor`, `device`, `library`, `process` |
| `max_depth` | system-graph hops, 1..12 (default 6 — same bound as `/graph/blast-radius`) |

A **process target** ("what breaks if Card Payments stops?") cascades the
systems that support it, everyone who depends on them, their crypto,
endpoints and vendors — the business-impact view of the same graph.

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

Every answer carries `honest_unknowns`. Without a declared crypto-to-hardware
link, a device remains inventory-only and its consumers cannot be named. With
that link and asset/system associations, device cascades can propagate to known
consumers. Network evidence is only as fresh as the last authorized scan, code
evidence is capped, and system propagation only sees the relationships in its
supplied snapshot (normally registered edges, with a graph-snapshot fallback
when the registered list is empty). The unknowns array is not a guarantee that
every possible coverage gap is automatically diagnosed.

## History (audit trail)

Every run is persisted with its full result, who asked, and when:

- `GET /api/v1/technology-bom/cascade/runs` — newest first
- `GET /api/v1/technology-bom/cascade/runs/{run_id}` — one past answer,
  exactly as it was returned
- `GET /api/v1/technology-bom/cascade/runs/{run_id}/diff` — how the blast
  radius changed since the previous run of the same target (or pass
  `?against={run_id}` for an explicit comparison): affected systems added
  and removed, process changes, verdict change. Answers the audit question
  "we migrated two services — did the RSA blast radius actually shrink?"

`impact.migration_waves` groups the affected systems by the migration wave
the roadmap would fix them in — what breaks, and when the plan repairs it.

The diff covers every layer: affected systems, processes, network endpoints,
hardware devices, vendors and code-evidence counts.

### Point-in-time replay

`POST /technology-bom/cascade?version=N` replays the cascade over a captured
twin snapshot instead of the live estate (`POST /digital-twin/snapshot`
captures one; `GET /digital-twin/snapshots` lists them). Unchanged estates
hash to the same version — the same discipline as BOM snapshots.

Replay provenance is part of the audit trail, not just the live response:
the persisted run — and therefore `GET /cascade/runs` (each entry carries
`replayed_over.twin_snapshot_version`) and `GET /cascade/runs/{run_id}` —
records which twin snapshot the answer replayed. An auditor can tell a
"what breaks NOW" answer from a "what DID break at v5" answer without
guessing.

### Watches

`POST /technology-bom/cascade/watch` saves a target;
`POST /technology-bom/cascade/watches/run-due` re-runs every active watch,
diffs each against its own previous answer, and emits a
`cascade.blast_radius_changed` platform event when systems were added or
removed — the alert stream already carries it.

A watched target that has left the estate (system decommissioned,
certificate rotated away) is reported explicitly: the run-due entry carries
`target_missing: true` with a `NOT_FOUND` verdict, the disappearance is
persisted as its own run, and the collapse of the blast radius is diffed
like any other change (the removed systems are named once; a second run
reports the stable missing state without re-alerting). The watch stays
active until an operator retires it — disappearance is information, not a
reason to stop watching.

Runs are tenant-scoped like every other row: a tenant sees its own runs and
the un-attributed platform runs, never another tenant's.

### Read-model honesty guarantees (2026-10)

The answers above are built to understate nothing the estate actually
declared:

- **Systems are always canonical IDs.** Every cascade kind reports system
  IDs (not names) in `layers.system.systems` and `impact.affected_systems`,
  so answers join back to the system registry. Vendor cascades used to
  report names — that path was fixed in October 2026.
- **Shared evidence keeps every owner.** An evidence record reachable
  through assets of two systems (a shared key file, a common library)
  contributes *both* systems to the blast radius. The evidence id itself
  still appears once — deduped — but no owning system is dropped.
- **BOM snapshots see edges, not just components.** A dependency edge
  registered (or removed) with zero component changes still produces a new
  Technology BOM version: the snapshot state carries the canonicalized
  `[source, target, type]` edge list and the fingerprint hashes it.
- **Diffs name changed fields.** `POST /technology-bom/snapshot` and
  `GET /technology-bom/compare` report per-layer `changed` entries — a
  component whose `bom-ref` survives but whose fields moved (an RSA key
  grown from 2048 to 4096 bits, a version bump) appears with the exact
  field-level from/to values, plus a `dependencies` section with
  added/removed edges.

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
- `GET /api/v1/cbom/scan/{scan_id}` carries the scanner's observed cascade
  (provider files, business systems, wave properties) — the same edges the
  export renders, marked `cryptoscan:dependencies=scan-cascade`.
- `POST /api/v1/graph/edges` registers the `SystemDependency` edges every
  walk above depends on; `GET /graph/blast-radius?asset_id=` starts the
  walk from a crypto asset instead of a system.
