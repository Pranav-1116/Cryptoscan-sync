# 15 — Dependency and cascade API runbook for bank operators

[Guide index](README.md) · Previous: [Bank examples](14-bank-cascade-examples.md) ·
Next: [Limitations and acceptance](16-dependency-limitations-and-acceptance.md)

## 1. Preconditions and safe operation

Use the authenticated HTTPS ingress and restricted evidence directory described
in [05](05-practical-bank-walkthrough.md). Its `bank_api` helper passes the
approved Bearer token and optional authorized tenant context without putting
credentials in example URLs. Do not enable shell tracing around secrets.

The examples below operate on **real returned IDs from your installed estate**.
Do not run write operations against production without bank approval. A saved
dependency changes later analysis even though it does not change the target
application. Existing objects, correct environment and permission checks are
prerequisites; a successful schema check alone proves none of them.

Some graph write routes use the shared authenticated-user dependency rather than
a specialized approver dependency. Qualify effective role/tenant enforcement
with the deployed policy; do not assume a UI role guard is the complete control.
This guide does not change authorization behavior.

## 2. Inspect the current relationship baseline

| Method/path | Meaning and caution |
|---|---|
| `GET /api/v1/graph/edges` | Registered system edges; default 500, selectable limit up to 5,000 |
| `GET /api/v1/graph/edges/discovered` | Candidate proposals/unresolved names, not automatic approval |
| `GET /api/v1/graph/hardware-links` | Declared crypto-to-hardware links, bounded list |
| `GET /api/v1/graph/vendor-edges` | Declared sub-tier supplier relationships |
| `GET /api/v1/graph/stats` | Graph composition/hygiene context |
| `GET /api/v1/graph/drift` | Persisted graph versus relational-payload drift context |

```bash
bank_api GET '/api/v1/graph/edges?limit=5000' > registered-edges.json
bank_api GET /api/v1/graph/edges/discovered > candidate-edges.json
bank_api GET /api/v1/graph/hardware-links > hardware-links.json
bank_api GET /api/v1/graph/drift > graph-drift.json
```

The current edge-list function applies its limit before its optional system
filter. Filtering a bounded page is not proof of a complete system-neighborhood
list. Reconcile the accepted estate baseline independently for large estates.

## 3. Register a substantiated system dependency

Save this as `dependency-request.json`, replacing placeholders with actual
registered IDs. It means the consumer depends on the provider:

```json
{
  "parent_id": "<actual-consumer-system-id>",
  "child_id": "<actual-provider-system-id>",
  "relation": "CALLS",
  "source": "manual"
}
```

```bash
bank_api POST /api/v1/graph/edges \
  --data-binary @dependency-request.json > registered-dependency.json
```

`EdgeRequest` also accepts supported names and optional confidence. Prefer IDs
where names could collide across environments. The route checks object
resolution, rejects self-dependency, rejects an existing pair, records creator
and metadata, and emits a graph update after commit.

The pair uniqueness means multiple relationship meanings between the same two
systems are not independent parallel rows in this table. Plan how to represent
and review semantics rather than assuming an unrestricted multigraph.

For discovered candidates, review actual proposal IDs/evidence and save the
selected pairs in `adopt-request.json`:

```json
{
  "edges": [
    {
      "parent_id": "<actual-proposed-consumer-id>",
      "child_id": "<actual-proposed-provider-id>",
      "relation": "CALLS"
    }
  ]
}
```

```bash
bank_api POST /api/v1/graph/edges/adopt \
  --data-binary @adopt-request.json > adopted-edges.json
```

Inspect `adopted` and `skipped`; a 200 response does not mean every pair was
accepted. Adoption accepts pairs in its body; do not treat it as independently
re-verifying a scanner observation or enforcing an external approval workflow.

## 4. Declare which crypto asset a hardware device serves

Save `hardware-link-request.json` using an actual crypto asset ID and actual
persisted hardware asset ID:

```json
{
  "asset_id": "<actual-crypto-asset-id>",
  "hardware_asset_id": "<actual-hardware-asset-id>",
  "note": "Bank owner substantiated this device-to-asset relationship under the approved review."
}
```

```bash
bank_api POST /api/v1/graph/hardware-links \
  --data-binary @hardware-link-request.json > declared-hardware-link.json
```

The route checks both objects exist and rejects an existing link. This is an
operator declaration, not a live HSM-session trace or attestation. Separately
confirm the crypto asset's system links; a hardware link alone does not create
every missing asset-to-system relationship.

## 5. Ask the correct directional question

Set `SYSTEM_ID` and `TARGET_SYSTEM_ID` from actual registered records.

```bash
: "${SYSTEM_ID:?use the actual selected system ID}"
: "${TARGET_SYSTEM_ID:?use the actual destination system ID}"
bank_api GET "/api/v1/graph/blast-radius?system_id=$SYSTEM_ID&hops=6" > forward-context.json
bank_api GET "/api/v1/graph/dependents?system_id=$SYSTEM_ID&hops=6" > reverse-consumers.json
bank_api GET "/api/v1/graph/path?system_id=$SYSTEM_ID&target_id=$TARGET_SYSTEM_ID&direction=downstream" > dependency-path.json
```

- Forward blast-radius endpoint: supporting dependency context.
- Dependents endpoint: who relies on this system.
- Path endpoint: supported shortest-path explanation; `reachable=false` can be
  a normal result rather than proof the real bank has no relationship.

`hops` defaults to 5 on graph blast/dependents routes and allows 1..12. Unified
cascade defaults to 6. Hold the depth constant when comparing results.

The graph backend's relationship rules and seed/count envelope differ from
unified cascade. Read [13](13-cascade-and-blast-radius.md) before interpreting
count differences as an incident or a defect fix.

## 6. Run a cross-domain cascade

Save as `cascade-request.json`:

```json
{
  "target": "<actual-hardware-asset-id>",
  "kind": "device",
  "max_depth": 6
}
```

```bash
bank_api POST /api/v1/technology-bom/cascade \
  --data-binary @cascade-request.json > cascade-response.json
CASCADE_RUN_ID=$(python3 -c 'import json; print(json.load(open("cascade-response.json"))["run_id"])')
bank_api GET "/api/v1/technology-bom/cascade/runs/$CASCADE_RUN_ID" > stored-cascade-run.json
```

Review matched target, inventory-only status, seed systems, both depth maps,
aggregate counts, process coverage and `honest_unknowns`. Do not use `AFFECTED`
as an outage assertion or `NOT_FOUND` as a safety result.

The engine supports other kinds including `algorithm`, `library`, `certificate`,
`endpoint`, `system`, `vendor` and `process`. Substitute a real appropriate target
and inspect what was matched. [Step 7](23-exact-target-identities-and-ambiguity.md)
adds `target_resolution` and `analysis_performed`. Use exact fingerprints, versioned
PURLs and vendor IDs. `allow_name_search=true` permits non-executing broad candidate
discovery; submit a chosen canonical identity separately. An unresolved answer
has not analyzed impact—do not treat its compatibility zeroes as no exposure.

## 7. Capture a twin and replay it

Step 4 evaluates captured-version replay at its capture clock by default. An
explicit aware `as_of` body field requests another clock, records that choice
and never rewrites the saved answer. See [lifecycle/replay contract](20-relationship-lifecycle-and-reconciliation.md).

| Method/path | Meaning |
|---|---|
| `POST /api/v1/digital-twin/snapshot` | Capture the supported twin state; unchanged content can reuse a version |
| `POST /api/v1/technology-bom/cascade?version=...` | Run against an actual captured twin version, not the current live adapter |
| `GET /api/v1/technology-bom/cascade/runs` | Retrieve bounded run history |
| `GET /api/v1/technology-bom/cascade/runs/{run_id}` | Retrieve the stored answer |
| `GET /api/v1/technology-bom/cascade/runs/{run_id}/diff` | Compare stored answers; optional explicit `against` run |

```bash
bank_api POST /api/v1/digital-twin/snapshot > twin-snapshot-response.json
: "${TWIN_VERSION:?set from the actual captured twin snapshot version}"
bank_api POST "/api/v1/technology-bom/cascade?version=$TWIN_VERSION" \
  --data-binary @cascade-request.json > replayed-cascade.json
: "${BASELINE_CASCADE_RUN_ID:?use the actual comparable baseline run ID}"
bank_api GET "/api/v1/technology-bom/cascade/runs/$CASCADE_RUN_ID/diff?against=$BASELINE_CASCADE_RUN_ID" \
  > cascade-diff.json
```

Twin snapshot version, TechBOM version, graph snapshot version, source scan ID,
SBOM artifact ID and cascade run ID are different identities. Capture their
relationships in the bank evidence manifest; never substitute one for another.

A live adapter gathers multiple collections; it is not proof of an atomic
whole-bank observation instant. A stored snapshot captures that modeled state,
not an independent timestamped measurement of every bank component.

A reduced count can result from remediation, but also stale/deleted edges,
missing evidence, changed depth, changed identity or a different backend/input
scope. Explain the delta before claiming risk reduction.

## 8. Watches need an executor and fresh inputs

| Method/path | Meaning |
|---|---|
| `POST /api/v1/technology-bom/cascade/watch` | Save a supported target/depth watch |
| `GET /api/v1/technology-bom/cascade/watches` | List stored watches |
| `POST /api/v1/technology-bom/cascade/watches/run-due` | Rerun active watches and report supported result changes |

Saving a watch alone does not provision a reliable scheduler or refresh source,
network, vendor or hardware evidence. Approve the executor, schedule, failure
handling and alert delivery separately. An emitted event is not proof of
successful downstream incident-system ingestion.

## 9. Audit handoff checklist

Retain approved scope, exact input identities, source/deployment evidence,
relationship provenance, old/new stored run IDs, selected twin versions, depth,
backend, capture times, omissions, verification context and owner decisions.

Maintain separate sections for modeled exposure and independently confirmed
operational outcomes. Apply bank access, retention, encryption and transfer
controls; no signing secrets, tokens or arbitrary raw source belong in an
unrestricted report.
