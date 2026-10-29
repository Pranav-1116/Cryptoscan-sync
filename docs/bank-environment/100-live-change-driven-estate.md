# 100 — Live, Change-Driven Estate Intelligence

Status: **architecture + first live slice built** on `arena/bb4b80dd-cryproscan`.
Companions: [`93-estate-evidence-graph-and-six-bom-projections.md`](93-estate-evidence-graph-and-six-bom-projections.md),
[`94-digital-twin.md`](94-digital-twin.md), [`97-operator-cli.md`](97-operator-cli.md),
[`98-cli-architecture.md`](98-cli-architecture.md).

> **The direction, in one sentence.** CryptoScan observes the authorised bank estate
> continuously, establishes an evidence-backed baseline once, stores only the changes,
> keeps a live Digital Twin current, projects the six BOMs from that live state on demand,
> and correlates cryptographic, runtime, network and configuration changes into attack
> patterns — without ever declaring a compromise it cannot evidence.

## 0. Status register (what exists, what does not)

| Piece | State | Where |
| --- | --- | --- |
| Live observation intake with change-only storage | **built** | `POST /api/v1/ingestion/observations` (`services/api/api/routers/ingestion.py`) |
| State-hash comparison (agent hash vs platform hash) | **built** | `shared_models/live_estate.py` `compare_state`, `state_hash_report` |
| Connection state `LIVE / STALE / NEVER_CONNECTED` | **built** | `GET /api/v1/ingestion/live/status`, `live_estate.connection_state` |
| Stored-observations listing | **built** | `GET /api/v1/ingestion/observations` |
| BOM download from the current twin | **built** | `GET /api/v1/estate/evidence/boms/{kind}/export?fmt=cyclonedx\|json`, `GET …/boms/export` |
| CycloneDX 1.6 renderer with limits in the document | **built** | `shared_models/bom_export.py` |
| BOM-impact narrowing per change | **built** | `live_estate.bom_impact` |
| Attack-pattern correlation, evidence levels 0–4 | **built** | `shared_models/attack_patterns.py`, `GET /api/v1/estate/evidence/threat/patterns` |
| CLI `live status\|observations\|patterns`, `observe push`, `bom --download` | **built** | `services/api/api/cli_remote.py` |
| Change feed, evidence store, catalogue, twin, drift | **built earlier** | `GET /estate/evidence/changes`, `…/evidence/records`, `…/catalog`, `…/twin`, `…/drift` |
| Continuous agent that *runs the collectors* on a cadence | **not built** | collectors are importable modules/surfaces; no supervised agent process |
| Server-side scheduling of observation pushes | **partly built** | `POST /estate/evidence/schedules` stores a cadence; no worker executes it in this build |
| mTLS machine identity for the agent | **not built** | observations are signed (Ed25519) and the verdict is recorded; transport identity is deployment work |
| Runtime/network/static correlation across collectors in one pattern | **partly built** | patterns correlate change *kinds* and subjects; per-collector corroboration is not modelled |
| Live UI screen for connection, changes and patterns | **not built** | API + CLI exist; the console reads the change feed but has no `/live` surface |
| Air-gapped evidence bundle transfer (`cryptoscan.bundle/1`) | **withdrawn** | removed from the product by decision on 2026-10-29; git history keeps the earlier module |

An air-gapped *bundle* path was designed and partly built, and then withdrawn: the product
direction is a live connection, and a second transfer format that nothing else uses would be
maintained code that lies about being supported. What replaced it is the observation
envelope below, which is the same evidence one poll at a time.

## 1. The model

```text
                         BANK ENVIRONMENT
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
   Linux/Windows            Network/K8s            Cloud/DB/HSM
   collectors               collectors             collectors
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                        normalise + state hash
                                │
                    ┌───────────┴───────────┐
              hash == stored           hash changed
                    │                       │
                 DROP                 evidence event (signed)
                                            │
                                            ▼
                                POST /ingestion/observations
                                            │
                                ┌───────────┴───────────┐
                                │  NO_CHANGE → heartbeat │   (one pruned row, no estate copy)
                                │  CHANGED   → twin write│
                                └───────────┬───────────┘
                                            ▼
                              evidence store · catalogue · change feed
                                            │
                                            ▼
                                   DIGITAL TWIN (live)
                                            │
             ┌──────────────────────────────┼──────────────────────────────┐
             ▼                              ▼                              ▼
      six BOM projections            drift / impact               attack patterns
             │                              │                              │
    download on demand                asset history                 evidence levels 0–4
```

Two rules make the whole thing work:

1. **the twin is the only state.** A BOM never exists as stored truth. "Download the current
   CBOM" projects the twin; it does not scan and does not read a cached file;
2. **a poll that saw nothing costs nothing.** No run, no evidence, no BOM revision — one
   pruned heartbeat row per tenant records that the agent reported.

## 2. The observation envelope (built)

`POST /api/v1/ingestion/observations`

```json
{
  "estate": "payments",
  "scope": "production",
  "inventory_id": "INV-1",
  "observed_at": "2026-10-29T17:00:00Z",
  "assets": [{"ref": "host-01", "type": "HOST", "name": "host-01"}],
  "evidence": [{"source": "linux-static", "evidence_type": "STATIC_OBSERVED",
                "target": "host-01", "layer": "PLATFORM", "facts": {"hostname": "host-01"}}],
  "relationships": [],
  "collectors": [{"plane": "Linux hosts", "state": "COMPLETE", "expected": 2, "collected": 2}],
  "coverage": [{"plane": "Linux hosts", "expected": 2, "collected": 2}],
  "state_hash": "<the agent's own hash of its normalised state>",
  "signature": {"schema": "cryptoscan.signature/1", "alg": "Ed25519", "...": "..."}
}
```

* **`state_hash` is compared, never trusted.** The platform computes its own hash from the
  same normalised state (the graph fingerprint) and returns both plus `agrees`. Two
  different normalisers is a bug worth surfacing, not a silent drift.
* **`signature` is optional and its verdict is always reported** —
  `VALID`/`SIGNED_UNVERIFIED`/`UNSIGNED`/`KEY_MISMATCH`/`SIGNATURE_MALFORMED`/`INVALID`. A
  signature checked against no trusted key is never `VALID`. A deployment can require
  signatures with `CRYPTOSCAN_REQUIRE_SIGNED_OBSERVATIONS=1`, in which case only `VALID` is
  stored (401 otherwise).
* **coverage rides along.** A plane that reports less than before becomes
  `COVERAGE_DEGRADED` in the change feed — "found nothing" is never allowed to look like
  "nothing exists".

Responses: `201` with `state: FIRST_BASELINE|CHANGED` for a stored write; `200` with
`state: NO_CHANGE`, `stored: false` and the heartbeat for a dropped poll.

## 3. Downloading a BOM (built)

```
GET /api/v1/estate/evidence/boms/CBOM/export?fmt=cyclonedx   → CycloneDX 1.6, attachment
GET /api/v1/estate/evidence/boms/TECHBOM/export?fmt=json     → the native projection
GET /api/v1/estate/evidence/boms/export                      → all six, one projection id
CLI: cryptoscan bom CBOM --download cbom.cdx.json
```

* the document carries `cryptoscan:projection_id`, `cryptoscan:boundary`,
  `cryptoscan:unknowns` and `cryptoscan:not_authoritative` as CycloneDX properties, so its
  limits travel with it;
* the serial number is a UUIDv5 over (projection id, kind): re-downloading the same
  projection produces the same document;
* before any observation the route is `404 no_estate_discovery` — never an empty file that
  reads as "the bank has no crypto".

## 4. Attack patterns (built)

`GET /api/v1/estate/evidence/threat/patterns?window_seconds=3600` correlates the stored
change feed. Levels are **correlation levels, not probabilities**:

| Level | Name | Assigned by |
| --- | --- | --- |
| 0 | `NORMAL_CHANGE` | a change with no corroborating signal |
| 1 | `UNEXPECTED_CHANGE` | coverage loss, a single weakened artefact, new code alone |
| 2 | `SUSPICIOUS_ACTIVITY` | related changes in one window (blind spot, regression, trust-path mutation, burst, new crypto surface) |
| 3 | `SECURITY_INCIDENT` | **never assigned by this engine** — a responder's decision |
| 4 | `CORRELATED_PATTERN` | two independent level-2 patterns in the same window |

Patterns built: `COLLECTION_BLIND_SPOT` (a change inside a window where a plane stopped
reporting is `attributable: false`), `COLLECTION_LOSS`, `CRYPTOGRAPHIC_REGRESSION`,
`EVIDENCE_WEAKENED`, `TRUST_PATH_MUTATION`, `NEW_CRYPTO_SURFACE`, `NEW_CODE_PRESENT`,
`RAPID_CHANGE_BURST`, `CORRELATED_ACTIVITY`.

Every pattern carries `why`, `next_action`, the signals (event, kind, subject, evidence ids)
and a `not_proven` list that starts with "a pattern is not proof of compromise".

## 5. CLI (built)

```
cryptoscan observe push --file observation.json [--sign-key collector.key] [--dry-run]
cryptoscan live status
cryptoscan live observations [--limit 20]
cryptoscan live patterns [--window 3600]
cryptoscan bom CBOM --download current-cbom.cdx.json [--format cyclonedx|json]
```

* every command prints `source: <METHOD> <path> (HTTP n)`;
* `observe push --dry-run` prints "nothing was collected and nothing was written" and issues
  no request;
* a failed download leaves no file behind and exits non-zero.

## 6. Operational facts this build states rather than hides

* **a quiet estate and a stopped agent look identical** — which is why `live status` reports
  the age of the last observation against the expected interval, and `STALE` is a state in
  its own right;
* **the platform cannot see a change no collector reads** — every pattern says so;
* **coverage is per observation**, so a reduced coverage block degrades coverage even if the
  rest of the payload is unchanged;
* **no BOM is authoritative**; the twin is, and the twin holds evidence, not files;
* **levels 3 and 4 are not confidence** — 4 means "several patterns, same window".

## 7. Not built (and not pretended)

* a supervised agent process that runs collectors on a cadence and pushes observations
  itself (the endpoint, the CLI push, and the schedules table exist; the worker does not);
* mTLS machine identity between agent and API;
* per-collector corroboration inside a pattern (the data to do it — collector per evidence
  record — exists in the evidence store; the correlation rule does not use it yet);
* a console surface for connection state, live changes and patterns;
* retention/compaction policy for the change feed;
* horizontal scale-out of projection rendering.
