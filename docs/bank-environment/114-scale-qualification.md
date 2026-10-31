# Bank-scale qualification — 100k assets, 1M facts, measured

`cryptoscan.scale-qualification/1` · profile `bank` · generated 2026-10-31T18:46:15.915594+00:00 · **2 pass · 3 fail · 1 unproven** · 380 s · peak RSS 1188 MB · largest database 646 MB

The review asked whether this works at bank scale. This drill answers with the first thing that breaks, in the order a deployment would meet it.

## The rows

| Property | Verdict | Criterion | Measured |
|---|---|---|---|
| **does one discovery request carry a 100,000-asset estate?** | **FAIL** | assets list length >= 100,000 in EstateDiscoverRequest | assets: List should have at most 20000 items after validation, not 100000 |
| **how long does one observation take, and does a 100k-asset estate fit the window?** | **PASS** | >= 200 assets/s and a linear projection of 100k assets <= 900 s | 470.9 assets/s at 20,000 (2.12 ms/asset); 100k projected 3.5 min |
| **do twin and console reads answer at 100,000 assets / 1,000,000 facts?** | **FAIL** | every read path p95 <= 1000 ms | 100,000 assets / 1,000,000 facts, 645.8 MB; slowest p95 1262.4 ms (observation_summary) |
| **does observation 4 of a 2,000-asset estate cost what observation 1 did?** | **PASS** | the last round is within 2.0x the first, and a changed fact adds exactly one row (2,000 per round) while the CURRENT set stays flat | growth 1.94x over 4 rounds |
| **after two 10,000-asset slices, is the whole estate still readable?** | **FAIL** | a sliced observation leaves no asset STALE — one estate, sent in chunks, must read as one estate | 10000 active, 10000 stale after two slices |
| **does the BOM project a 100,000-asset estate?** | **UNPROVEN** | project_all() over a graph built from a bank-scale observation | — |

## What each row measured

### `ingest_ceiling` — FAIL

*does one discovery request carry a 100,000-asset estate?*

- **Criterion:** assets list length >= 100,000 in EstateDiscoverRequest
- **Reading:** the request model caps `assets` at 20,000 and `evidence` at 100,000, so a bank-scale estate cannot be ingested in one observation; the route answers 422 before any collection runs
- **Limit:** the cap is a pydantic field constraint; a raised limit would not by itself make the rest of the path scale

```
{
  "requested_assets": 100000,
  "accepted": false,
  "validation_errors": [
    "assets: List should have at most 20000 items after validation, not 100000"
  ]
}
```

### `ingest_throughput` — PASS

*how long does one observation take, and does a 100k-asset estate fit the window?*

- **Criterion:** >= 200 assets/s and a linear projection of 100k assets <= 900 s
- **Reading:** the projection is linear from the largest measured point and ignores the run row, which stores the whole payload — it is an optimistic floor, not a forecast
- **Limit:** measured to 20k assets, the request cap; beyond it only the projection exists

```
{
  "points": [
    {
      "assets": 1000,
      "seconds": 4.0,
      "assets_per_second": 250.1,
      "milliseconds_per_asset": 4.0,
      "bom_components": {
        "SBOM": 0,
        "CBOM": 1000,
        "HBOM": 0,
        "NBOM": 0,
        "VBOM": 0,
        "TECHBOM": 1000
      },
      "current_facts": {
        "assets_with_facts": 1000,
        "current": 9000
      },
      "database_mb": 13.6,
      "peak_rss_mb": 284.5
    },
    {
      "assets": 5000,
      "seconds": 9.64,
      "assets_per_second": 518.6,
      "milliseconds_per_asset": 1.93,
      "bom_components": {
        "SBOM": 0,
        "CBOM": 5000,
        "HBOM": 0,
        "NBOM": 0,
        "VBOM": 0,
        "TECHBOM": 5000
      },
      "current_facts": {
        "assets_with_facts": 5000,
        "current": 45000
      },
      "database_mb": 53.1,
      "peak_rss_mb": 431.0
    },
    {
      "assets": 10000,
      "seconds": 20.0,
      "assets_per_second": 500.0,
      "milliseconds_per_asset": 2.0,
      "bom_components": {
        "SBOM": 0,
        "CBOM": 10000,
        "HBOM": 0,
        "NBOM": 0,
        "VBOM": 0,
        "TECHBOM": 10000
      },
      "current_facts": {
        "assets_with_facts": 10000,
        "current": 90000
      },
      "database_mb": 102.9,
      "peak_rss_mb": 686.2
    },
    {
      "assets": 20000,
      "seconds": 42.47,
      "assets_per_second": 470.9,
      "milliseconds_per_asset": 2.12,
      "bom_components": {
        "SBOM": 0,
        "CBOM": 20000,
        "HBOM": 0,
        "NBOM": 0,
        "VBOM": 0,
        "TECHBOM": 20000
      },
      "current_facts": {
        "assets_with_facts": 20000,
        "current": 180000
      },
      "database_mb": 202.5,
      "peak_rss_mb": 1188.5
    }
  ],
  "projected_100k_seconds": 212.3,
  "projected_100k_minutes": 3.5,
  "threshold_assets_per_second": 200.0
}
```

### `read_paths` — FAIL

*do twin and console reads answer at 100,000 assets / 1,000,000 facts?*

- **Criterion:** every read path p95 <= 1000 ms
- **Reading:** the estate was written through the persistence layer because the request cap makes an API ingest at this size impossible — this measures the read side, not ingest. The composite tenant+asset index added this pass is measured both ways — the gap widens with the estate, so a small database finds a path either way while 1M facts do not — and `observation_summary` is counted in SQL rather than in Python
- **Limit:** SQLite on one machine with no concurrent writers; PostgreSQL may differ in both directions

```
{
  "seed": {
    "assets": 100000,
    "facts": 1000000,
    "seed_seconds": 30.5,
    "database_mb": 645.8,
    "peak_rss_mb": 1188.5
  },
  "reads": {
    "catalog_page": {
      "p50_ms": 27.5,
      "p95_ms": 38.8,
      "max_ms": 41.6
    },
    "asset_detail": {
      "p50_ms": 26.2,
      "p95_ms": 33.7,
      "max_ms": 44.3
    },
    "history": {
      "p50_ms": 2.6,
      "p95_ms": 3.0,
      "max_ms": 4.5
    },
    "why": {
      "p50_ms": 5.0,
      "p95_ms": 5.6,
      "max_ms": 6.5
    },
    "evidence_for": {
      "p50_ms": 1.5,
      "p95_ms": 1.6,
      "max_ms": 3.1
    },
    "catalog_summary": {
      "p50_ms": 26.5,
      "p95_ms": 28.0,
      "max_ms": 39.4
    },
    "observation_summary": {
      "p50_ms": 1202.3,
      "p95_ms": 1262.4,
      "max_ms": 1319.8
    }
  },
  "slowest": "observation_summary",
  "samples": 40,
  "index_effect": {
    "with_index": {
      "history_ms_p50": 2.3,
      "why_ms_p50": 4.9
    },
    "without_index": {
      "history_ms_p50": 181.9,
      "why_ms_p50": 178.8
    },
    "faster": "with_index",
    "history_gap_ms": 179.6
  }
}
```

### `continuous_ingest` — PASS

*does observation 4 of a 2,000-asset estate cost what observation 1 did?*

- **Criterion:** the last round is within 2.0x the first, and a changed fact adds exactly one row (2,000 per round) while the CURRENT set stays flat
- **Reading:** each round writes a full run row and a full catalogue pass; the growth factor is the cost of history, and a factor well above 1 means the 15-minute schedule cannot hold as the estate ages
- **Limit:** no concurrent collectors; one tenant; SQLite

```
{
  "rounds": [
    {
      "round": 0,
      "assets": 2000,
      "seconds": 3.35,
      "current_facts": {
        "assets_with_facts": 2000,
        "current": 18000
      },
      "observation_rows": 18000,
      "current_rows": 18000,
      "change_verdict": "BASELINE",
      "changes": {}
    },
    {
      "round": 1,
      "assets": 2000,
      "seconds": 6.13,
      "current_facts": {
        "assets_with_facts": 2000,
        "current": 18000
      },
      "observation_rows": 20000,
      "current_rows": 18000,
      "change_verdict": "NO_CHANGE",
      "changes": {
        "ASSET_CHANGED": 50
      }
    },
    {
      "round": 2,
      "assets": 2000,
      "seconds": 6.36,
      "current_facts": {
        "assets_with_facts": 2000,
        "current": 18000
      },
      "observation_rows": 22000,
      "current_rows": 18000,
      "change_verdict": "NO_CHANGE",
      "changes": {
        "ASSET_CHANGED": 50
      }
    },
    {
      "round": 3,
      "assets": 2000,
      "seconds": 6.49,
      "current_facts": {
        "assets_with_facts": 2000,
        "current": 18000
      },
      "observation_rows": 24000,
      "current_rows": 18000,
      "change_verdict": "NO_CHANGE",
      "changes": {
        "ASSET_CHANGED": 50
      }
    }
  ],
  "growth_factor": 1.94,
  "rows_added_per_round": [
    2000,
    2000,
    2000
  ],
  "current_rows_flat": true,
  "batch_assets": 2000
}
```

### `sharding` — FAIL

*after two 10,000-asset slices, is the whole estate still readable?*

- **Criterion:** a sliced observation leaves no asset STALE — one estate, sent in chunks, must read as one estate
- **Reading:** the second slice's graph does not contain the first slice, so the catalogue retires it: the 20k request cap cannot be worked around by sending the estate in pieces without losing whichever piece came first
- **Limit:** the drill uses two slices; N slices would stale N-1 of them

```
{
  "slice_assets": 10000,
  "active_rows": 10000,
  "stale_rows": 10000,
  "listed_on_one_page": 200,
  "second_run_catalog": {}
}
```

### `bom_projection_at_scale` — UNPROVEN

*does the BOM project a 100,000-asset estate?*

- **Criterion:** project_all() over a graph built from a bank-scale observation
- **Reading:** the ingest ceiling is below bank scale, so no graph of that size can be built through the API; the projection is measured only at the ladder's largest point
- **Limit:** closing this needs either a raised request cap or a streaming ingest

```
{
  "assets": 100000
}
```

## Defects this drill exposes

Measured while running the drill. They are reported, not fixed here, and they are not the reason any row passes or fails.

| Defect | Where | Detail |
|---|---|---|
| `change-verdict-contradicts-its-own-claims` | `continuous_ingest` | 3 round(s) report verdict NO_CHANGE with {'ASSET_CHANGED': 50} named changes and the headline 'the two observations are identical': the verdict comes from the BOM and coverage comparison while the claims come from the twin's asset comparison, so a metadata-only movement is listed and denied in the same response |

## Read paths at bank scale

| Read | p50 | p95 | max |
|---|---|---|---|
| `catalog_page` | 27.5 ms | 38.8 ms | 41.6 ms |
| `asset_detail` | 26.2 ms | 33.7 ms | 44.3 ms |
| `history` | 2.6 ms | 3.0 ms | 4.5 ms |
| `why` | 5.0 ms | 5.6 ms | 6.5 ms |
| `evidence_for` | 1.5 ms | 1.6 ms | 3.1 ms |
| `catalog_summary` | 26.5 ms | 28.0 ms | 39.4 ms |
| `observation_summary` | 1202.3 ms | 1262.4 ms | 1319.8 ms |

## Thresholds

Chosen for this drill so a bank's 15-minute observation window is plausible. They are not vendor benchmarks, and a PASS is not a capacity guarantee.

| Threshold | Value |
|---|---|
| `ingest_assets_per_request` | 100000 |
| `ingest_seconds_for_100k` | 900.0 |
| `assets_per_second` | 200.0 |
| `read_p95_ms` | 1000.0 |
| `continuous_growth_factor` | 2.0 |
| `sharded_estate_stale_assets` | 0 |

## What this does not prove

- Every measurement is SQLite on one machine: no PostgreSQL, no concurrent writers, no network storage. The schema's indexes are exercised; the database engine's behaviour at scale is not.
- No concurrent ingest: the drill measures one observation at a time, so lock contention and pool exhaustion are unmeasured here (blocker #3 owns those).
- The synthetic estate is regular — every asset has the same shape and fact set. A real bank has long tails (one asset with 40k relationships), which this drill does not model.
- The thresholds are this drill's, chosen so a 15-minute observation window is plausible. They are not vendor benchmarks, and a PASS is not a capacity guarantee.

**The verdict this drill supports:** the estate path does not reach bank scale through its own API. One request carries at most 20,000 assets, sending the estate in slices retires the slices that came before, and the read side is only measurable at 100k/1M because the rows were written around the API. That is a structural finding, not a tuning one.
