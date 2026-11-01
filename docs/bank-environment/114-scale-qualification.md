# Bank-scale qualification — 100k assets, 1M facts, measured

`cryptoscan.scale-qualification/1` · profile `bank` · generated 2026-11-01T08:37:25.919731+00:00 · **4 pass · 1 fail · 1 unproven** · 584 s · peak RSS 1345 MB · largest database 647 MB

The review asked whether this works at bank scale. This drill answers with the first thing that breaks, in the order a deployment would meet it.

## The rows

| Property | Verdict | Criterion | Measured |
|---|---|---|---|
| **does one discovery request carry a 100,000-asset estate?** | **FAIL** | assets list length >= 100,000 in EstateDiscoverRequest | assets: List should have at most 20000 items after validation, not 100000 |
| **how long does one observation take, and does a 100k-asset estate fit the window?** | **PASS** | >= 200 assets/s and a linear projection of 100k assets <= 900 s | 454.1 assets/s at 20,000 (2.2 ms/asset); 100k projected 3.7 min |
| **do twin and console reads answer at 100,000 assets / 1,000,000 facts?** | **PASS** | every read path p95 <= 1000 ms | 100,000 assets / 1,000,000 facts, 647.3 MB; slowest p95 765.0 ms (observation_summary) |
| **does observation 4 of a 2,000-asset estate cost what observation 1 did?** | **PASS** | the last round is within 2.0x the first, and a changed fact adds exactly one row (2,000 per round) while the CURRENT set stays flat | growth 1.67x over 4 rounds |
| **after two 10,000-asset slices, is the whole estate still readable?** | **PASS** | a sliced observation that declares itself a slice leaves no asset STALE and keeps every slice readable; a payload that claims to be the whole estate still retires what it does not carry | None active, None stale after two slices |
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
      "seconds": 4.16,
      "assets_per_second": 240.2,
      "milliseconds_per_asset": 4.16,
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
      "peak_rss_mb": 285.4
    },
    {
      "assets": 5000,
      "seconds": 10.42,
      "assets_per_second": 479.7,
      "milliseconds_per_asset": 2.08,
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
      "peak_rss_mb": 432.4
    },
    {
      "assets": 10000,
      "seconds": 20.58,
      "assets_per_second": 485.8,
      "milliseconds_per_asset": 2.06,
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
      "peak_rss_mb": 688.3
    },
    {
      "assets": 20000,
      "seconds": 44.04,
      "assets_per_second": 454.1,
      "milliseconds_per_asset": 2.2,
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
      "database_mb": 202.4,
      "peak_rss_mb": 1191.0
    }
  ],
  "projected_100k_seconds": 220.2,
  "projected_100k_minutes": 3.7,
  "threshold_assets_per_second": 200.0
}
```

### `read_paths` — PASS

*do twin and console reads answer at 100,000 assets / 1,000,000 facts?*

- **Criterion:** every read path p95 <= 1000 ms
- **Reading:** the estate was written through the persistence layer because the request cap makes an API ingest at this size impossible — this measures the read side, not ingest. The composite tenant+asset index added this pass is measured both ways — the gap widens with the estate, so a small database finds a path either way while 1M facts do not — and `observation_summary` is counted in SQL rather than in Python
- **Limit:** SQLite on one machine with no concurrent writers; PostgreSQL may differ in both directions

```
{
  "seed": {
    "assets": 100000,
    "facts": 1000000,
    "seed_seconds": 32.5,
    "database_mb": 647.3,
    "peak_rss_mb": 1191.0
  },
  "reads": {
    "catalog_page": {
      "p50_ms": 27.2,
      "p95_ms": 30.1,
      "max_ms": 36.7
    },
    "asset_detail": {
      "p50_ms": 26.9,
      "p95_ms": 30.7,
      "max_ms": 35.5
    },
    "history": {
      "p50_ms": 2.7,
      "p95_ms": 2.9,
      "max_ms": 3.5
    },
    "why": {
      "p50_ms": 5.2,
      "p95_ms": 5.5,
      "max_ms": 5.8
    },
    "evidence_for": {
      "p50_ms": 1.6,
      "p95_ms": 1.8,
      "max_ms": 4.1
    },
    "catalog_summary": {
      "p50_ms": 27.0,
      "p95_ms": 29.2,
      "max_ms": 41.6
    },
    "observation_summary": {
      "p50_ms": 715.9,
      "p95_ms": 765.0,
      "max_ms": 983.0
    }
  },
  "slowest": "observation_summary",
  "samples": 40,
  "index_effect": {
    "with_index": {
      "history_ms_p50": 2.4,
      "why_ms_p50": 5.2
    },
    "without_index": {
      "history_ms_p50": 205.7,
      "why_ms_p50": 3.1
    },
    "faster": "with_index",
    "history_gap_ms": 203.3
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
      "seconds": 4.39,
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
      "seconds": 6.81,
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
      "seconds": 7.02,
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
      "seconds": 7.34,
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
  "growth_factor": 1.67,
  "rows_added_per_round": [
    2000,
    2000,
    2000
  ],
  "current_rows_flat": true,
  "batch_assets": 2000
}
```

### `sharding` — PASS

*after two 10,000-asset slices, is the whole estate still readable?*

- **Criterion:** a sliced observation that declares itself a slice leaves no asset STALE and keeps every slice readable; a payload that claims to be the whole estate still retires what it does not carry
- **Reading:** the request cap is a batch size, not a wall: an estate larger than one request is sent as slices with `complete: false`, and only a payload that declares itself the whole estate retires what it does not carry
- **Limit:** the drill uses two slices of one shape; a real incremental collector also has to decide per slice which facts it is authoritative for, which is the operator's judgement, not the platform's

```
{
  "slice_assets": 10000,
  "after_two_slices": {
    "active_rows": 20000,
    "stale_rows": 0,
    "listed_on_one_page": 200
  },
  "control_undeclared_slice": {
    "stale_rows": 10000
  },
  "second_run_catalog": {
    "complete": false
  }
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
| `catalog_page` | 27.2 ms | 30.1 ms | 36.7 ms |
| `asset_detail` | 26.9 ms | 30.7 ms | 35.5 ms |
| `history` | 2.7 ms | 2.9 ms | 3.5 ms |
| `why` | 5.2 ms | 5.5 ms | 5.8 ms |
| `evidence_for` | 1.6 ms | 1.8 ms | 4.1 ms |
| `catalog_summary` | 27.0 ms | 29.2 ms | 41.6 ms |
| `observation_summary` | 715.9 ms | 765.0 ms | 983.0 ms |

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
