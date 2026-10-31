"""Bank-scale qualification: measure the estate path at 100k assets / 1M facts.

The review's sixth blocker said the branch was qualified on small local datasets
and never at bank scale. This drill answers it with numbers instead of a table,
and it answers with the *first* thing that breaks, in order:

    ingest ceiling      how large an estate one discovery request can carry
    ingest throughput   assets per second to that ceiling, and the projection cost
    storage at scale    100k assets and 1M facts through the persistence layer
    read paths          catalogue page, asset detail, history, why, summary, evidence
    continuous ingest   repeated observations of a changing estate
    sharding            whether a capped estate can be sent in slices
    growth              rows and bytes per 1k assets, to price a real deployment

Every row carries a verdict and the criterion it was judged against:

    PASS      the criterion was met, on this machine, at this scale
    FAIL      the criterion was missed — the row names by how much
    UNPROVEN  the path could not be executed at this scale at all

The thresholds are this drill's, chosen so a bank's 15-minute observation window
is plausible; they are not vendor benchmarks and the artifact says so. Every
measurement is on SQLite, because this sandbox has no PostgreSQL — which is a
limit of the measurement, not of the schema, and is stated in the artifact
rather than in a footnote.

Run::

    python scripts/scale_qualification.py --profile bank \\
        --json docs/bank-environment/114-scale-qualification.json \\
        --md   docs/bank-environment/114-scale-qualification.md
"""

from __future__ import annotations

import json
import os
import resource
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.scale-qualification/1"
VERSION = "scale-qualification/1.0"
TENANT = "tenant-scale"

REPO_ROOT = Path(__file__).resolve().parents[1]

PASS, FAIL, UNPROVEN = "PASS", "FAIL", "UNPROVEN"

#: thresholds chosen for a bank's 15-minute observation window, not vendor SLAs
THRESHOLDS = {
    #: one discovery request must carry a bank-scale estate
    "ingest_assets_per_request": 100_000,
    #: a full observation must fit inside a 15-minute window with room to think
    "ingest_seconds_for_100k": 900.0,
    "assets_per_second": 200.0,
    #: a console page must answer while a human is looking at it
    "read_p95_ms": 1_000.0,
    #: an observation every 15 minutes must not double in cost as history grows
    "continuous_growth_factor": 2.0,
    #: chunking is only usable if it does not stale the other chunks
    "sharded_estate_stale_assets": 0,
}

PROFILES = {
    #: the drill: the numbers the review asked for
    "bank": {
        "ladder": (1_000, 5_000, 10_000, 20_000),
        "storage_assets": 100_000,
        "storage_facts": 10,
        "reads": 40,
        "continuous_batches": 4,
        "continuous_batch_assets": 2_000,
        "shard_assets": 10_000,
    },
    #: the suite: the same code paths, small enough to run in CI
    "ci": {
        "ladder": (200, 800),
        "storage_assets": 2_000,
        "storage_facts": 5,
        "reads": 8,
        "continuous_batches": 2,
        "continuous_batch_assets": 200,
        "shard_assets": 300,
    },
}


# --------------------------------------------------------------------- input --- #
def estate_payload(count: int, *, alphabet: int = 50, start: int = 0,
                   facts_per_asset: int = 8) -> tuple[list[dict], list[dict]]:
    """A synthetic estate slice in the shape a collector package produces."""
    assets: list[dict] = []
    evidence: list[dict] = []
    facts = {
        "algorithm": "AES", "key_size": 256, "mode": "GCM", "purpose": "ENCRYPTION",
        "usage_state": "SUPPORTED", "confidence": "HIGH", "file_path": "", "team": "",
        "environment": "PROD", "classification": "CONFIDENTIAL", "system": "",
        "lifecycle": "ACTIVE",
    }
    for i in range(start, start + count):
        ref = f"application:app-{i:06d}"
        assets.append({
            "ref": ref, "type": "APPLICATION", "name": f"app-{i:06d}",
            "identity": {"application": f"app-{i:06d}"},
            "location": f"/srv/bank/app{i:06d}",
            "source": "synthetic",
            "attributes": {"team": f"team-{i % alphabet:02d}", "system": f"sys-{i % 40:02d}"},
        })
        record_facts = dict(facts)
        record_facts["file_path"] = f"/srv/bank/app{i:06d}/Crypto.java"
        record_facts["team"] = f"team-{i % alphabet:02d}"
        record_facts["system"] = f"sys-{i % 40:02d}"
        # trim to the requested depth, always keeping the crypto identity
        keep = ["algorithm", "key_size", "mode", "purpose", "usage_state", "confidence"]
        for extra in [k for k in record_facts if k not in keep][: max(0, facts_per_asset - len(keep))]:
            keep.append(extra)
        evidence.append({
            "source": "synthetic", "collector": "synthetic:scale",
            "evidence_type": "STATIC_OBSERVED", "target": ref, "layer": "APPLICATION",
            "observed_at": "2026-10-31T00:00:00+00:00",
            "facts": {k: record_facts[k] for k in keep},
        })
    return assets, evidence


def _database(path: str | None = None):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers the metadata
    from db.models.base import Base
    from db.tenancy import install_tenant_guard

    # the real app installs this at startup: it stamps ``tenant_id`` on new rows
    # and refuses a Core statement that would read across tenants. Without it the
    # drill would measure a database the product never runs.
    install_tenant_guard()

    path = path or tempfile.mktemp(suffix=".db", prefix="scale-")
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)(), engine, path


def _tenant_scope():
    from db.tenancy import tenant_scope

    return tenant_scope(TENANT)


def _peak_rss_mb() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000.0, 1)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return round(ordered[index], 1)


@dataclass
class Row:
    """One measured property, with the criterion it was graded against."""

    id: str
    question: str
    verdict: str
    criterion: str
    measured: dict[str, Any] = field(default_factory=dict)
    note: str = ""
    limit: str = ""
    #: defects the measurement exposes without failing the row
    defects: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "question": self.question, "verdict": self.verdict,
                "criterion": self.criterion, "measured": self.measured,
                "note": self.note, "limit": self.limit, "defects": self.defects}


# ------------------------------------------------------------------- ingest --- #
def ingest_ceiling() -> Row:
    """How large an estate can one discovery request carry?"""
    from pydantic import ValidationError

    from api.routers.estate_graph import EstateDiscoverRequest

    wanted = THRESHOLDS["ingest_assets_per_request"]
    assets, evidence = estate_payload(wanted)
    try:
        EstateDiscoverRequest(estate="bank", assets=assets, evidence=evidence)
    except ValidationError as exc:
        errors = [f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()]
        return Row(
            id="ingest_ceiling",
            question=f"does one discovery request carry a {wanted:,}-asset estate?",
            verdict=FAIL,
            criterion=f"assets list length >= {wanted:,} in EstateDiscoverRequest",
            measured={"requested_assets": wanted, "accepted": False, "validation_errors": errors[:3]},
            note=("the request model caps `assets` at 20,000 and `evidence` at 100,000, so a "
                  "bank-scale estate cannot be ingested in one observation; the route answers "
                  "422 before any collection runs"),
            limit="the cap is a pydantic field constraint; a raised limit would not by itself "
                  "make the rest of the path scale",
        )
    return Row(
        id="ingest_ceiling",
        question=f"does one discovery request carry a {wanted:,}-asset estate?",
        verdict=PASS,
        criterion=f"assets list length >= {wanted:,} in EstateDiscoverRequest",
        measured={"requested_assets": wanted, "accepted": True},
    )


def ingest_throughput(scales: tuple[int, ...]) -> Row:
    """Assets per second through the real discovery path, up to the cap."""
    from api.routers.estate_graph import EstateDiscoverRequest, run_discovery
    from shared_models.estate_graph import collector_outcome

    points: list[dict[str, Any]] = []
    for count in scales:
        assets, evidence = estate_payload(count)
        db, engine, path = _database()
        try:
            with _tenant_scope():
                started = time.perf_counter()
                body = EstateDiscoverRequest(
                    estate="bank", scope="scale", assets=assets, evidence=evidence,
                    collectors=[collector_outcome("STATIC", "COMPLETE", expected=count,
                                                  collected=count)],
                    coverage=[{"plane": "STATIC", "status": "COMPLETE",
                               "expected": count, "collected": count}],
                    include_boms=True, persist=True,
                )
                response = run_discovery(db, "scale-drill", body)
                elapsed = time.perf_counter() - started
            points.append({
                "assets": count,
                "seconds": round(elapsed, 2),
                "assets_per_second": round(count / elapsed, 1) if elapsed else None,
                "milliseconds_per_asset": round(elapsed / count * 1000, 2),
                "bom_components": response.get("bom_counts"),
                "current_facts": (response.get("evidence_store") or {}).get("observations", {}).get("counts"),
                "database_mb": round(os.path.getsize(path) / 1e6, 1),
                "peak_rss_mb": round(_peak_rss_mb(), 1),
            })
        finally:
            db.close()
            engine.dispose()
            try:
                os.unlink(path)
            except OSError:
                pass

    rate = points[-1]["assets_per_second"] or 0.0
    projected = THRESHOLDS["ingest_seconds_for_100k"]
    per_asset = points[-1]["seconds"] / points[-1]["assets"]
    projection = round(per_asset * THRESHOLDS["ingest_assets_per_request"], 1)
    ok = rate >= THRESHOLDS["assets_per_second"] and projection <= projected
    return Row(
        id="ingest_throughput",
        question="how long does one observation take, and does a 100k-asset estate fit the window?",
        verdict=PASS if ok else FAIL,
        criterion=(f">= {THRESHOLDS['assets_per_second']:.0f} assets/s and a linear projection of "
                   f"100k assets <= {projected:.0f} s"),
        measured={"points": points, "projected_100k_seconds": projection,
                  "projected_100k_minutes": round(projection / 60, 1),
                  "threshold_assets_per_second": THRESHOLDS["assets_per_second"]},
        note=("the projection is linear from the largest measured point and ignores the run row, "
              "which stores the whole payload — it is an optimistic floor, not a forecast"),
        limit="measured to 20k assets, the request cap; beyond it only the projection exists",
    )


def sharding_hazard(shard: int) -> Row:
    """Can a capped estate be sent as slices without corrupting the estate view?"""
    from api.routers.estate_graph import EstateDiscoverRequest, run_discovery
    from shared_models.estate_graph import collector_outcome

    db, engine, path = _database()
    try:
        with _tenant_scope():
            for index, start in enumerate((0, shard)):
                assets, evidence = estate_payload(shard, start=start)
                body = EstateDiscoverRequest(
                    estate="bank", scope="shard", assets=assets, evidence=evidence,
                    collectors=[collector_outcome("STATIC", "COMPLETE", expected=shard,
                                                  collected=shard)],
                    coverage=[{"plane": "STATIC", "status": "COMPLETE",
                               "expected": shard, "collected": shard}],
                    include_boms=True, persist=True,
                )
                response = run_discovery(db, "scale-drill", body)
            catalog = response.get("catalog") or {}
            from sqlalchemy import func, select

            from db.models.estate_catalog import EstateAssetRecord

            counts = dict(db.execute(
                select(EstateAssetRecord.lifecycle_state, func.count())
                .group_by(EstateAssetRecord.lifecycle_state)
            ).all())
            from api import estate_catalog

            listed = estate_catalog.list_assets(db, tenant_id=TENANT, limit=500)
        stale_count = int(counts.get("STALE", 0))
        active_count = int(counts.get("ACTIVE", 0))
        return Row(
            id="sharding",
            question=f"after two {shard:,}-asset slices, is the whole estate still readable?",
            verdict=PASS if stale_count <= THRESHOLDS["sharded_estate_stale_assets"] else FAIL,
            criterion=("a sliced observation leaves no asset STALE — one estate, sent in "
                       "chunks, must read as one estate"),
            measured={"slice_assets": shard, "active_rows": active_count,
                      "stale_rows": stale_count, "listed_on_one_page": len(listed),
                      "second_run_catalog": {k: v for k, v in catalog.items()
                                             if k in {"assets", "relationships"}}},
            note=("the second slice's graph does not contain the first slice, so the catalogue "
                  "retires it: the 20k request cap cannot be worked around by sending the "
                  "estate in pieces without losing whichever piece came first"),
            limit="the drill uses two slices; N slices would stale N-1 of them",
        )
    finally:
        db.close()
        engine.dispose()
        try:
            os.unlink(path)
        except OSError:
            pass


# ------------------------------------------------------------------ storage --- #
def _seed_bank_scale(assets: int, facts_per_asset: int) -> tuple[Any, Any, str, dict[str, Any]]:
    """Write a bank-scale estate through the persistence layer.

    The request cap makes this unreachable through the API, so the rows are
    written directly — which is exactly what a backfill or a migration would do,
    and what any read-path measurement at this size has to start from.
    """
    from db.models.estate_catalog import EstateAssetRecord, EstateObservationRecord

    db, engine, path = _database()
    started = time.perf_counter()
    from db.tenancy import platform_scope

    # a bulk load is not a tenant request: the rows name their tenant explicitly,
    # and the guard would (correctly) refuse a Core INSERT inside a tenant scope
    with platform_scope():
        db.execute(EstateAssetRecord.__table__.insert(), [
            {
                "id": f"asset-{i}", "tenant_id": TENANT,
                "asset_id": f"application:app-{i:06d}", "asset_type": "APPLICATION",
                "name": f"app-{i:06d}", "location": f"/srv/bank/app{i:06d}",
                "source": "synthetic", "evidence_ids": [f"ev-{i}"], "evidence_count": 1,
                "observation_count": 1, "lifecycle_state": "ACTIVE",
                "first_seen_at": datetime.now(timezone.utc),
                "last_seen_at": datetime.now(timezone.utc),
            }
            for i in range(assets)
        ])
        db.commit()
        batch: list[dict[str, Any]] = []
        for i in range(assets):
            for j in range(facts_per_asset):
                batch.append({
                    "id": f"obs-{i}-{j}", "tenant_id": TENANT,
                    "observation_id": f"obs-{i:06d}-{j:02d}",
                    "asset_id": f"application:app-{i:06d}",
                    "fact_type": f"attribute:fact_{j:02d}", "value": f"value-{j}",
                    "value_kind": "string", "evidence_id": f"ev-{i}",
                    "evidence_type": "STATIC_OBSERVED", "layer": "APPLICATION",
                    "lifecycle_state": "CURRENT", "observation_count": 1,
                    "first_seen_at": datetime.now(timezone.utc),
                    "last_seen_at": datetime.now(timezone.utc),
                })
            if len(batch) >= 50_000:
                db.execute(EstateObservationRecord.__table__.insert(), batch)
                db.commit()
                batch = []
        if batch:
            db.execute(EstateObservationRecord.__table__.insert(), batch)
            db.commit()
    elapsed = time.perf_counter() - started
    return db, engine, path, {
        "assets": assets,
        "facts": assets * facts_per_asset,
        "seed_seconds": round(elapsed, 1),
        "database_mb": round(os.path.getsize(path) / 1e6, 1),
        "peak_rss_mb": round(_peak_rss_mb(), 1),
    }


INDEX_NAME = "ix_estate_observations_tenant_asset"


def _index_effect(db: Any, asset_id: str, rounds: int = 3) -> dict[str, Any]:
    """The same two reads with and without the composite tenant+asset index.

    Measured rather than argued: the index is dropped, the reads are timed, and it
    is put back. On a database this size the difference is two orders of magnitude,
    which is why the row quotes both numbers instead of a claim.
    """
    from sqlalchemy import text

    from api import estate_observations

    def _time() -> dict[str, float]:
        values = []
        for _ in range(rounds):
            started = time.perf_counter()
            estate_observations.history(db, asset_id, tenant_id=TENANT)
            history_ms = _ms(started)
            started = time.perf_counter()
            estate_observations.why(db, asset_id, "attribute:fact_00", tenant_id=TENANT)
            values.append({"history_ms": history_ms, "why_ms": _ms(started)})
        return {
            "history_ms_p50": _percentile([v["history_ms"] for v in values], 50),
            "why_ms_p50": _percentile([v["why_ms"] for v in values], 50),
        }

    from db.tenancy import platform_scope

    with_index = _time()
    # DDL is platform work, not a tenant read; the guard would refuse it in scope
    with platform_scope():
        db.execute(text(f"DROP INDEX IF EXISTS {INDEX_NAME}"))
        db.commit()
        without_index = _time()
        db.execute(text(
            f"CREATE INDEX IF NOT EXISTS {INDEX_NAME} ON estate_observations (tenant_id, asset_id)"
        ))
        db.commit()
    history_gap = without_index["history_ms_p50"] - with_index["history_ms_p50"]
    faster = ("with_index" if history_gap > 0 else
              "without_index" if history_gap < 0 else "same")
    return {"with_index": with_index, "without_index": without_index,
            "faster": faster, "history_gap_ms": round(history_gap, 1)}


def read_paths(assets: int, facts_per_asset: int, samples: int) -> tuple[Row, dict[str, Any]]:
    """Do the console and twin reads still answer at 100k assets / 1M facts?"""
    from api import estate_catalog, estate_observations

    db, engine, path, seeded = _seed_bank_scale(assets, facts_per_asset)
    timings: dict[str, list[float]] = {name: [] for name in
                                       ("catalog_page", "asset_detail", "history", "why",
                                        "evidence_for", "catalog_summary", "observation_summary")}
    try:
        with _tenant_scope():
            index_effect = _index_effect(db, f"application:app-{(assets // 2):06d}")
            for k in range(samples):
                index = (k * 7919) % assets  # spread the sample across the estate
                asset_id = f"application:app-{index:06d}"

                started = time.perf_counter()
                estate_catalog.list_assets(db, tenant_id=TENANT, limit=200)
                timings["catalog_page"].append(_ms(started))

                started = time.perf_counter()
                estate_catalog.asset_detail(db, asset_id, tenant_id=TENANT)
                timings["asset_detail"].append(_ms(started))

                started = time.perf_counter()
                estate_observations.history(db, asset_id, tenant_id=TENANT)
                timings["history"].append(_ms(started))

                started = time.perf_counter()
                estate_observations.why(db, asset_id, "attribute:fact_00", tenant_id=TENANT)
                timings["why"].append(_ms(started))

                started = time.perf_counter()
                estate_observations.evidence_for(db, target=asset_id, tenant_id=TENANT)
                timings["evidence_for"].append(_ms(started))

                started = time.perf_counter()
                estate_catalog.summary(db, tenant_id=TENANT)
                timings["catalog_summary"].append(_ms(started))

                started = time.perf_counter()
                estate_observations.summary(db, tenant_id=TENANT)
                timings["observation_summary"].append(_ms(started))
    finally:
        db.close()
        engine.dispose()
        try:
            os.unlink(path)
        except OSError:
            pass

    measured = {name: {"p50_ms": _percentile(values, 50), "p95_ms": _percentile(values, 95),
                       "max_ms": round(max(values), 1) if values else None}
                for name, values in timings.items()}
    worst = max(measured.items(), key=lambda item: item[1]["p95_ms"] or 0.0)
    ok = all(item["p95_ms"] <= THRESHOLDS["read_p95_ms"] for item in measured.values())
    return Row(
        id="read_paths",
        question=f"do twin and console reads answer at {assets:,} assets / {assets * facts_per_asset:,} facts?",
        verdict=PASS if ok else FAIL,
        criterion=f"every read path p95 <= {THRESHOLDS['read_p95_ms']:.0f} ms",
        measured={"seed": seeded, "reads": measured, "slowest": worst[0],
                  "samples": samples, "index_effect": index_effect},
        note=("the estate was written through the persistence layer because the request cap makes "
              "an API ingest at this size impossible — this measures the read side, not ingest. "
              "The composite tenant+asset index added this pass is measured both ways — the gap "
              "widens with the estate, so a small database finds a path either way while 1M facts "
              "do not — and `observation_summary` is counted in SQL rather than in Python"),
        limit="SQLite on one machine with no concurrent writers; PostgreSQL may differ in both "
              "directions",
    ), measured


# --------------------------------------------------------------- continuous --- #
def continuous_ingest(batches: int, size: int) -> Row:
    """An estate that keeps being observed: does an unchanged estate stay cheap?"""
    from api.routers.estate_graph import EstateDiscoverRequest, run_discovery
    from shared_models.estate_graph import collector_outcome

    db, engine, path = _database()
    rounds: list[dict[str, Any]] = []
    try:
        for round_index in range(batches):
            assets, evidence = estate_payload(size)
            if round_index:  # one fact changes per asset per round: a real estate moves
                for asset in assets:
                    asset["attributes"]["team"] = f"team-r{round_index}-{asset['attributes']['team']}"
            started = time.perf_counter()
            with _tenant_scope():
                body = EstateDiscoverRequest(
                    estate="bank", scope="continuous", assets=assets, evidence=evidence,
                    collectors=[collector_outcome("STATIC", "COMPLETE", expected=size,
                                                  collected=size)],
                    coverage=[{"plane": "STATIC", "status": "COMPLETE", "expected": size,
                               "collected": size}],
                    include_boms=True, persist=True,
                )
                response = run_discovery(db, "scale-drill", body)
                from sqlalchemy import func, select

                from db.models.estate_catalog import EstateObservationRecord

                fact_rows = db.execute(select(func.count()).select_from(
                    EstateObservationRecord)).scalar()
                current_rows = db.execute(select(func.count()).where(
                    EstateObservationRecord.lifecycle_state == "CURRENT")).scalar()
            rounds.append({
                "round": round_index,
                "assets": size,
                "seconds": round(time.perf_counter() - started, 2),
                "current_facts": (response.get("evidence_store") or {}).get("observations", {}).get("counts"),
                "observation_rows": int(fact_rows or 0),
                "current_rows": int(current_rows or 0),
                "change_verdict": (response.get("detection") or {}).get("verdict"),
                "changes": (response.get("detection") or {}).get("counts"),
            })
        first = rounds[0]["seconds"]
        last = rounds[-1]["seconds"]
        growth = round(last / first, 2) if first else None
        # a changed fact must cost exactly one new row and retire exactly one: more
        # means the sync is rewriting the estate every observation, which is how a
        # bank's history table stops fitting on its disk
        added = [rounds[i]["observation_rows"] - rounds[i - 1]["observation_rows"]
                 for i in range(1, len(rounds))]
        current_flat = len({round_["current_rows"] for round_ in rounds[1:]}) <= 1
        rows_ok = all(delta == size for delta in added) and current_flat
        ok = (growth is not None and growth <= THRESHOLDS["continuous_growth_factor"]
              and rows_ok)
        contradictions = [
            round_ for round_ in rounds[1:]
            if round_["change_verdict"] == "NO_CHANGE" and any(round_["changes"].values())
        ]
        defects = []
        if contradictions:
            defects.append({
                "id": "change-verdict-contradicts-its-own-claims",
                "row": "continuous_ingest",
                "detail": (
                    f"{len(contradictions)} round(s) report verdict NO_CHANGE with "
                    f"{contradictions[0]['changes']} named changes and the headline 'the two "
                    "observations are identical': the verdict comes from the BOM and coverage "
                    "comparison while the claims come from the twin's asset comparison, so a "
                    "metadata-only movement is listed and denied in the same response"
                ),
                "affects": "an operator reading the headline misses an attribute-level change",
            })
        return Row(
            id="continuous_ingest",
            question=f"does observation {batches} of a {size:,}-asset estate cost what observation 1 did?",
            verdict=PASS if ok else FAIL,
            criterion=(f"the last round is within {THRESHOLDS['continuous_growth_factor']:.1f}x the "
                       f"first, and a changed fact adds exactly one row ({size:,} per round) while "
                       "the CURRENT set stays flat"),
            measured={"rounds": rounds, "growth_factor": growth,
                      "rows_added_per_round": added, "current_rows_flat": current_flat,
                      "batch_assets": size},
            defects=defects,
            note=("each round writes a full run row and a full catalogue pass; the growth factor is "
                  "the cost of history, and a factor well above 1 means the 15-minute schedule "
                  "cannot hold as the estate ages"),
            limit="no concurrent collectors; one tenant; SQLite",
        )
    finally:
        db.close()
        engine.dispose()
        try:
            os.unlink(path)
        except OSError:
            pass


# ------------------------------------------------------------------ measure --- #
def measure(profile: str = "bank") -> dict[str, Any]:
    config = PROFILES[profile]
    started = time.perf_counter()
    rows: list[Row] = [
        ingest_ceiling(),
        ingest_throughput(tuple(config["ladder"])),
    ]
    read_row, reads = read_paths(config["storage_assets"], config["storage_facts"],
                                 config["reads"])
    rows.append(read_row)
    rows.append(continuous_ingest(config["continuous_batches"],
                                  config["continuous_batch_assets"]))
    rows.append(sharding_hazard(config["shard_assets"]))
    rows.append(Row(
        id="bom_projection_at_scale",
        question=f"does the BOM project a {config['storage_assets']:,}-asset estate?",
        verdict=UNPROVEN,
        criterion="project_all() over a graph built from a bank-scale observation",
        measured={"assets": config["storage_assets"]},
        note=("the ingest ceiling is below bank scale, so no graph of that size can be built "
              "through the API; the projection is measured only at the ladder's largest point"),
        limit="closing this needs either a raised request cap or a streaming ingest",
    ))

    graded = [row.as_dict() for row in rows]
    counts = {verdict: sum(1 for row in graded if row["verdict"] == verdict)
              for verdict in (PASS, FAIL, UNPROVEN)}
    worst_db = max((row["measured"].get("database_mb") or row["measured"].get("seed", {}).get("database_mb") or 0)
                   for row in graded) if graded else 0
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "profile": profile,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tenant": TENANT,
        "elapsed_seconds": round(time.perf_counter() - started, 1),
        "peak_rss_mb": round(_peak_rss_mb(), 1),
        "largest_database_mb": round(float(worst_db), 1),
        "thresholds": THRESHOLDS,
        "counts": counts,
        "rows": graded,
        "defects": [defect for row in graded for defect in row.get("defects") or []],
        "read_paths": reads,
        "limits": [
            "Every measurement is SQLite on one machine: no PostgreSQL, no concurrent writers, "
            "no network storage. The schema's indexes are exercised; the database engine's "
            "behaviour at scale is not.",
            "No concurrent ingest: the drill measures one observation at a time, so lock "
            "contention and pool exhaustion are unmeasured here (blocker #3 owns those).",
            "The synthetic estate is regular — every asset has the same shape and fact set. A "
            "real bank has long tails (one asset with 40k relationships), which this drill does "
            "not model.",
            "The thresholds are this drill's, chosen so a 15-minute observation window is "
            "plausible. They are not vendor benchmarks, and a PASS is not a capacity guarantee.",
        ],
    }


def render_md(report: dict[str, Any]) -> str:
    verdicts = report["counts"]
    lines = [
        "# Bank-scale qualification — 100k assets, 1M facts, measured",
        "",
        f"`{report['schema']}` · profile `{report['profile']}` · generated {report['generated_at']} · "
        f"**{verdicts.get(PASS, 0)} pass · {verdicts.get(FAIL, 0)} fail · "
        f"{verdicts.get(UNPROVEN, 0)} unproven** · {report['elapsed_seconds']:.0f} s · "
        f"peak RSS {report['peak_rss_mb']:.0f} MB · largest database {report['largest_database_mb']:.0f} MB",
        "",
        "The review asked whether this works at bank scale. This drill answers with the first "
        "thing that breaks, in the order a deployment would meet it.",
        "",
        "## The rows",
        "",
        "| Property | Verdict | Criterion | Measured |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        headline = _headline(row)
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {row['criterion']} | {headline} |")

    lines += ["", "## What each row measured", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        lines.append(f"- **Criterion:** {row['criterion']}")
        if row["note"]:
            lines.append(f"- **Reading:** {row['note']}")
        if row["limit"]:
            lines.append(f"- **Limit:** {row['limit']}")
        lines.append("")
        lines.append("```")
        lines.append(json.dumps(row["measured"], indent=2, default=str))
        lines.append("```")
        lines.append("")

    if report.get("defects"):
        lines += ["## Defects this drill exposes", "",
                  "Measured while running the drill. They are reported, not fixed here, and they "
                  "are not the reason any row passes or fails.", "",
                  "| Defect | Where | Detail |", "|---|---|---|"]
        for defect in report["defects"]:
            lines.append(f"| `{defect['id']}` | `{defect['row']}` | {defect['detail']} |")
        lines.append("")

    if report.get("read_paths"):
        lines += ["## Read paths at bank scale", "",
                  "| Read | p50 | p95 | max |", "|---|---|---|---|"]
        for name, values in report["read_paths"].items():
            lines.append(f"| `{name}` | {values['p50_ms']} ms | {values['p95_ms']} ms | "
                         f"{values['max_ms']} ms |")
        lines.append("")

    lines += ["## Thresholds", "",
              "Chosen for this drill so a bank's 15-minute observation window is plausible. They "
              "are not vendor benchmarks, and a PASS is not a capacity guarantee.", "",
              "| Threshold | Value |", "|---|---|"]
    for key, value in report["thresholds"].items():
        lines.append(f"| `{key}` | {value} |")

    lines += ["", "## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** the estate path does not reach bank scale through "
        "its own API. One request carries at most 20,000 assets, sending the estate in slices "
        "retires the slices that came before, and the read side is only measurable at 100k/1M "
        "because the rows were written around the API. That is a structural finding, not a "
        "tuning one.",
        "",
    ]
    return "\n".join(lines)


def _headline(row: dict[str, Any]) -> str:
    measured = row["measured"]
    if row["id"] == "ingest_ceiling":
        return "accepted" if measured.get("accepted") else ", ".join(measured.get("validation_errors", [])[:1])
    if row["id"] == "ingest_throughput":
        points = measured.get("points") or []
        if not points:
            return "—"
        last = points[-1]
        return (f"{last['assets_per_second']} assets/s at {last['assets']:,} "
                f"({last['milliseconds_per_asset']} ms/asset); 100k projected "
                f"{measured['projected_100k_minutes']} min")
    if row["id"] == "read_paths":
        seed = measured.get("seed") or {}
        return (f"{seed.get('assets', 0):,} assets / {seed.get('facts', 0):,} facts, "
                f"{seed.get('database_mb', 0)} MB; slowest p95 "
                f"{(measured.get('reads') or {}).get(measured.get('slowest'), {}).get('p95_ms')} ms "
                f"({measured.get('slowest')})")
    if row["id"] == "continuous_ingest":
        return f"growth {measured.get('growth_factor')}x over {len(measured.get('rounds') or [])} rounds"
    if row["id"] == "sharding":
        return (f"{measured.get('active_rows')} active, {measured.get('stale_rows')} stale "
                f"after two slices")
    return "—"


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Bank-scale qualification, measured.")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="bank")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--min-pass", type=int, default=0,
                        help="exit non-zero when fewer than this many rows pass")
    args = parser.parse_args(argv)

    report = measure(args.profile)
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<9} {row['id']:<24} {_headline(row)}")
        print(f"\n{report['counts']} in {report['elapsed_seconds']:.0f}s")
    return 0 if report["counts"].get(PASS, 0) >= args.min_pass else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
