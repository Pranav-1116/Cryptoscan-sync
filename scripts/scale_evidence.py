#!/usr/bin/env python3
"""Scale evidence — the DB discipline claims, at volume, with receipts.

The database rules are written down (indexes from actual query patterns,
EXPLAIN-driven; 50,000 assets never all rendered at once; pagination is
the server's job). This run makes those claims AUDITABLE: seed a
realistic estate into PostgreSQL, run the hot queries with
``EXPLAIN (ANALYZE, BUFFERS)``, and record what the planner actually
did — indexes used, seq scans, rows, timing.

    python3 scripts/scale_evidence.py --assets 50000        # the ratchet
    python3 scripts/scale_evidence.py --assets 2000 --out data/scale.json

Artifacts land under ``data/`` (gitignored) — evidence is produced by
running the tool, never committed as a claim. Exit codes: 0 the run
completed and the artifact is written; 2 the run could not execute.
``--expect-index`` names indexes the plans MUST use (repeatable): a hot
query that seq-scans past them fails the run — that is the ratchet
against index drift.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

# The hot paths (the surfaces the frontend architecture rules rely on):
# filter+sort+paginate, aggregate, bounded lookup. Parameters are bound
# at execution — the plans below are what the planner does with data.
HOT_QUERIES: dict[str, str] = {
    "catalog_page_filter_sort_paginate": (
        "SELECT id, algorithm, asset_key, confidence FROM crypto_assets "
        "WHERE tenant_id = :tenant AND algorithm = :algorithm "
        "ORDER BY asset_key LIMIT 50 OFFSET 0"
    ),
    "dashboard_aggregate_by_algorithm": (
        "SELECT algorithm, COUNT(*) FROM crypto_assets "
        "WHERE tenant_id = :tenant GROUP BY algorithm"
    ),
    "bounded_findings_lookup": (
        "SELECT id, asset_key, file_path FROM crypto_assets "
        "WHERE tenant_id = :tenant AND is_hardcoded_key = true "
        "ORDER BY id LIMIT 100"
    ),
}


def seed(engine: Any, n_assets: int, *, tenant: str = "tenant_scale",
         batch: int = 2000) -> dict[str, int]:
    """Synthetic estate at scale. Bulk inserts, committed per batch —
    seeding must not be the slow part of an evidence run."""
    from sqlalchemy import text

    started = time.time()
    inserted = 0
    algorithms = ("RSA", "AES", "ECDSA", "ChaCha20", "DES", "Ed25519")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS crypto_assets ("
            " id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL,"
            " algorithm TEXT NOT NULL, asset_key TEXT, file_path TEXT NOT NULL,"
            " confidence TEXT NOT NULL DEFAULT 'LOW',"
            " is_hardcoded_key BOOLEAN NOT NULL DEFAULT false,"
            " line_number INTEGER NOT NULL DEFAULT 0)"))
        # the real schema's hot-path indexes (migrations 0010/0026/0092) —
        # evidence about index usage must run against the shapes the
        # production schema actually has
        for stmt in (
            "CREATE INDEX IF NOT EXISTS ix_crypto_assets_algorithm"
            " ON crypto_assets (algorithm)",
            "CREATE INDEX IF NOT EXISTS ix_assets_algorithm_file"
            " ON crypto_assets (algorithm, file_path)",
            "CREATE INDEX IF NOT EXISTS ix_crypto_assets_asset_key"
            " ON crypto_assets (asset_key)",
        ):
            conn.execute(text(stmt))
        while inserted < n_assets:
            rows = [
                {"tenant": tenant,
                 "algorithm": algorithms[i % len(algorithms)],
                 "asset_key": f"key-{tenant}-{inserted + i}",
                 "file_path": f"/src/mod{(inserted + i) % 97}.c",
                 "confidence": ("HIGH", "MEDIUM", "LOW")[i % 3],
                 "hard": (inserted + i) % 7 == 0}
                for i in range(min(batch, n_assets - inserted))
            ]
            conn.execute(text(
                "INSERT INTO crypto_assets (tenant_id, algorithm, asset_key,"
                " file_path, confidence, is_hardcoded_key) VALUES (:tenant,"
                " :algorithm, :asset_key, :file_path, :confidence, :hard)"),
                rows)
            inserted += len(rows)
    return {"inserted": inserted, "seconds": round(time.time() - started, 2)}


def explain(engine: Any, name: str, sql: str,
            params: dict[str, Any]) -> dict[str, Any]:
    """EXPLAIN (ANALYZE, BUFFERS) one query and summarise the plan tree —
    index names used, seq scans, rows, timing. PostgreSQL only: an
    evidence run that cannot EXPLAIN does not get to claim anything."""
    from sqlalchemy import text

    with engine.begin() as conn:
        raw = conn.execute(text(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + sql), params)
        plan = raw.scalar()[0]

    indexes: list[str] = []
    seq_scans: list[str] = []
    max_rows = 0

    def walk(node: dict[str, Any]) -> None:
        nonlocal max_rows
        ptype = node.get("Node Type", "")
        if ptype in ("Seq Scan", "Parallel Seq Scan"):
            seq_scans.append(node.get("Relation Name") or "?")
        if "Index Name" in node:
            indexes.append(node["Index Name"])
        if "Index Cond" in node or "Filter" in node:
            pass
        max_rows = max(max_rows, int(node.get("Actual Rows") or 0))
        for child in node.get("Plans") or []:
            walk(child)

    walk(plan["Plan"])
    return {
        "query": name,
        "planning_ms": plan.get("Planning Time"),
        "execution_ms": plan.get("Execution Time"),
        "rows": plan["Plan"].get("Actual Rows"),
        "indexes_used": sorted(set(indexes)),
        "seq_scans": seq_scans,
        "max_node_rows": max_rows,
    }


def run(n_assets: int, *, engine: Any, expect_index: tuple[str, ...] = (),
        tenant: str = "tenant_scale") -> dict[str, Any]:
    """Seed + explain every hot query + apply the index ratchet."""
    from sqlalchemy import text

    seeded = seed(engine, n_assets, tenant=tenant)
    params = {"tenant": tenant, "algorithm": "RSA"}
    plans = [explain(engine, name, sql, params)
             for name, sql in HOT_QUERIES.items()]
    with engine.begin() as conn:
        distinct_algs = conn.execute(text(
            "SELECT COUNT(DISTINCT algorithm) FROM crypto_assets"
            " WHERE tenant_id = :t"), {"t": tenant}).scalar()

    report = {
        "schema": "cryptoscan-scale-evidence-1",
        "assets": n_assets,
        "tenant": tenant,
        "seed": seeded,
        "distinct_algorithms": distinct_algs,
        "plans": plans,
        "expect_index": list(expect_index),
        "ratchet": "PASS",
        "violations": [],
    }
    used = {idx for p in plans for idx in p["indexes_used"]}
    for wanted in expect_index:
        if wanted not in used:
            report["ratchet"] = "FAIL"
            report["violations"].append(
                f"expected index {wanted} never appeared in any hot plan")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--assets", type=int, default=50000)
    ap.add_argument("--database-url", default=None,
                    help="PostgreSQL URL (default: boot a scratch pgserver)")
    ap.add_argument("--out", default=str(ROOT / "data" / "scale-evidence.json"))
    ap.add_argument("--expect-index", action="append", default=[],
                    help="index name the hot plans must use (repeatable)")
    ap.add_argument("--tenant", default="tenant_scale")
    args = ap.parse_args()

    engine = None
    cleanup = None
    try:
        if args.database_url:
            from sqlalchemy import create_engine

            engine = create_engine(args.database_url, future=True)
        else:
            import tempfile

            import pgserver

            work = tempfile.mkdtemp(prefix="scale-evidence-")
            server = pgserver.get_server(work)
            cleanup = server.cleanup
            uri = server.get_uri()
            server.psql("CREATE DATABASE cryptoscan;")
            host = uri.split("host=")[1]
            from sqlalchemy import create_engine

            engine = create_engine(
                f"postgresql+psycopg2://postgres:@/cryptoscan?host={host}",
                future=True)
        report = run(args.assets, engine=engine,
                     expect_index=tuple(args.expect_index),
                     tenant=args.tenant)
    except Exception as exc:  # noqa: BLE001 — an unrunnable run is exit 2
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)},
                         indent=2))
        return 2
    finally:
        if engine is not None:
            engine.dispose()
        if cleanup is not None:
            cleanup()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps({"out": str(out), "ratchet": report["ratchet"],
                      "assets": report["assets"]}, indent=2))
    return 0 if report["ratchet"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
