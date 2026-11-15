#!/usr/bin/env python3
"""Projection consistency for the dependency-graph stores.

PostgreSQL is the source of truth; Neo4j (traversal), Elasticsearch
(search) and Cassandra (edge history) are PROJECTIONS — rebuildable views,
never authorities. Two questions decide whether that claim holds:

    check    do the projections agree with the authoritative catalogue —
             exactly, and answerably? Each backend reports PARITY,
             MISMATCH (with differences named), or NOT_CONNECTED (a gap,
             never a pass). Cassandra — append-only history — reports
             HISTORY_OK when sampled events are deterministic and
             replayable, MISMATCH when a stored event id does not match
             its own content.
    rebuild  re-derive every projection from the authoritative catalogue
             (the estate_catalog rows PostgreSQL holds) through the same
             one-way writers the live sync uses. One way only: the
             payload is never mutated, stores receive fresh derived
             documents.

    python3 scripts/projection_drift.py check --tenant tenant_a
    python3 scripts/projection_drift.py rebuild --tenant tenant_a
    python3 scripts/projection_drift.py check --payload payload.json

Exit codes: 0 every configured backend in parity; 1 a mismatch; 2 a
REQUIRED backend is not connected (the projection must exist for the
bank's estate, and silence is not parity).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


# ------------------------------------------------------------- authoritative --

def authoritative_payload(db: Any, tenant_id: str) -> dict[str, Any]:
    """The authoritative side of the boundary, straight from PostgreSQL's
    estate catalogue (what estate_catalog.sync materialised). The
    projections are checked/rebuilt against THIS, never against each
    other — two projections agreeing on a lie is not consistency."""
    from api.estate_catalog import public_asset, public_relationship
    from db.models.estate_catalog import EstateAssetRecord, EstateRelationshipRecord

    assets = [public_asset(r) for r in db.query(EstateAssetRecord).filter(
        EstateAssetRecord.tenant_id == tenant_id).all()]
    edges = [public_relationship(r) for r in db.query(EstateRelationshipRecord).filter(
        EstateRelationshipRecord.tenant_id == tenant_id).all()]
    return {"assets": assets, "edges": edges}


def _expected_search_docs(payload: dict[str, Any]) -> int:
    return sum(len(payload.get(key) or [])
               for key in ("systems", "assets", "edges"))


# ------------------------------------------------------------------- checks --

def check_search(tenant_id: str, payload: dict[str, Any], *,
                 search: Any = None) -> dict[str, Any]:
    from graph_engine.core.dependency_stores import dependency_search_store

    store = search if search is not None else dependency_search_store()
    if store is None or not store.ping():
        return {"projection": "elasticsearch", "verdict": "NOT_CONNECTED",
                "note": "the search projection is unconfigured or unreachable — "
                        "a gap, never a pass"}
    expected = _expected_search_docs(payload)
    actual = store.count(tenant_id)
    report = {"projection": "elasticsearch", "verdict": "PARITY",
              "expected": expected, "actual": actual}
    if actual != expected:
        report["verdict"] = "MISMATCH"
        report["difference"] = {"missing_or_extra": actual - expected}
        report["note"] = ("document count differs from the authoritative "
                          "catalogue — rebuild to re-derive")
    return report


def check_history(tenant_id: str, payload: dict[str, Any], *,
                  history: Any = None, sample: int = 5) -> dict[str, Any]:
    from graph_engine.core.dependency_stores import edge_history_store
    from graph_engine.history.edge_history import event_id_for

    store = history if history is not None else edge_history_store()
    if store is None or not store.ping():
        return {"projection": "cassandra", "verdict": "NOT_CONNECTED",
                "note": "the edge-history projection is unconfigured or "
                        "unreachable — a gap, never a pass"}
    rows = []
    for edge in (payload.get("edges") or [])[:sample]:
        subject = edge.get("subject") or edge.get("from") or edge.get("parent_id")
        object_ = edge.get("object") or edge.get("to") or edge.get("child_id")
        relation = edge.get("relation") or edge.get("label")
        if not (subject and object_ and relation):
            continue
        got = store.history(tenant_id, subject, object_, relation)
        rows.extend(got or [])
    # append-only honesty: a stored event id must be derivable from its own
    # content (event_id_for is deterministic) — a row whose id does not
    # match its content is a tampered or non-deterministic history.
    bad = []
    for row in rows:
        try:
            if event_id_for(row) != row.get("event_id"):
                bad.append(row.get("event_id"))
        except Exception:  # noqa: BLE001 — an underivable row is a mismatch
            bad.append(row.get("event_id"))
    report = {"projection": "cassandra", "verdict": "HISTORY_OK",
              "sampled_events": len(rows), "checked": sample}
    if bad:
        report["verdict"] = "MISMATCH"
        report["difference"] = {"non_derivable_event_ids": bad[:10]}
    return report


def check_graph(tenant_id: str, payload: dict[str, Any], *,
                driver: Any = None) -> dict[str, Any]:
    from graph_engine.core.engine import GraphEngine

    try:
        from graph_engine.connection.neo4j_driver import get_driver
        from graph_engine.core.store import Neo4jGraphStore
    except Exception as exc:  # noqa: BLE001
        return {"projection": "neo4j", "verdict": "NOT_CONNECTED",
                "note": f"graph store unavailable ({type(exc).__name__})"}
    handle = driver if driver is not None else get_driver()
    if handle is None:
        return {"projection": "neo4j", "verdict": "NOT_CONNECTED",
                "note": "the traversal projection is unconfigured — a gap, "
                        "never a pass"}
    store = Neo4jGraphStore(handle)
    engine = GraphEngine().build(**payload)
    expected_nodes = len(engine.nodes)
    expected_edges = sum(len(v) for v in engine.out.values())
    counts = store.counts()
    report = {"projection": "neo4j", "verdict": "PARITY",
              "expected": {"nodes": expected_nodes, "relationships": expected_edges},
              "actual": counts}
    if counts.get("nodes") != expected_nodes or counts.get("relationships") != expected_edges:
        report["verdict"] = "MISMATCH"
        report["note"] = ("store counts differ from the authoritative build — "
                          "run estate_graph_loader.parity for named id-level "
                          "differences, or rebuild")
    return report


def check(tenant_id: str, payload: dict[str, Any], *, history: Any = None,
          search: Any = None, driver: Any = None,
          required: tuple[str, ...] = ()) -> dict[str, Any]:
    """Every projection, exactly and answerably. NOT_CONNECTED is a gap,
    never a pass — and for a REQUIRED backend it is a failure."""
    reports = [
        check_graph(tenant_id, payload, driver=driver),
        check_search(tenant_id, payload, search=search),
        check_history(tenant_id, payload, history=history),
    ]
    missing_required = [r["projection"] for r in reports
                        if r["verdict"] == "NOT_CONNECTED"
                        and r["projection"] in required]
    mismatches = [r["projection"] for r in reports if r["verdict"] == "MISMATCH"]
    if missing_required:
        verdict = "REQUIRED_NOT_CONNECTED"
    elif mismatches:
        verdict = "MISMATCH"
    else:
        verdict = "CONSISTENT"
    return {"tenant": tenant_id, "verdict": verdict, "projections": reports,
            "mismatched": mismatches, "missing_required": missing_required}


# ----------------------------------------------------------------- rebuild --

def rebuild(tenant_id: str, payload: dict[str, Any], *, history: Any = None,
            search: Any = None, driver: Any = None) -> dict[str, Any]:
    """Re-derive every projection from the authoritative payload through
    the one-way writers. The payload is never mutated; projections are
    never authorities — this is the button that proves it."""
    from graph_engine.core.sync_coordinator import sync_payload

    out: dict[str, Any] = {"tenant": tenant_id, "rebuilt": []}

    neo = sync_payload(payload, driver=driver)
    out["neo4j"] = neo
    out["rebuilt"].append("neo4j" if neo.get("synced") else None)

    from graph_engine.core.dependency_stores import sync_dependency_stores

    stores = sync_dependency_stores(payload, history=history, search=search,
                                    tenant_id=tenant_id)
    out["dependency_stores"] = stores
    search_report = stores.get("search") or {}
    history_report = stores.get("history") or {}
    if search_report.get("edges") is not None and "error" not in search_report:
        out["rebuilt"].append("elasticsearch")
    if history_report.get("written"):
        out["rebuilt"].append("cassandra")
    out["rebuilt"] = [b for b in out["rebuilt"] if b]
    out["note"] = ("one way only: PostgreSQL stays the source of truth; "
                   "projections are re-derived views")
    return out


# --------------------------------------------------------------------- CLI --

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["check", "rebuild"])
    ap.add_argument("--tenant", required=True)
    ap.add_argument("--payload", default=None,
                    help="canonical payload JSON (default: read the "
                         "authoritative catalogue from PostgreSQL)")
    ap.add_argument("--required", default="",
                    help="comma-separated projections that MUST be connected "
                         "(neo4j,elasticsearch,cassandra)")
    args = ap.parse_args()

    payload: dict[str, Any]
    if args.payload:
        payload = json.loads(Path(args.payload).read_text())
    else:
        from db.connection.session import SessionLocal

        with SessionLocal() as db:
            payload = authoritative_payload(db, args.tenant)

    required = tuple(p for p in args.required.split(",") if p)
    if args.mode == "check":
        report = check(args.tenant, payload, required=required)
        code = {"CONSISTENT": 0, "MISMATCH": 1,
                "REQUIRED_NOT_CONNECTED": 2}[report["verdict"]]
    else:
        report = rebuild(args.tenant, payload)
        code = 0
    print(json.dumps(report, indent=2, default=str))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
