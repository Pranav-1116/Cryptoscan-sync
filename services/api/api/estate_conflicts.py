"""Conflicts, kept as conflicts (spec 94 §23).

The twin's job when two observations disagree is to *show the disagreement*, not to pick
a winner. `EstateGraph.conflicts()` already refuses to resolve; what was missing is a
place to see them together, and a distinction a bank needs before it acts on one:

* **REAL** — two sources on the **same plane** disagree. The SBOM says OpenSSL 3.0.13,
  the container says 3.0.11, both are inventory claims: one of them is wrong, and a human
  has to find out which.
* **EXPLAINED** — the values come from **different planes**, and both can be true at
  once: a library that *supports* AES-128 and an API *observed* using AES-256-GCM are
  not in conflict, they are different claims about different things. Calling that a
  conflict trains an operator to ignore conflicts, which is worse than hiding them.

Both are reported. The classification is derived from the evidence behind each value, and
every entry carries the evidence ids, so the answer to "why do you think these disagree"
is in the same payload as the disagreement.

Nothing here edits, merges or "resolves". A conflict is resolved when a human says so and
a new observation proves it — not when the newest timestamp wins.
"""
from __future__ import annotations

from typing import Any, Mapping

from sqlalchemy import select

from db.models.estate_catalog import EstateObservationRecord
from shared_models.estate_graph import CONFLICT_FIELDS

SCHEMA = "cryptoscan.estate-conflicts/1"

#: the smallest set of planes a disagreement can span. A value from each of two different
#: layers is explainable; two values inside one layer are not.
PLANE_ORDER = ("APPLICATION", "NETWORK_TRANSPORT", "STORAGE", "HSM", "KMS", "PLATFORM")

NEXT_ACTION = {
    "REAL": (
        "two sources on the same plane disagree about this. Decide which observation is correct, "
        "fix the source that is wrong, and re-collect — re-running the collector that produced the "
        "stale value is how the conflict closes, not editing the twin"
    ),
    "EXPLAINED": (
        "the values come from different planes and can both be true. Read them as separate claims "
        "(capability vs use, or configured vs observed) rather than as a contradiction — nothing "
        "needs fixing"
    ),
    "UNKNOWN": (
        "the evidence does not say which plane each value came from, so it cannot be classified. "
        "Treat it as real until a collector states its plane"
    ),
}


def _classify(values: list[Mapping[str, Any]]) -> tuple[str, str]:
    """REAL, EXPLAINED or UNKNOWN — decided from the planes the values came from."""
    # an unstated plane is not a *different* plane: it is missing information, and
    # counting it as one would turn every record with an attribution gap into an
    # "explained" conflict — which is how a conflict list stops being read
    layers = {str(item.get("layer") or "UNKNOWN").upper() for item in values}
    known = layers - {"UNKNOWN"}
    if not known:
        return "UNKNOWN", (
            "no plane was recorded for the disagreeing values, so this cannot be classified; "
            "treat it as real until a collector states its plane"
        )
    layers = known
    if len(layers) > 1:
        return "EXPLAINED", (
            f"the values come from different planes ({', '.join(sorted(layers))}) and can both be "
            "true at once"
        )
    return "REAL", (
        f"two observations on the same plane ({', '.join(sorted(layers))}) disagree; one of them is "
        "wrong"
    )


def _evidence_layers(graph: Any) -> dict[str, tuple[str, str]]:
    return {
        str(item["evidence_id"]): (str(item.get("layer") or "UNKNOWN"), str(item.get("evidence_type") or "UNKNOWN"))
        for item in graph.evidence()
    }


def from_graph(graph: Any) -> list[dict[str, Any]]:
    """The graph's own conflicts, each classified against the evidence behind its values."""
    layers = _evidence_layers(graph)
    entries: list[dict[str, Any]] = []
    for conflict in graph.conflicts():
        values = []
        for item in conflict.get("values") or []:
            layer, evidence_type = layers.get(str(item.get("evidence_id")), ("UNKNOWN", str(item.get("evidence_type") or "UNKNOWN")))
            values.append({
                "value": item.get("value"),
                "source": item.get("source"),
                "evidence_type": evidence_type,
                "layer": layer,
                "evidence_id": item.get("evidence_id"),
                "observed_at": item.get("observed_at"),
            })
        verdict, reason = _classify(values)
        entries.append({
            "asset_id": conflict.get("asset_id"),
            "asset_name": conflict.get("asset_name"),
            "field": conflict.get("field"),
            "values": values,
            "classification": verdict,
            "reason": reason,
            "status": "CONFLICT",
            "source_of_conflict": "observation",
            "next_action": NEXT_ACTION[verdict],
        })
    return entries


def from_history(db: Any, *, tenant_id: str | None, graph_asset_names: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    """Facts with two *currently asserted* values in the per-fact record (§19, §23).

    A change retires the previous value, so a fact with two CURRENT rows is not an
    ordinary change — it is a dispute the record is still holding.
    """
    stmt = select(EstateObservationRecord).where(
        EstateObservationRecord.lifecycle_state == "CURRENT",
        EstateObservationRecord.tenant_id == tenant_id
        if tenant_id
        else EstateObservationRecord.tenant_id.is_(None),
    )
    rows = list(db.execute(stmt).scalars())

    grouped: dict[tuple[str, str], list[EstateObservationRecord]] = {}
    for row in rows:
        grouped.setdefault((row.asset_id, row.fact_type), []).append(row)

    names = dict(graph_asset_names or {})
    entries: list[dict[str, Any]] = []
    for (asset_id, fact_type), held in sorted(grouped.items()):
        if len({row.value for row in held}) < 2:
            continue
        # a recorded fact cites the evidence behind its *asset*, not the record that
        # observed that value; claiming a plane per value here would invent the very
        # precision this module is careful about, so the plane is left unstated and the
        # classification says UNKNOWN until an observation supplies it
        values = [
            {
                "value": row.value,
                "source": row.evidence_id,
                "evidence_type": row.evidence_type,
                "layer": None,
                "evidence_scope": "ASSET",
                "evidence_id": row.evidence_id,
                "observed_at": _iso(row.last_seen_at),
            }
            for row in held
        ]
        verdict, reason = _classify(values)
        # the field is the bare name — "algorithm", not "crypto:algorithm" — so a dispute
        # seen by the history and the same dispute seen by the observation merge instead of
        # being reported twice under two spellings
        field = fact_type.split(":", 1)[1] if ":" in fact_type else fact_type
        if field not in CONFLICT_FIELDS:
            # two artefacts of one asset with different usage states is normal, not a
            # disagreement about a fact — only the fields the twin treats as
            # conflict-bearing belong in a conflict list
            continue
        entries.append({
            "asset_id": asset_id,
            "asset_name": names.get(asset_id),
            "field": field,
            "fact_type": fact_type,
            "values": values,
            "classification": verdict,
            "reason": reason,
            "status": "CONFLICT",
            "source_of_conflict": "history",
            "next_action": NEXT_ACTION[verdict],
        })
    return entries


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    value = moment if getattr(moment, "tzinfo", None) else moment.replace(tzinfo=None)
    return value.isoformat()


def survey(
    db: Any,
    graph: Any | None = None,
    *,
    tenant_id: str | None,
) -> dict[str, Any]:
    """Every conflict the twin is currently holding, classified and de-duplicated.

    The same disagreement can appear twice — once from the current observation and once
    from the durable fact history — so entries are merged on ``(asset, field)`` with the
    sources named, rather than reported as two separate problems.
    """
    names: dict[str, str] = {}
    if graph is not None:
        names = {str(asset["asset_id"]): str(asset.get("name")) for asset in graph.assets()}

    merged: dict[tuple[str, str], dict[str, Any]] = {}
    sources: dict[tuple[str, str], set[str]] = {}
    for entry in (from_graph(graph) if graph is not None else []) + from_history(
        db, tenant_id=tenant_id, graph_asset_names=names
    ):
        key = (str(entry["asset_id"]), str(entry["field"]))
        sources.setdefault(key, set()).add(entry["source_of_conflict"])
        if key not in merged:
            merged[key] = entry
            continue
        existing = merged[key]
        seen = {(item.get("evidence_id"), repr(item.get("value"))) for item in existing["values"]}
        for item in entry["values"]:
            if (item.get("evidence_id"), repr(item.get("value"))) not in seen:
                existing["values"].append(item)
        # a conflict seen from both sides is re-classified over the union of its values
        verdict, reason = _classify(existing["values"])
        existing["classification"] = verdict
        existing["reason"] = reason
        existing["next_action"] = NEXT_ACTION[verdict]

    entries = sorted(
        merged.values(),
        key=lambda item: (
            {"REAL": 0, "UNKNOWN": 1, "EXPLAINED": 2}[item["classification"]],
            str(item.get("asset_name") or item["asset_id"]),
            str(item["field"]),
        ),
    )
    for entry in entries:
        key = (str(entry["asset_id"]), str(entry["field"]))
        entry["seen_by"] = sorted(sources.get(key, set()))

    by_class: dict[str, int] = {"REAL": 0, "EXPLAINED": 0, "UNKNOWN": 0}
    for entry in entries:
        by_class[entry["classification"]] += 1

    return {
        "schema": SCHEMA,
        "conflicts": entries,
        "count": len(entries),
        "by_classification": by_class,
        "real_count": by_class["REAL"],
        "explained_count": by_class["EXPLAINED"],
        "assets_affected": len({entry["asset_id"] for entry in entries}),
        "meaning": (
            "a conflict is reported, never resolved: two assertions about the same field are shown "
            "side by side with the evidence behind each. REAL means two sources on one plane "
            "disagree; EXPLAINED means the values come from different planes and can both be true"
        ),
        "limits": [
            "only fields the twin treats as conflict-bearing are compared (algorithm, key size, "
            "protocol, version, environment); silent disagreement elsewhere is invisible",
            "an empty list is not 'no conflicts in the bank' — it is no conflict in what has been "
            "observed",
            "nothing here decides which value is true; closing a conflict needs a corrected source "
            "and a re-collection",
        ],
    }


__all__ = ["NEXT_ACTION", "SCHEMA", "from_graph", "from_history", "survey"]
