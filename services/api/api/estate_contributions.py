"""One estate, many agents: compose per-contributor slices into one observation.

Before this module the live twin was *the newest push*. That is right for a single
collector that sees the whole estate, and wrong the moment a second agent exists: a
Cryptava agent on ``swiftgw01`` posting its own host would replace everything the
estate collector — and every other agent — had reported.

The stored observation is therefore split into slices:

* ``base`` — the last push that named no contributor (an estate-wide collector, the
  frontend-triggered scans). A new base push replaces only the base;
* ``contributions[<name>]`` — the last push from one named agent. A new push from that
  agent replaces only its own slice.

The twin is ``compose(base, contributions)``. Three rules keep that honest:

1. **local labels never cross slices.** Every ``ref`` (asset or evidence) and every
   explicit ``evidence_id`` inside a contributor slice is prefixed with
   ``<name>::`` before composition, so agent A's ``host`` label can never resolve to
   agent B's host. Canonical identity still merges: two planes that describe the same
   identity keys become one node, which is the point of the twin;
2. **the base wins name lookups.** Slices are composed before the base, so a base
   relationship that cites an asset by *name* resolves to the base's asset, never to an
   agent asset that happens to share the name;
3. **planes stay attributable.** Collector and coverage rows from a slice are labelled
   ``<name> · <plane>`` so a failed plane on one agent is never read as the estate's.
"""

from __future__ import annotations

from typing import Any, Mapping

SLICE_FIELDS = ("assets", "evidence", "relationships", "collectors", "coverage")
SEPARATOR = "::"


def empty_slice() -> dict[str, list]:
    return {field: [] for field in SLICE_FIELDS}


def slice_from(source: Mapping[str, Any]) -> dict[str, list]:
    return {field: [dict(item) for item in (source.get(field) or [])] for field in SLICE_FIELDS}


def stored_slices(payload: Mapping[str, Any] | None) -> tuple[dict[str, list], dict[str, dict]]:
    """``(base, contributions)`` from a stored ``estate_discovery`` payload.

    A payload written before contributions existed is all base — its lists *are* the
    estate as it was observed.
    """
    payload = payload or {}
    contributions = payload.get("contributions")
    if isinstance(contributions, Mapping) and isinstance(payload.get("base"), Mapping):
        base = slice_from(payload["base"])
        return base, {str(name): dict(entry) for name, entry in contributions.items()}
    return slice_from(payload), {}


def _ns(contributor: str, value: Any) -> str:
    return f"{contributor}{SEPARATOR}{value}"


def namespace(contributor: str, data: Mapping[str, Any]) -> dict[str, list]:
    """Prefix every slice-local label so it cannot collide with another slice."""
    out = slice_from(data)
    asset_labels: set[str] = set()
    for asset in out["assets"]:
        label = asset.get("ref") or asset.get("name")
        if label:
            asset_labels.add(str(label))
        if asset.get("name"):
            asset_labels.add(str(asset["name"]))
    evidence_labels: set[str] = set()
    for record in out["evidence"]:
        for key in ("ref", "evidence_id"):
            if record.get(key):
                evidence_labels.add(str(record[key]))

    def asset_ref(value: Any) -> Any:
        text = str(value or "")
        return _ns(contributor, text) if text in asset_labels else value

    def evidence_ref(value: Any) -> Any:
        text = str(value or "")
        return _ns(contributor, text) if text in evidence_labels else value

    for asset in out["assets"]:
        asset["ref"] = _ns(contributor, asset.get("ref") or asset.get("name"))
    for record in out["evidence"]:
        record["target"] = asset_ref(record.get("target"))
        if record.get("ref"):
            record["ref"] = _ns(contributor, record["ref"])
        if record.get("evidence_id"):
            record["evidence_id"] = _ns(contributor, record["evidence_id"])
    for edge in out["relationships"]:
        edge["subject"] = asset_ref(edge.get("subject"))
        edge["object"] = asset_ref(edge.get("object"))
        for key in ("evidence_ids", "evidence_refs"):
            if edge.get(key):
                edge[key] = [evidence_ref(item) for item in edge[key]]
    for row in out["collectors"]:
        row["plane"] = f"{contributor} · {row.get('plane') or 'UNKNOWN'}"
    for row in out["coverage"]:
        label = row.get("target") or row.get("plane") or "plane"
        row["target"] = f"{contributor} · {label}"
        row.pop("plane", None)
    return out


def compose(base: Mapping[str, Any], contributions: Mapping[str, Mapping[str, Any]]) -> dict[str, list]:
    """The estate the twin is built from: every slice, then the base."""
    composed = empty_slice()
    for name in sorted(contributions):
        entry = contributions[name] or {}
        prepared = namespace(name, entry)
        for field in SLICE_FIELDS:
            composed[field].extend(prepared[field])
    for field in SLICE_FIELDS:
        composed[field].extend(dict(item) for item in (base.get(field) or []))
    return composed


def contribution_entry(data: Mapping[str, Any], *, meta: Mapping[str, Any]) -> dict[str, Any]:
    """One stored slice: the agent's own (un-namespaced) lists plus who/when."""
    entry = slice_from(data)
    entry["meta"] = dict(meta)
    return entry


def summary(contributions: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for name in sorted(contributions):
        entry = contributions[name] or {}
        meta = entry.get("meta") or {}
        types: dict[str, int] = {}
        for asset in entry.get("assets") or []:
            kind = str(asset.get("type") or "UNKNOWN")
            types[kind] = types.get(kind, 0) + 1
        rows.append(
            {
                "contributor": name,
                "assets": len(entry.get("assets") or []),
                "evidence": len(entry.get("evidence") or []),
                "relationships": len(entry.get("relationships") or []),
                "asset_types": dict(sorted(types.items())),
                "planes": [
                    {"plane": row.get("plane"), "status": row.get("status") or row.get("state"),
                     "reason": row.get("reason")}
                    for row in entry.get("collectors") or []
                ],
                **{key: meta.get(key) for key in ("observed_at", "received_at", "authenticity",
                                                  "key_id", "agent_id", "agent_version")},
            }
        )
    return rows


__all__ = [
    "SLICE_FIELDS",
    "compose",
    "contribution_entry",
    "empty_slice",
    "namespace",
    "slice_from",
    "stored_slices",
    "summary",
]
