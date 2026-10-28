"""Evidence records and per-fact observation history (spec 94 §11, §19, §28).

Two gaps this closes, both of which made honest provenance answers impossible:

* evidence existed only inside the stored discovery payload, so "who observed this,
  from where, when, with what hash" meant finding the right run;
* an asset had ``observation_count`` but no idea what it *was* at any point in time, so
  "what was the algorithm on Tuesday" had no answer that was not a guess.

Design rules, carried from the rest of the twin:

* **A fact is a value with a window, not a column that gets overwritten.** A changed
  value adds a row and retires the previous one to ``HISTORICAL``; a value that comes
  back is revived, so a variable estate stops looking like a busy one.
* **Absence is not deletion.** A fact no longer observed is retired, never dropped.
* **Evidence attribution is asset-scoped, and says so.** Collectors attach evidence to
  an asset; they do not yet attribute an individual attribute to an individual record.
  Every fact therefore carries the evidence that establishes its *asset* and a
  ``provenance`` of ``ASSET`` / ``CRYPTO`` / ``RELATIONSHIP`` so the claim stops
  exactly where the evidence does.
* **Nothing here resolves a conflict.** Two values for one fact become two ``CURRENT``
  rows and a reported conflict — the twin's job is to show the disagreement.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import select

from api.estate_catalog import entries as catalogue_entries
from db.models.estate_catalog import (
    EstateAssetRecord,
    EstateEvidenceRecord,
    EstateObservationRecord,
)

SCHEMA = "cryptoscan.estate-observations/1"

# The facts a catalogued asset carries of its own. Attributes and crypto facts are
# added on top of these, keyed by their own names.
ASSET_FACT_FIELDS = ("asset_type", "name", "environment", "owner", "location")


def _digest(*parts: Any) -> str:
    payload = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def observation_id(asset_id: str, fact_type: str, value: str | None) -> str:
    """Content-addressed per fact *value*, so a value that returns is one row."""
    return f"obs-{_digest(asset_id, fact_type, value)[:24]}"


def evidence_record_id(evidence_id: str) -> str:
    return f"evr-{_digest(evidence_id)[:24]}"


def _text(value: Any) -> tuple[str | None, str]:
    """Canonical text for a value plus what kind it is (for display and diffing)."""
    if value is None:
        return None, "absent"
    if isinstance(value, bool):
        return ("true" if value else "false"), "bool"
    if isinstance(value, (int, float)):
        return str(value), "number"
    if isinstance(value, str):
        return value, "text"
    return json.dumps(value, sort_keys=True, default=str), "json"


def asset_fact_rows(entry: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every fact one catalogue entry asserts, as ``(fact_type, value, kind, provenance)``."""
    asset_id = str(entry["asset_id"])
    rows: list[dict[str, Any]] = []
    for field in ASSET_FACT_FIELDS:
        value, kind = _text(entry.get(field))
        if value is None:
            continue
        rows.append({
            "asset_id": asset_id,
            "fact_type": field,
            "value": value,
            "value_kind": kind,
            "provenance": "ASSET",
        })
    for key, raw in (entry.get("attributes") or {}).items():
        value, kind = _text(raw)
        if value is None:
            continue
        rows.append({
            "asset_id": asset_id,
            "fact_type": f"attribute:{key}",
            "value": value,
            "value_kind": kind,
            "provenance": "ASSET",
        })
    return rows


def fact_rows(graph: Any) -> dict[str, list[dict[str, Any]]]:
    """All facts the graph asserts, grouped by asset id.

    Crypto artifacts are attributed to their asset, because that is the only link the
    evidence supports; a relationship becomes a fact on its *subject*, named after the
    predicate, so "what connects this to X" is a fact with history like any other.
    """
    entries = catalogue_entries(graph)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for entry in entries.get("assets", []):
        grouped.setdefault(str(entry["asset_id"]), []).extend(asset_fact_rows(entry))
    for item in entries.get("crypto", []):
        asset_id = item.get("asset_id")
        if not asset_id:
            continue
        rows = grouped.setdefault(str(asset_id), [])
        for field in ("algorithm", "key_size", "protocol", "usage_state", "evidence_type"):
            value, kind = _text(item.get(field))
            if value is None:
                continue
            rows.append({
                "asset_id": str(asset_id),
                "fact_type": f"crypto:{field}",
                "value": value,
                "value_kind": kind,
                "provenance": "CRYPTO",
            })
    for edge in entries.get("relationships", []):
        if edge.get("status") != "ESTABLISHED":
            continue
        rows = grouped.setdefault(str(edge["subject_id"]), [])
        rows.append({
            "asset_id": str(edge["subject_id"]),
            # the vocabulary is upper-case (spec §6-8); the graph keeps the caller's case
            "fact_type": f"relationship:{str(edge.get('predicate')).upper()}",
            "value": str(edge.get("object_id")),
            "value_kind": "text",
            "provenance": "RELATIONSHIP",
        })
    return grouped


def _evidence_refs(graph: Any) -> dict[str, list[str]]:
    """Each asset's evidence ids, so a fact can cite the evidence behind its asset."""
    refs: dict[str, list[str]] = {}
    source = catalogue_entries(graph)
    for entry in source.get("assets", []):
        refs[str(entry["asset_id"])] = [str(item) for item in (entry.get("evidence_ids") or [])]
    return refs


def _evidence_types(graph: Any) -> dict[str, str]:
    return {str(item["evidence_id"]): str(item.get("evidence_type")) for item in graph.evidence()}


def _evidence_layers(graph: Any) -> dict[str, str]:
    return {str(item["evidence_id"]): str(item.get("layer")) for item in graph.evidence()}


def _existing(db: Any, model: Any, key_name: str, tenant_id: str | None) -> dict[str, Any]:
    stmt = select(model).where(model.tenant_id == tenant_id if tenant_id else model.tenant_id.is_(None))
    return {str(getattr(row, key_name)): row for row in db.execute(stmt).scalars()}


def _utc(moment: Any) -> datetime | None:
    if moment is None:
        return None
    return moment if getattr(moment, "tzinfo", None) else moment.replace(tzinfo=timezone.utc)


def sync_evidence(
    db: Any,
    graph: Any,
    *,
    tenant_id: str | None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Persist every evidence record in the graph, content-addressed and additive."""
    now = observed_at or datetime.now(timezone.utc)
    now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    existing = _existing(db, EstateEvidenceRecord, "evidence_id", tenant_id)

    created = refreshed = 0
    seen: set[str] = set()
    for item in graph.evidence():
        evidence_id = str(item["evidence_id"])
        seen.add(evidence_id)
        row = existing.get(evidence_id)
        if row is None:
            db.add(EstateEvidenceRecord(
                tenant_id=tenant_id,
                id=evidence_record_id(evidence_id),
                lifecycle_state="ACTIVE",
                observed_at=item.get("observed_at"),
                first_seen_at=now,
                last_seen_at=now,
                observation_count=1,
                evidence_id=evidence_id,
                schema_version=item.get("schema"),
                source=item.get("source"),
                collector=item.get("collector"),
                evidence_type=str(item.get("evidence_type") or "UNKNOWN"),
                confidence=item.get("confidence"),
                target_id=str(item.get("target") or ""),
                layer=item.get("layer"),
                facts=dict(item.get("facts") or {}),
            ))
            created += 1
            continue
        # the evidence id is content-addressed: the same record seen again advances its
        # count and keeps its first sighting, which is how staleness stays honest
        row.lifecycle_state = "ACTIVE"
        row.last_seen_at = now
        row.observation_count = int(row.observation_count or 0) + 1
        if item.get("observed_at"):
            row.observed_at = item.get("observed_at")
        refreshed += 1
    for evidence_id, row in existing.items():
        if evidence_id not in seen and row.lifecycle_state != "STALE":
            row.lifecycle_state = "STALE"

    db.commit()
    return {
        "created": created,
        "refreshed": refreshed,
        "total": len(seen),
        "stale": len([key for key in existing if key not in seen]),
    }


def sync(
    db: Any,
    graph: Any,
    *,
    tenant_id: str | None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Record one observation of every asserted fact, keeping the previous ones."""
    now = observed_at or datetime.now(timezone.utc)
    now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)

    grouped = fact_rows(graph)
    refs = _evidence_refs(graph)
    types = _evidence_types(graph)
    layers = _evidence_layers(graph)

    existing = _existing(db, EstateObservationRecord, "observation_id", tenant_id)
    # current facts, indexed for comparison: an existing CURRENT row is the truth this
    # run argues with, and a run that agrees is a refresh, not a change
    current: dict[tuple[str, str], list[EstateObservationRecord]] = {}
    for row in existing.values():
        if row.lifecycle_state == "CURRENT":
            current.setdefault((row.asset_id, row.fact_type), []).append(row)

    created = refreshed = superseded = revived = retired = 0
    conflicts: list[dict[str, Any]] = []
    for asset_id, rows in grouped.items():
        evidence_ids = refs.get(asset_id, [])
        primary = evidence_ids[0] if evidence_ids else None
        values_by_fact: dict[str, list[str]] = {}
        for row in rows:
            values_by_fact.setdefault(row["fact_type"], []).append(row["value"])

        for fact_type, values in values_by_fact.items():
            key = (asset_id, fact_type)
            held = current.get(key, [])
            if len(set(values)) > 1:
                conflicts.append({
                    "asset_id": asset_id,
                    "fact_type": fact_type,
                    "values": sorted(set(values)),
                    "meaning": "two observations disagree about this fact; both are kept as CURRENT",
                })
            for value in dict.fromkeys(values):
                row = existing.get(observation_id(asset_id, fact_type, value))
                if row is not None and row.lifecycle_state == "CURRENT":
                    row.last_seen_at = now
                    row.observation_count = int(row.observation_count or 0) + 1
                    refreshed += 1
                    continue
                if row is not None:
                    # the value was true before and is asserted again: revive the window
                    row.lifecycle_state = "CURRENT"
                    row.last_seen_at = now
                    row.observation_count = int(row.observation_count or 0) + 1
                    if primary and not row.evidence_id:
                        row.evidence_id = primary
                    revived += 1
                    continue
                entry_row = next(item for item in rows
                                 if item["fact_type"] == fact_type and item["value"] == value)
                db.add(EstateObservationRecord(
                    tenant_id=tenant_id,
                    observation_id=observation_id(asset_id, fact_type, value),
                    asset_id=asset_id,
                    fact_type=fact_type,
                    value=value,
                    value_kind=entry_row["value_kind"],
                    evidence_id=primary,
                    evidence_type=types.get(primary) if primary else None,
                    layer=layers.get(primary) if primary else None,
                    lifecycle_state="CURRENT",
                    first_seen_at=now,
                    last_seen_at=now,
                    observation_count=1,
                ))
                created += 1
            for old in held:
                if old.value not in values:
                    old.lifecycle_state = "HISTORICAL"
                    superseded += 1

        # a fact this asset no longer asserts is retired — including one whose asset is
        # still very much present. "the region is known" and "the region is no longer
        # reported" are different observations, and only one of them is silence.
        for (owner_id, held_fact), held_rows in current.items():
            if owner_id != asset_id or held_fact in values_by_fact:
                continue
            for row in held_rows:
                row.lifecycle_state = "HISTORICAL"
                retired += 1

    for key, rows in current.items():
        if key[0] in grouped:
            continue
        for row in rows:
            row.lifecycle_state = "HISTORICAL"
            retired += 1

    db.commit()

    current_total = db.execute(
        select(EstateObservationRecord).where(
            EstateObservationRecord.lifecycle_state == "CURRENT",
            EstateObservationRecord.tenant_id == tenant_id
            if tenant_id
            else EstateObservationRecord.tenant_id.is_(None),
        )
    ).scalars()
    return {
        "schema": SCHEMA,
        "observed_at": now.isoformat(),
        "created": created,
        "refreshed": refreshed,
        "revived": revived,
        "superseded": superseded,
        "retired": retired,
        "conflicts": conflicts,
        "counts": {
            "assets_with_facts": len(grouped),
            "current": len(list(current_total)),
        },
        "meaning": (
            "a fact is a value with a window: a change adds a row and retires the previous one to "
            "HISTORICAL, a returning value is revived rather than duplicated, and a fact no longer "
            "observed is retired — never deleted"
        ),
    }


def _iso(moment: Any) -> str | None:
    value = _utc(moment)
    return value.isoformat() if value else None


def resolve_asset_id(db: Any, identifier: str, *, tenant_id: str | None) -> str:
    """Accept an asset id *or* an exact name, the way the catalogue endpoints do.

    A human types "HSM-03"; the twin stores ``hsm:9c1f…``. Resolving here keeps the
    identifier rules in one place instead of every caller inventing a lookup.
    """
    stmt = select(EstateAssetRecord.asset_id).where(EstateAssetRecord.asset_id == identifier)
    stmt = stmt.where(
        EstateAssetRecord.tenant_id == tenant_id
        if tenant_id
        else EstateAssetRecord.tenant_id.is_(None)
    )
    if db.execute(stmt).scalars().first() is not None:
        return identifier
    by_name = select(EstateAssetRecord.asset_id).where(EstateAssetRecord.name == identifier)
    by_name = by_name.where(
        EstateAssetRecord.tenant_id == tenant_id
        if tenant_id
        else EstateAssetRecord.tenant_id.is_(None)
    )
    resolved = db.execute(by_name.order_by(EstateAssetRecord.last_seen_at.desc())).scalars().first()
    if resolved is not None:
        return str(resolved)
    # no catalogue row (history written without one): the "name" fact itself is the
    # index, so a name still resolves without inventing a second source of truth
    name_fact = select(EstateObservationRecord.asset_id).where(
        EstateObservationRecord.fact_type == "name",
        EstateObservationRecord.value == identifier,
    )
    name_fact = name_fact.where(
        EstateObservationRecord.tenant_id == tenant_id
        if tenant_id
        else EstateObservationRecord.tenant_id.is_(None)
    )
    found = db.execute(name_fact.order_by(EstateObservationRecord.last_seen_at.desc())).scalars().first()
    return str(found) if found else identifier


def history(db: Any, asset_id: str, *, tenant_id: str | None) -> dict[str, Any]:
    """Every fact this asset ever asserted, current value first, with its windows (§19)."""
    asset_id = resolve_asset_id(db, asset_id, tenant_id=tenant_id)
    stmt = select(EstateObservationRecord).where(EstateObservationRecord.asset_id == asset_id)
    stmt = stmt.where(
        EstateObservationRecord.tenant_id == tenant_id
        if tenant_id
        else EstateObservationRecord.tenant_id.is_(None)
    )
    rows = list(db.execute(stmt).scalars())

    grouped: dict[str, list[EstateObservationRecord]] = {}
    for row in rows:
        grouped.setdefault(row.fact_type, []).append(row)

    facts: list[dict[str, Any]] = []
    conflicted: list[str] = []
    for fact_type, items in sorted(grouped.items()):
        active = [row for row in items if row.lifecycle_state == "CURRENT"]
        if len(active) > 1:
            conflicted.append(fact_type)
        facts.append({
            "fact_type": fact_type,
            "provenance": _provenance(fact_type),
            "state": "CONFLICT" if len(active) > 1 else ("CURRENT" if active else "HISTORICAL"),
            "current_values": sorted({row.value for row in active if row.value is not None}),
            "timeline": [_public_observation(row) for row in
                         sorted(items, key=lambda item: (_utc(item.first_seen_at) or datetime.min.replace(tzinfo=timezone.utc)))],
        })

    return {
        "schema": SCHEMA,
        "asset_id": asset_id,
        "fact_count": len(facts),
        "fact_types": sorted(grouped),
        "conflicted_facts": sorted(conflicted),
        "facts": facts,
        "meaning": (
            "the current value of a fact is the value last observed; previous values are kept with "
            "the window in which they were true, so a change is a window that closed, not a lost row"
        ),
    }


def _provenance(fact_type: str) -> str:
    if fact_type.startswith("crypto:"):
        return "CRYPTO"
    if fact_type.startswith("relationship:"):
        return "RELATIONSHIP"
    if fact_type.startswith("attribute:"):
        return "ASSET"
    return "ASSET"


def _public_observation(row: EstateObservationRecord) -> dict[str, Any]:
    return {
        "observation_id": row.observation_id,
        "value": row.value,
        "value_kind": row.value_kind,
        "state": row.lifecycle_state,
        "evidence_id": row.evidence_id,
        "evidence_type": row.evidence_type,
        "layer": row.layer,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "observation_count": row.observation_count,
    }


def why(
    db: Any,
    asset_id: str,
    fact_type: str,
    *,
    tenant_id: str | None,
) -> dict[str, Any] | None:
    """§28: why does the twin believe this fact?

    The answer is the evidence that establishes the asset plus the windows in which
    each value held. It deliberately stops short of claiming that one attribute was
    observed by one record, and says where that claim would come from.
    """
    asset_id = resolve_asset_id(db, asset_id, tenant_id=tenant_id)
    asset_stmt = select(EstateAssetRecord).where(EstateAssetRecord.asset_id == asset_id)
    asset_stmt = asset_stmt.where(
        EstateAssetRecord.tenant_id == tenant_id if tenant_id else EstateAssetRecord.tenant_id.is_(None)
    )
    asset = db.execute(asset_stmt).scalars().first()

    obs_stmt = select(EstateObservationRecord).where(
        EstateObservationRecord.asset_id == asset_id,
        EstateObservationRecord.fact_type == fact_type,
    )
    obs_stmt = obs_stmt.where(
        EstateObservationRecord.tenant_id == tenant_id
        if tenant_id
        else EstateObservationRecord.tenant_id.is_(None)
    )
    observations = list(db.execute(obs_stmt).scalars())
    if not observations:
        return None

    # the catalogue is one source for "which evidence" and the history is another; an
    # answer that needed both would refuse to explain a fact it can see perfectly well
    if asset is not None:
        evidence_ids = [str(item) for item in (asset.evidence_ids or [])]
        asset_name = asset.name
    else:
        all_facts = select(EstateObservationRecord).where(
            EstateObservationRecord.asset_id == asset_id
        )
        all_facts = all_facts.where(
            EstateObservationRecord.tenant_id == tenant_id
            if tenant_id
            else EstateObservationRecord.tenant_id.is_(None)
        )
        rows = list(db.execute(all_facts).scalars())
        evidence_ids = sorted({str(row.evidence_id) for row in rows if row.evidence_id})
        asset_name = next(
            (row.value for row in rows if row.fact_type == "name" and row.value), asset_id
        )

    evidence_rows: list[dict[str, Any]] = []
    if evidence_ids:
        ev_stmt = select(EstateEvidenceRecord).where(
            EstateEvidenceRecord.evidence_id.in_(evidence_ids)
        )
        ev_stmt = ev_stmt.where(
            EstateEvidenceRecord.tenant_id == tenant_id
            if tenant_id
            else EstateEvidenceRecord.tenant_id.is_(None)
        )
        evidence_rows = [
            {
                "evidence_id": row.evidence_id,
                "collector": row.collector,
                "source": row.source,
                "evidence_type": row.evidence_type,
                "confidence": row.confidence,
                "target": row.target_id,
                "observed_at": row.observed_at,
                "first_seen_at": _iso(row.first_seen_at),
                "last_seen_at": _iso(row.last_seen_at),
                "facts": row.facts or {},
            }
            for row in db.execute(ev_stmt).scalars()
        ]

    active = [row for row in observations if row.lifecycle_state == "CURRENT"]
    return {
        "schema": SCHEMA,
        "asset_id": asset_id,
        "asset_name": asset_name,
        "fact_type": fact_type,
        "resolution": "CONFLICT" if len(active) > 1 else ("CURRENT" if active else "HISTORICAL"),
        "current_values": sorted({row.value for row in active if row.value is not None}),
        "observations": [
            _public_observation(row)
            for row in sorted(observations, key=lambda item: _utc(item.first_seen_at) or datetime.min.replace(tzinfo=timezone.utc))
        ],
        "evidence": evidence_rows,
        "evidence_scope": "ASSET",
        "answer": (
            f"{asset_name} carries {len(evidence_ids)} evidence record(s) from "
            f"{len({item['collector'] for item in evidence_rows}) or 0} collector(s); this fact is "
            f"{'disputed' if len(active) > 1 else ('currently held' if active else 'no longer observed')}"
        ),
        "limit": (
            "collectors attach evidence to an asset, not to an individual attribute: this shows the "
            "evidence behind the asset, not one record per attribute value"
        ),
    }


def evidence_for(
    db: Any,
    *,
    target: str | None = None,
    evidence_type: str | None = None,
    limit: int = 200,
    tenant_id: str | None,
) -> dict[str, Any]:
    """Stored evidence records, filterable by target or type (§11)."""
    stmt = select(EstateEvidenceRecord)
    stmt = stmt.where(
        EstateEvidenceRecord.tenant_id == tenant_id
        if tenant_id
        else EstateEvidenceRecord.tenant_id.is_(None)
    )
    if target:
        stmt = stmt.where(EstateEvidenceRecord.target_id == target)
    if evidence_type:
        stmt = stmt.where(EstateEvidenceRecord.evidence_type == evidence_type.upper())
    stmt = stmt.order_by(EstateEvidenceRecord.last_seen_at.desc()).limit(max(1, min(limit, 1000)))
    rows = list(db.execute(stmt).scalars())
    return {
        "schema": SCHEMA,
        "count": len(rows),
        "target": target,
        "evidence_type": evidence_type.upper() if evidence_type else None,
        "records": [
            {
                "evidence_id": row.evidence_id,
                "collector": row.collector,
                "source": row.source,
                "evidence_type": row.evidence_type,
                "confidence": row.confidence,
                "target": row.target_id,
                "layer": row.layer,
                "observed_at": row.observed_at,
                "lifecycle_state": row.lifecycle_state,
                "observation_count": row.observation_count,
                "first_seen_at": _iso(row.first_seen_at),
                "last_seen_at": _iso(row.last_seen_at),
                "facts": row.facts or {},
            }
            for row in rows
        ],
        "meaning": (
            "evidence is content-addressed: the same record observed twice is one row whose "
            "observation_count advances, and a record no longer produced is STALE with its "
            "first sighting intact"
        ),
    }


def summary(db: Any, *, tenant_id: str | None) -> dict[str, Any]:
    """Counts for the console: how much evidence and history the twin actually holds."""
    tenant_filter = (
        EstateObservationRecord.tenant_id == tenant_id
        if tenant_id
        else EstateObservationRecord.tenant_id.is_(None)
    )
    evidence_filter = (
        EstateEvidenceRecord.tenant_id == tenant_id
        if tenant_id
        else EstateEvidenceRecord.tenant_id.is_(None)
    )
    observations = list(db.execute(select(EstateObservationRecord).where(tenant_filter)).scalars())
    evidence = list(db.execute(select(EstateEvidenceRecord).where(evidence_filter)).scalars())

    current = [row for row in observations if row.lifecycle_state == "CURRENT"]
    assets = {row.asset_id for row in observations}
    conflicts: dict[tuple[str, str], int] = {}
    for row in current:
        conflicts[(row.asset_id, row.fact_type)] = conflicts.get((row.asset_id, row.fact_type), 0) + 1
    disputed = [key for key, count in conflicts.items() if count > 1]
    collectors = sorted({row.collector for row in evidence if row.collector})
    by_type: dict[str, int] = {}
    for row in evidence:
        by_type[row.evidence_type] = by_type.get(row.evidence_type, 0) + 1

    return {
        "schema": SCHEMA,
        "evidence": {
            "total": len(evidence),
            "active": len([row for row in evidence if row.lifecycle_state == "ACTIVE"]),
            "stale": len([row for row in evidence if row.lifecycle_state == "STALE"]),
            "collectors": collectors,
            "by_type": dict(sorted(by_type.items())),
        },
        "observations": {
            "total": len(observations),
            "current": len(current),
            "historical": len([row for row in observations if row.lifecycle_state == "HISTORICAL"]),
            "assets": len(assets),
            "changed_facts": len({(row.asset_id, row.fact_type) for row in observations
                                  if row.lifecycle_state == "HISTORICAL"}),
            "disputed_facts": len(disputed),
        },
        "disputes": [
            {"asset_id": asset_id, "fact_type": fact_type}
            for asset_id, fact_type in sorted(disputed)[:50]
        ],
        "meaning": (
            "the twin remembers every value it has ever asserted for a fact and the window in which "
            "it was true; a dispute is two values still asserted, never one chosen for you"
        ),
    }


def sync_all(
    db: Any,
    graph: Any,
    *,
    tenant_id: str | None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Both sides of the record in one call, for the discovery path to use."""
    evidence = sync_evidence(db, graph, tenant_id=tenant_id, observed_at=observed_at)
    facts = sync(db, graph, tenant_id=tenant_id, observed_at=observed_at)
    return {"schema": SCHEMA, "evidence": evidence, "observations": facts}
