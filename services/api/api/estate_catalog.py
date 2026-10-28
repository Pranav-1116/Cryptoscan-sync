"""The durable canonical estate catalogue — the twin's memory (spec 94 §19, §22, §26).

The twin was reconstructed on every request from the newest stored discovery payload.
That answers "what is there now" and cannot answer the questions that make a twin
worth keeping:

* when did we first see this asset, and when did we last see it?
* is this missing from the latest run, or retired, or was it never really there?
* which evidence establishes this edge — and has it been asserted in every run or once?
* which assets actually *use* RSA-2048, as opposed to merely supporting it?

This module materialises a graph into three records (assets, relationships, crypto
artefacts) and keeps them across observations. Four rules, enforced rather than
documented:

1. **Derived, never typed.** Every field comes from the graph, which comes from
   evidence. Nothing here invents a fact, and every row carries the evidence ids
   behind it.
2. **Absence is not deletion.** A row not present in the latest observation becomes
   ``STALE`` with ``last_seen_at`` intact. A host that stopped answering, a plane that
   failed and a decommissioned server all look the same in a diff; the catalogue
   refuses to turn that ambiguity into a deletion.
3. **Capability and use never merge.** Crypto rows are keyed by the graph's
   ``artifact_id``, which is per-artefact-per-plane, so ``SUPPORTED AES-128`` and
   ``OBSERVED AES-256-GCM`` stay two rows. A registry that merged them would produce
   exactly the CBOM bug this product exists to prevent.
4. **An unresolved candidate is not a relationship.** It is stored (it is what a bank
   most wants to chase) with ``status='UNRESOLVED'`` and its refusal reason, and every
   read path that answers "what depends on what" filters on ``ESTABLISHED``.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from sqlalchemy import select

from db.models.estate_catalog import (
    EstateAssetRecord,
    EstateCryptoRecord,
    EstateRelationshipRecord,
)

SCHEMA = "cryptoscan.estate-catalog/1"
REGISTRY_SCHEMA = "cryptoscan.estate-crypto-registry/1"

#: lifecycle states a catalogue row can be in. There is no DELETED on purpose.
LIFECYCLE_STATES = ("ACTIVE", "STALE")

LIST_LIMIT = 200


def _digest(*parts: Any) -> str:
    body = "|".join(str(part) for part in parts)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:32]


def asset_entries(graph: Any) -> list[dict[str, Any]]:
    """Every canonical asset in the graph, as a storable record."""
    entries: list[dict[str, Any]] = []
    for asset in graph.assets():
        evidence_ids = [str(item) for item in (asset.get("evidence_refs") or [])]
        entries.append(
            {
                "asset_id": str(asset["asset_id"]),
                "asset_type": str(asset.get("type") or "UNKNOWN"),
                "name": str(asset.get("name") or "UNKNOWN"),
                "environment": asset.get("environment"),
                "owner": asset.get("owner"),
                "location": asset.get("location"),
                "source": asset.get("source"),
                "identity": dict(asset.get("identity") or {}),
                "attributes": dict(asset.get("attributes") or {}),
                "evidence_ids": evidence_ids,
                "evidence_count": len(evidence_ids),
            }
        )
    return sorted(entries, key=lambda entry: entry["asset_id"])


#: strongest first: an edge established by a runtime observation is not downgraded to the
#: weakest record that happens to cite it
_EVIDENCE_RANK = {
    "RUNTIME_OBSERVED": 0,
    "NETWORK_ACTIVE_OBSERVED": 1,
    "CERTIFICATE_OBSERVED": 2,
    "AUDIT_OBSERVED": 3,
    "NETWORK_PASSIVE_OBSERVED": 4,
    "STATIC_OBSERVED": 5,
    "CONFIGURED": 6,
    "VENDOR_DECLARED": 7,
    "IMPORTED": 8,
    "INFERRED": 9,
    "UNKNOWN": 10,
}


def _provenance(edge: Mapping[str, Any], evidence: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """§8 — what kind of evidence established this edge, and when was it observed.

    A relationship is not a foreign key, so the answer to "how do you know?" belongs on the
    edge. The type reported is the *strongest* of the records behind it, and the time is the
    latest of those, because an edge keeps its strongest support and its most recent sighting
    rather than the weakest and the oldest.
    """
    records = [evidence[item] for item in (edge.get("evidence_ids") or []) if item in evidence]
    if not records:
        return {"evidence_type": None, "observed_at": None}
    best = min(records, key=lambda item: _EVIDENCE_RANK.get(str(item.get("evidence_type")), 99))
    moments = [str(item["observed_at"]) for item in records if item.get("observed_at")]
    return {
        "evidence_type": best.get("evidence_type"),
        "observed_at": max(moments) if moments else None,
    }


def relationship_entries(graph: Any) -> list[dict[str, Any]]:
    """Established edges, plus unresolved candidates as their own status."""
    names = {str(asset["asset_id"]): asset.get("name") for asset in graph.assets()}
    evidence = {str(item["evidence_id"]): item for item in graph.evidence()}
    entries: list[dict[str, Any]] = []
    for edge in graph.relationships():
        subject, predicate, obj = str(edge["subject"]), str(edge["predicate"]), str(edge["object"])
        entries.append(
            {
                "relationship_id": "rel_" + _digest(subject, predicate, obj, edge.get("basis")),
                "subject_id": subject,
                "subject_name": names.get(subject),
                "predicate": predicate,
                "object_id": obj,
                "object_name": names.get(obj),
                "basis": edge.get("basis"),
                "confidence": edge.get("confidence"),
                **_provenance(edge, evidence),
                "status": "ESTABLISHED",
                "reason": None,
                "evidence_ids": [str(item) for item in (edge.get("evidence_ids") or [])],
                "attributes": dict(edge.get("attributes") or {}),
            }
        )
    for edge in graph.unresolved_relationships():
        subject, predicate, obj = str(edge["subject"]), str(edge["predicate"]), str(edge["object"])
        entries.append(
            {
                "relationship_id": "unr_" + _digest(subject, predicate, obj, edge.get("basis")),
                "subject_id": subject,
                "subject_name": names.get(subject),
                "predicate": predicate,
                "object_id": obj,
                "object_name": names.get(obj),
                "basis": edge.get("basis"),
                "confidence": None,
                **_provenance(edge, evidence),
                "status": "UNRESOLVED",
                "reason": edge.get("reason"),
                "evidence_ids": [str(item) for item in (edge.get("evidence_ids") or [])],
                "attributes": dict(edge.get("attributes") or {}),
            }
        )
    return sorted(entries, key=lambda entry: entry["relationship_id"])


def crypto_entries(graph: Any) -> list[dict[str, Any]]:
    """Every cryptographic artefact on its own plane, as its own row."""
    entries: list[dict[str, Any]] = []
    for item in graph.crypto_artifacts():
        entries.append(
            {
                "artifact_id": str(item["artifact_id"]),
                "asset_id": str(item["asset_id"]),
                "asset_name": item.get("asset_name"),
                "asset_type": item.get("asset_type"),
                "algorithm": item.get("algorithm"),
                "protocol": item.get("protocol"),
                "curve": item.get("curve"),
                "key_size": item.get("key_size"),
                "mode": item.get("mode"),
                "role": item.get("role"),
                "layer": item.get("layer"),
                "usage_state": str(item.get("usage_state") or "UNKNOWN"),
                "evidence_type": item.get("evidence_type"),
                "confidence": item.get("confidence"),
                "evidence_ids": [str(ref) for ref in (item.get("evidence_ids") or [])],
                "source": item.get("source"),
            }
        )
    return sorted(entries, key=lambda entry: entry["artifact_id"])


def entries(graph: Any) -> dict[str, list[dict[str, Any]]]:
    """Everything one observation contributes to the catalogue."""
    return {
        "assets": asset_entries(graph),
        "relationships": relationship_entries(graph),
        "crypto": crypto_entries(graph),
    }


def _existing(db: Any, model: Any, key_column: Any, tenant_id: str | None) -> dict[str, Any]:
    stmt = select(model)
    stmt = stmt.where(model.tenant_id == tenant_id if tenant_id else model.tenant_id.is_(None))
    return {str(getattr(row, key_column.key)): row for row in db.execute(stmt).scalars()}


def _touch(row: Any, entry: Mapping[str, Any], *, now: datetime, run_id: str | None) -> None:
    row.lifecycle_state = "ACTIVE"
    row.last_seen_at = now
    row.observation_count = int(row.observation_count or 0) + 1
    if run_id:
        row.last_run_id = run_id
    for field in ("name", "environment", "owner", "location", "source", "identity", "attributes"):
        if field in entry and entry[field] is not None:
            setattr(row, field, entry[field])


def sync(
    db: Any,
    graph: Any,
    *,
    tenant_id: str | None,
    run_id: str | None = None,
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Materialise one observation into the catalogue.

    Idempotent per call and additive across calls: a row already present keeps its
    ``first_seen_at``, advances ``observation_count``, and is refreshed from the newer
    observation. Rows absent from this observation become ``STALE`` — never deleted.
    """
    now = observed_at or datetime.now(timezone.utc)
    if not now.tzinfo:
        now = now.replace(tzinfo=timezone.utc)
    current = entries(graph)

    created = {"assets": 0, "relationships": 0, "crypto": 0}
    updated = {"assets": 0, "relationships": 0, "crypto": 0}
    staled = {"assets": 0, "relationships": 0, "crypto": 0}

    assets = _existing(db, EstateAssetRecord, EstateAssetRecord.asset_id, tenant_id)
    seen_assets: set[str] = set()
    for entry in current["assets"]:
        seen_assets.add(entry["asset_id"])
        row = assets.get(entry["asset_id"])
        if row is None:
            db.add(EstateAssetRecord(
                tenant_id=tenant_id,
                lifecycle_state="ACTIVE",
                first_seen_at=now,
                last_seen_at=now,
                observation_count=1,
                first_run_id=run_id,
                last_run_id=run_id,
                **entry,
            ))
            created["assets"] += 1
            continue
        _touch(row, entry, now=now, run_id=run_id)
        row.asset_type = entry["asset_type"]
        row.evidence_ids = entry["evidence_ids"]
        row.evidence_count = entry["evidence_count"]
        updated["assets"] += 1
    for asset_id, row in assets.items():
        if asset_id not in seen_assets and row.lifecycle_state != "STALE":
            row.lifecycle_state = "STALE"
            staled["assets"] += 1

    relationships = _existing(
        db, EstateRelationshipRecord, EstateRelationshipRecord.relationship_id, tenant_id
    )
    seen_relationships: set[str] = set()
    for entry in current["relationships"]:
        seen_relationships.add(entry["relationship_id"])
        row = relationships.get(entry["relationship_id"])
        if row is None:
            db.add(EstateRelationshipRecord(
                tenant_id=tenant_id,
                lifecycle_state="ACTIVE",
                first_seen_at=now,
                last_seen_at=now,
                observation_count=1,
                **entry,
            ))
            created["relationships"] += 1
            continue
        _touch(row, entry, now=now, run_id=None)
        row.status = entry["status"]
        row.reason = entry["reason"]
        row.confidence = entry["confidence"]
        row.evidence_type = entry.get("evidence_type")
        row.observed_at = entry.get("observed_at")
        row.evidence_ids = entry["evidence_ids"]
        updated["relationships"] += 1
    for relationship_id, row in relationships.items():
        if relationship_id not in seen_relationships and row.lifecycle_state != "STALE":
            row.lifecycle_state = "STALE"
            staled["relationships"] += 1

    crypto = _existing(db, EstateCryptoRecord, EstateCryptoRecord.artifact_id, tenant_id)
    seen_crypto: set[str] = set()
    for entry in current["crypto"]:
        seen_crypto.add(entry["artifact_id"])
        row = crypto.get(entry["artifact_id"])
        if row is None:
            db.add(EstateCryptoRecord(
                tenant_id=tenant_id,
                lifecycle_state="ACTIVE",
                first_seen_at=now,
                last_seen_at=now,
                observation_count=1,
                **entry,
            ))
            created["crypto"] += 1
            continue
        _touch(row, entry, now=now, run_id=None)
        row.usage_state = entry["usage_state"]
        row.evidence_type = entry["evidence_type"]
        row.confidence = entry["confidence"]
        row.evidence_ids = entry["evidence_ids"]
        updated["crypto"] += 1
    for artifact_id, row in crypto.items():
        if artifact_id not in seen_crypto and row.lifecycle_state != "STALE":
            row.lifecycle_state = "STALE"
            staled["crypto"] += 1

    db.commit()

    return {
        "schema": SCHEMA,
        "observed_at": now.isoformat(),
        "run_id": run_id,
        "created": created,
        "updated": updated,
        "staled": staled,
        "counts": {
            "assets": len(current["assets"]),
            "relationships": sum(1 for e in current["relationships"] if e["status"] == "ESTABLISHED"),
            "unresolved": sum(1 for e in current["relationships"] if e["status"] == "UNRESOLVED"),
            "crypto": len(current["crypto"]),
        },
        "meaning": (
            "the catalogue is a derived, append-mostly record: nothing is deleted, an asset absent "
            "from this observation is STALE with its last_seen_at intact, and every row keeps the "
            "evidence ids behind it"
        ),
    }


def _iso(moment: Any) -> str | None:
    if moment is None:
        return None
    value = moment if getattr(moment, "tzinfo", None) else moment.replace(tzinfo=timezone.utc)
    return value.isoformat()


def public_asset(row: EstateAssetRecord) -> dict[str, Any]:
    return {
        "asset_id": row.asset_id,
        "asset_type": row.asset_type,
        "name": row.name,
        "environment": row.environment,
        "owner": row.owner,
        "location": row.location,
        "source": row.source,
        "identity": row.identity or {},
        "attributes": row.attributes or {},
        "evidence_ids": row.evidence_ids or [],
        "evidence_count": row.evidence_count,
        "lifecycle_state": row.lifecycle_state,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "observation_count": row.observation_count,
        "first_run_id": row.first_run_id,
        "last_run_id": row.last_run_id,
        "is_estate_state": True,
    }


def public_relationship(row: EstateRelationshipRecord) -> dict[str, Any]:
    return {
        "relationship_id": row.relationship_id,
        "subject_id": row.subject_id,
        "subject_name": row.subject_name,
        "predicate": row.predicate,
        "object_id": row.object_id,
        "object_name": row.object_name,
        "basis": row.basis,
        "confidence": row.confidence,
        "evidence_type": row.evidence_type,
        "observed_at": row.observed_at,
        "status": row.status,
        "reason": row.reason,
        "evidence_ids": row.evidence_ids or [],
        "lifecycle_state": row.lifecycle_state,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "observation_count": row.observation_count,
        "note": (
            "an UNRESOLVED row is a candidate the graph refused to establish. It is stored so it can "
            "be chased, and it is never counted as a relationship"
            if row.status == "UNRESOLVED"
            else (
                "an established edge: basis and evidence were required before it existed, and "
                "its evidence_type says whether that was configuration or an observation"
            )
        ),
    }


def public_crypto(row: EstateCryptoRecord) -> dict[str, Any]:
    return {
        "artifact_id": row.artifact_id,
        "asset_id": row.asset_id,
        "asset_name": row.asset_name,
        "asset_type": row.asset_type,
        "algorithm": row.algorithm,
        "protocol": row.protocol,
        "curve": row.curve,
        "key_size": row.key_size,
        "mode": row.mode,
        "role": row.role,
        "layer": row.layer,
        "usage_state": row.usage_state,
        "evidence_type": row.evidence_type,
        "confidence": row.confidence,
        "evidence_ids": row.evidence_ids or [],
        "source": row.source,
        "lifecycle_state": row.lifecycle_state,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "observation_count": row.observation_count,
        "note": (
            "SUPPORTED is capability, never use; OBSERVED is a runtime operation. They are separate "
            "rows on purpose"
            if row.usage_state == "SUPPORTED"
            else None
        ),
    }


def list_assets(
    db: Any,
    *,
    tenant_id: str | None,
    asset_type: str | None = None,
    environment: str | None = None,
    owner: str | None = None,
    lifecycle: str | None = None,
    q: str | None = None,
    limit: int = 100,
) -> list[EstateAssetRecord]:
    stmt = select(EstateAssetRecord).order_by(
        EstateAssetRecord.asset_type, EstateAssetRecord.name
    ).limit(max(1, min(limit, LIST_LIMIT)))
    stmt = stmt.where(
        EstateAssetRecord.tenant_id == tenant_id
        if tenant_id
        else EstateAssetRecord.tenant_id.is_(None)
    )
    if asset_type:
        stmt = stmt.where(EstateAssetRecord.asset_type == str(asset_type).upper())
    if environment:
        stmt = stmt.where(EstateAssetRecord.environment == environment)
    if owner:
        stmt = stmt.where(EstateAssetRecord.owner == owner)
    if lifecycle:
        stmt = stmt.where(EstateAssetRecord.lifecycle_state == str(lifecycle).upper())
    rows = list(db.execute(stmt).scalars())
    if q:
        needle = str(q).lower()
        rows = [
            row for row in rows
            if needle in str(row.name).lower()
            or needle in str(row.asset_id).lower()
            or needle in str(row.owner or "").lower()
            or needle in str(row.environment or "").lower()
        ]
    return rows


def get_asset(db: Any, identifier: str, *, tenant_id: str | None) -> EstateAssetRecord | None:
    identifier = str(identifier or "").strip()
    if not identifier:
        return None
    stmt = select(EstateAssetRecord).where(
        (EstateAssetRecord.asset_id == identifier) | (EstateAssetRecord.name == identifier)
    )
    stmt = stmt.where(
        EstateAssetRecord.tenant_id == tenant_id
        if tenant_id
        else EstateAssetRecord.tenant_id.is_(None)
    )
    return db.execute(stmt).scalars().first()


def relationships_for(db: Any, asset_id: str, *, tenant_id: str | None) -> list[EstateRelationshipRecord]:
    stmt = select(EstateRelationshipRecord).where(
        (EstateRelationshipRecord.subject_id == asset_id)
        | (EstateRelationshipRecord.object_id == asset_id)
    ).order_by(EstateRelationshipRecord.predicate)
    stmt = stmt.where(
        EstateRelationshipRecord.tenant_id == tenant_id
        if tenant_id
        else EstateRelationshipRecord.tenant_id.is_(None)
    )
    return list(db.execute(stmt).scalars())


def list_relationships(
    db: Any,
    *,
    tenant_id: str | None,
    subject: str | None = None,
    predicate: str | None = None,
    status: str | None = "ESTABLISHED",
    limit: int = 100,
) -> list[EstateRelationshipRecord]:
    """Edges, filtered. ``status=ALL`` includes candidates; the default excludes them."""
    stmt = select(EstateRelationshipRecord).order_by(
        EstateRelationshipRecord.predicate, EstateRelationshipRecord.subject_name
    ).limit(max(1, min(limit, LIST_LIMIT)))
    stmt = stmt.where(
        EstateRelationshipRecord.tenant_id == tenant_id
        if tenant_id
        else EstateRelationshipRecord.tenant_id.is_(None)
    )
    wanted = str(status or "").upper()
    if wanted and wanted != "ALL":
        stmt = stmt.where(EstateRelationshipRecord.status == wanted)
    if predicate:
        stmt = stmt.where(EstateRelationshipRecord.predicate == str(predicate).lower())
    if subject:
        stmt = stmt.where(
            (EstateRelationshipRecord.subject_id == subject)
            | (EstateRelationshipRecord.subject_name == subject)
        )
    return list(db.execute(stmt).scalars())


def crypto_for(db: Any, asset_id: str, *, tenant_id: str | None) -> list[EstateCryptoRecord]:
    stmt = select(EstateCryptoRecord).where(EstateCryptoRecord.asset_id == asset_id).order_by(
        EstateCryptoRecord.usage_state, EstateCryptoRecord.algorithm
    )
    stmt = stmt.where(
        EstateCryptoRecord.tenant_id == tenant_id
        if tenant_id
        else EstateCryptoRecord.tenant_id.is_(None)
    )
    return list(db.execute(stmt).scalars())


def asset_detail(db: Any, identifier: str, *, tenant_id: str | None) -> dict[str, Any] | None:
    """One asset with everything the catalogue knows about it (spec §25)."""
    row = get_asset(db, identifier, tenant_id=tenant_id)
    if row is None:
        return None
    relationships = relationships_for(db, row.asset_id, tenant_id=tenant_id)
    crypto = crypto_for(db, row.asset_id, tenant_id=tenant_id)
    established = [public_relationship(item) for item in relationships if item.status == "ESTABLISHED"]
    unresolved = [public_relationship(item) for item in relationships if item.status == "UNRESOLVED"]
    return {
        "schema": SCHEMA,
        "asset": public_asset(row),
        "crypto": [public_crypto(item) for item in crypto],
        "crypto_by_usage_state": _by_state(crypto),
        "relationships": established,
        "unresolved_candidates": unresolved,
        "counts": {
            "crypto": len(crypto),
            "relationships": len(established),
            "unresolved": len(unresolved),
            "evidence": int(row.evidence_count or 0),
        },
        "note": (
            "counts are of what the catalogue has recorded across observations, not of the latest "
            "run alone; lifecycle_state and last_seen_at say how current each row is"
        ),
    }


def _by_state(rows: Iterable[Any]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        state = str(getattr(row, "usage_state", "") or "UNKNOWN")
        out[state] = out.get(state, 0) + 1
    return out


def registry(
    db: Any,
    *,
    tenant_id: str | None,
    query: str | None = None,
    asset_type: str | None = None,
    include_stale: bool = True,
) -> dict[str, Any]:
    """Algorithm-centric view: who uses what, on which plane (spec §26).

    This is the answer to "RSA-2048 → 48 certificates, 13 applications, 5 load
    balancers". Each algorithm is reported per ``usage_state`` so a capability never
    inflates a usage count, and every group lists the assets behind it.
    """
    stmt = select(EstateCryptoRecord).order_by(EstateCryptoRecord.algorithm, EstateCryptoRecord.usage_state)
    stmt = stmt.where(
        EstateCryptoRecord.tenant_id == tenant_id
        if tenant_id
        else EstateCryptoRecord.tenant_id.is_(None)
    )
    if not include_stale:
        stmt = stmt.where(EstateCryptoRecord.lifecycle_state == "ACTIVE")
    if asset_type:
        stmt = stmt.where(EstateCryptoRecord.asset_type == str(asset_type).upper())
    rows = list(db.execute(stmt).scalars())

    if query:
        needle = str(query).lower()
        rows = [
            row for row in rows
            if needle in str(row.algorithm or "").lower()
            or needle in str(row.protocol or "").lower()
            or needle in str(row.curve or "").lower()
            or needle in str(row.asset_name or "").lower()
        ]

    algorithms: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = str(row.algorithm or row.protocol or row.curve or "UNSPECIFIED").upper()
        entry = algorithms.setdefault(
            key,
            {
                "algorithm": key,
                "usage_states": {},
                "asset_types": {},
                "assets": [],
                "evidence": 0,
                "stale": 0,
            },
        )
        state = str(row.usage_state or "UNKNOWN")
        entry["usage_states"][state] = entry["usage_states"].get(state, 0) + 1
        kind = str(row.asset_type or "UNKNOWN")
        entry["asset_types"][kind] = entry["asset_types"].get(kind, 0) + 1
        entry["evidence"] += len(row.evidence_ids or [])
        if row.lifecycle_state == "STALE":
            entry["stale"] += 1
        entry["assets"].append(
            {
                "asset_id": row.asset_id,
                "asset_name": row.asset_name,
                "asset_type": row.asset_type,
                "usage_state": row.usage_state,
                "layer": row.layer,
                "lifecycle_state": row.lifecycle_state,
                "evidence_ids": row.evidence_ids or [],
            }
        )

    ordered = sorted(algorithms.values(), key=lambda item: (-len(item["assets"]), item["algorithm"]))
    for entry in ordered:
        entry["asset_count"] = len({item["asset_id"] for item in entry["assets"]})
        entry["assets"] = sorted(
            entry["assets"], key=lambda item: (str(item["asset_type"]), str(item["asset_name"]))
        )[:50]

    return {
        "schema": REGISTRY_SCHEMA,
        "query": query,
        "asset_type": asset_type,
        "algorithms": ordered,
        "algorithm_count": len(ordered),
        "record_count": len(rows),
        "meaning": (
            "each algorithm is reported per usage_state: SUPPORTED is capability, OBSERVED is a "
            "runtime operation, CONFIGURED is a declaration. Adding them into one 'uses' number "
            "would be the CBOM bug this product exists to prevent"
        ),
        "limits": [
            "counts come from the catalogue as recorded across observations; a STALE row is history, "
            "not a current use",
            "a capability row says the asset can do it, never that it did",
        ],
    }


def summary(db: Any, *, tenant_id: str | None) -> dict[str, Any]:
    """Catalogue health: how much of the estate the twin actually remembers."""
    assets = list_assets(db, tenant_id=tenant_id, limit=LIST_LIMIT)
    by_type: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for row in assets:
        by_type[row.asset_type] = by_type.get(row.asset_type, 0) + 1
        by_state[row.lifecycle_state] = by_state.get(row.lifecycle_state, 0) + 1
    return {
        "schema": SCHEMA,
        "assets": len(assets),
        "assets_by_type": by_type,
        "assets_by_lifecycle": by_state,
        "note": (
            "this is the catalogue, not the estate: an empty catalogue means nothing has been "
            "observed yet, not that the bank has no assets"
        ),
    }


__all__ = [
    "LIFECYCLE_STATES",
    "REGISTRY_SCHEMA",
    "SCHEMA",
    "asset_detail",
    "asset_entries",
    "crypto_entries",
    "crypto_for",
    "entries",
    "get_asset",
    "list_assets",
    "list_relationships",
    "public_asset",
    "public_crypto",
    "public_relationship",
    "registry",
    "relationship_entries",
    "relationships_for",
    "summary",
    "sync",
]
