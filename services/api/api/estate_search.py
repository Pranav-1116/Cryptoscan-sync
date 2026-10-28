"""One search over the recorded estate (spec 94 §26).

Bank questions do not arrive pre-sorted into tables. "Where is RSA-2048?" is four
questions at once — which assets, which artefacts, which edges, and which evidence says
so — and an operator who has to know which of five endpoints to try is not searching,
they are navigating.

This module answers the one question across the records that exist, and is deliberate
about two things:

* **search is not discovery.** It searches what has been observed and recorded. A miss
  means "nothing matching has been recorded", never "the bank has no RSA-2048". The
  response says that in its own words, because a search box that returns zero rows reads
  as a negative finding to everyone who did not build it.
* **capability is not use, in search too.** Algorithm hits are grouped by ``usage_state``
  and never summed into one "assets using" number, so a search cannot quietly turn
  "this library supports RSA-2048" into "RSA-2048 is deployed here".

Results are bounded per kind and say when they were truncated. Each hit carries an id a
caller can act on, so a search result is a doorway rather than a dead end.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from sqlalchemy import select

from db.models.estate_catalog import (
    EstateAssetRecord,
    EstateCryptoRecord,
    EstateEvidenceRecord,
    EstateObservationRecord,
    EstateRelationshipRecord,
)

SCHEMA = "cryptoscan.estate-search/1"

#: the record kinds a search can reach, in the order a console shows them
KINDS = ("ASSETS", "CRYPTO", "RELATIONSHIPS", "EVIDENCE", "CHANGES", "FACTS")

#: per-kind ceiling: a search result is a shortlist, never an export
MAX_PER_KIND = 25


def _needle(query: str) -> str:
    text = str(query or "").strip()
    if not text:
        raise ValueError("empty query: a search needs something to look for")
    return text


def _tenant(model: Any, tenant_id: str | None):
    return model.tenant_id == tenant_id if tenant_id else model.tenant_id.is_(None)


def _hit(kind: str, identifier: str, label: str, **extra: Any) -> dict[str, Any]:
    return {"kind": kind, "id": identifier, "label": label, **extra}


def _assets(db: Any, needle: str, *, tenant_id: str | None, limit: int) -> list[dict[str, Any]]:
    like = f"%{needle.lower()}%"
    stmt = select(EstateAssetRecord).where(
        _tenant(EstateAssetRecord, tenant_id),
        (EstateAssetRecord.name.ilike(like))
        | (EstateAssetRecord.asset_id.ilike(like))
        | (EstateAssetRecord.owner.ilike(like))
        | (EstateAssetRecord.environment.ilike(like))
        | (EstateAssetRecord.asset_type.ilike(like)),
    ).order_by(EstateAssetRecord.last_seen_at.desc()).limit(limit)
    return [
        _hit(
            "ASSET",
            row.asset_id,
            f"{row.name} ({row.asset_type})",
            asset_type=row.asset_type,
            environment=row.environment,
            owner=row.owner,
            lifecycle_state=row.lifecycle_state,
            observation_count=row.observation_count,
        )
        for row in db.execute(stmt).scalars()
    ]


def _crypto(db: Any, needle: str, *, tenant_id: str | None, limit: int) -> dict[str, Any]:
    """Algorithm hits, grouped by usage state — never summed into one "in use" number."""
    like = f"%{needle.lower()}%"
    stmt = select(EstateCryptoRecord).where(
        _tenant(EstateCryptoRecord, tenant_id),
        (EstateCryptoRecord.algorithm.ilike(like))
        | (EstateCryptoRecord.protocol.ilike(like))
        | (EstateCryptoRecord.curve.ilike(like))
        | (EstateCryptoRecord.asset_name.ilike(like)),
    ).order_by(EstateCryptoRecord.algorithm).limit(500)
    rows = list(db.execute(stmt).scalars())

    by_state: dict[str, int] = {}
    by_type: dict[str, int] = {}
    algorithms: dict[str, int] = {}
    for row in rows:
        by_state[row.usage_state] = by_state.get(row.usage_state, 0) + 1
        by_type[row.asset_type] = by_type.get(row.asset_type, 0) + 1
        label = str(row.algorithm or row.protocol or row.curve or "UNSPECIFIED").upper()
        algorithms[label] = algorithms.get(label, 0) + 1

    assets: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = assets.setdefault(row.asset_id, {
            "asset_id": row.asset_id,
            "asset_name": row.asset_name,
            "asset_type": row.asset_type,
            "usage_states": {},
            "lifecycle_state": row.lifecycle_state,
        })
        entry["usage_states"][row.usage_state] = entry["usage_states"].get(row.usage_state, 0) + 1

    hits = [
        _hit(
            "CRYPTO",
            entry["asset_id"],
            f"{entry['asset_name']} ({entry['asset_type']})",
            usage_states=entry["usage_states"],
            lifecycle_state=entry["lifecycle_state"],
        )
        for entry in sorted(assets.values(), key=lambda item: str(item["asset_name"]).lower())[:limit]
    ]
    return {
        "hits": hits,
        "count": len(assets),
        "usage_states": dict(sorted(by_state.items())),
        "asset_types": dict(sorted(by_type.items())),
        "algorithms": dict(sorted(algorithms.items(), key=lambda item: (-item[1], item[0]))[:10]),
        "note": (
            "grouped per usage_state: SUPPORTED is capability, OBSERVED is a runtime operation. "
            "They are not added together, because capability is not use"
        ),
    }


def _relationships(db: Any, needle: str, *, tenant_id: str | None, limit: int) -> list[dict[str, Any]]:
    like = f"%{needle.lower()}%"
    stmt = select(EstateRelationshipRecord).where(
        _tenant(EstateRelationshipRecord, tenant_id),
        (EstateRelationshipRecord.predicate.ilike(like))
        | (EstateRelationshipRecord.subject_name.ilike(like))
        | (EstateRelationshipRecord.object_name.ilike(like))
        | (EstateRelationshipRecord.subject_id.ilike(like))
        | (EstateRelationshipRecord.object_id.ilike(like)),
    ).order_by(EstateRelationshipRecord.last_seen_at.desc()).limit(limit)
    return [
        _hit(
            "RELATIONSHIP",
            row.relationship_id,
            f"{row.subject_name or row.subject_id} —{row.predicate}→ {row.object_name or row.object_id}",
            status=row.status,
            basis=row.basis,
            confidence=row.confidence,
            evidence_ids=list(row.evidence_ids or []),
            reason=row.reason,
        )
        for row in db.execute(stmt).scalars()
    ]


#: how many evidence records a facts-JSON scan may look at. The scalar columns are
#: indexed and filtered in SQL; the recorded facts are not, so the scan is bounded and
#: the response says the answer is a shortlist rather than a census.
EVIDENCE_FACT_SCAN = 1000


def _evidence(db: Any, needle: str, *, tenant_id: str | None, limit: int) -> list[dict[str, Any]]:
    like = f"%{needle.lower()}%"
    stmt = select(EstateEvidenceRecord).where(
        _tenant(EstateEvidenceRecord, tenant_id),
        (EstateEvidenceRecord.collector.ilike(like))
        | (EstateEvidenceRecord.source.ilike(like))
        | (EstateEvidenceRecord.evidence_type.ilike(like))
        | (EstateEvidenceRecord.target_id.ilike(like)),
    ).order_by(EstateEvidenceRecord.last_seen_at.desc()).limit(limit)
    rows = list(db.execute(stmt).scalars())

    # ...and the recorded facts themselves: an auditor searching "RSA-2048" wants the
    # record whose facts mention it, not only records whose collector happens to be named
    # after it. Bounded, most recent first, deduplicated against the scalar matches.
    if len(rows) < limit:
        seen = {row.evidence_id for row in rows}
        recent = select(EstateEvidenceRecord).where(
            _tenant(EstateEvidenceRecord, tenant_id)
        ).order_by(EstateEvidenceRecord.last_seen_at.desc()).limit(EVIDENCE_FACT_SCAN)
        haystack_needle = needle.lower()
        for row in db.execute(recent).scalars():
            if len(rows) >= limit:
                break
            if row.evidence_id in seen:
                continue
            facts = row.facts or {}
            haystack = " ".join(
                f"{key} {' '.join(map(str, value)) if isinstance(value, list) else value}"
                for key, value in facts.items()
            ).lower()
            if haystack_needle in haystack:
                rows.append(row)
                seen.add(row.evidence_id)

    return [
        _hit(
            "EVIDENCE",
            row.evidence_id,
            f"{row.evidence_type} via {row.collector or row.source}",
            target=row.target_id,
            confidence=row.confidence,
            layer=row.layer,
            observed_at=row.observed_at,
            lifecycle_state=row.lifecycle_state,
        )
        for row in rows
    ]


def _facts(db: Any, needle: str, *, tenant_id: str | None, limit: int) -> list[dict[str, Any]]:
    """Recorded fact values — this is how "who is on me-central-1" is answered."""
    like = f"%{needle.lower()}%"
    stmt = select(EstateObservationRecord).where(
        _tenant(EstateObservationRecord, tenant_id),
        EstateObservationRecord.value.ilike(like),
    ).order_by(EstateObservationRecord.last_seen_at.desc()).limit(limit)
    return [
        _hit(
            "FACT",
            row.observation_id,
            f"{row.fact_type} = {row.value}",
            asset_id=row.asset_id,
            state=row.lifecycle_state,
            evidence_id=row.evidence_id,
            observation_count=row.observation_count,
        )
        for row in db.execute(stmt).scalars()
    ]


def _changes(db: Any, needle: str, *, tenant_id: str | None, limit: int) -> list[dict[str, Any]]:
    from db.models.estate_change_event import EstateChangeEvent

    like = f"%{needle.lower()}%"
    stmt = select(EstateChangeEvent).where(
        _tenant(EstateChangeEvent, tenant_id),
        (EstateChangeEvent.headline.ilike(like)) | (EstateChangeEvent.event_id.ilike(like)),
    ).order_by(EstateChangeEvent.first_detected_at.desc()).limit(limit)
    hits = [
        _hit(
            "CHANGE",
            row.event_id,
            row.headline,
            severity=row.severity,
            verdict=row.verdict,
            first_detected_at=row.first_detected_at.isoformat() if row.first_detected_at else None,
            acknowledged=bool(row.acknowledged_at),
        )
        for row in db.execute(stmt).scalars()
    ]
    if hits:
        return hits

    # a claim inside an event is searchable too, or "RSA-2048" would miss the change that
    # demoted it; bounded scan because the claims are JSON rather than columns
    recent = select(EstateChangeEvent).where(
        _tenant(EstateChangeEvent, tenant_id)
    ).order_by(EstateChangeEvent.first_detected_at.desc()).limit(200)
    for row in db.execute(recent).scalars():
        for claim in row.changes or []:
            haystack = " ".join(str(claim.get(key) or "") for key in ("subject", "detail", "kind")).lower()
            if needle.lower() in haystack:
                hits.append(_hit(
                    "CHANGE",
                    row.event_id,
                    f"{claim.get('kind')}: {claim.get('subject')}",
                    severity=row.severity,
                    verdict=row.verdict,
                    detail=claim.get("detail"),
                    first_detected_at=row.first_detected_at.isoformat() if row.first_detected_at else None,
                    acknowledged=bool(row.acknowledged_at),
                ))
                break
        if len(hits) >= limit:
            break
    return hits


def search(
    db: Any,
    query: str,
    *,
    tenant_id: str | None,
    kinds: Iterable[str] | None = None,
    limit: int = MAX_PER_KIND,
) -> dict[str, Any]:
    """Search every recorded kind for one string; results are grouped and bounded."""
    needle = _needle(query)
    wanted = [str(kind).upper() for kind in (kinds or KINDS) if str(kind or "").strip()]
    unknown = sorted(set(wanted) - set(KINDS))
    if unknown:
        raise ValueError(f"unknown search kind(s): {', '.join(unknown)}; expected {', '.join(KINDS)}")
    bound = max(1, min(int(limit or MAX_PER_KIND), MAX_PER_KIND))

    groups: dict[str, Any] = {}
    total = 0

    if "ASSETS" in wanted:
        rows = _assets(db, needle, tenant_id=tenant_id, limit=bound)
        groups["ASSETS"] = {"count": len(rows), "hits": rows}
        total += len(rows)
    if "CRYPTO" in wanted:
        group = _crypto(db, needle, tenant_id=tenant_id, limit=bound)
        groups["CRYPTO"] = group
        total += int(group["count"])
    if "RELATIONSHIPS" in wanted:
        rows = _relationships(db, needle, tenant_id=tenant_id, limit=bound)
        groups["RELATIONSHIPS"] = {"count": len(rows), "hits": rows}
        total += len(rows)
    if "EVIDENCE" in wanted:
        rows = _evidence(db, needle, tenant_id=tenant_id, limit=bound)
        groups["EVIDENCE"] = {"count": len(rows), "hits": rows}
        total += len(rows)
    if "FACTS" in wanted:
        rows = _facts(db, needle, tenant_id=tenant_id, limit=bound)
        groups["FACTS"] = {"count": len(rows), "hits": rows}
        total += len(rows)
    if "CHANGES" in wanted:
        rows = _changes(db, needle, tenant_id=tenant_id, limit=bound)
        groups["CHANGES"] = {"count": len(rows), "hits": rows}
        total += len(rows)

    for name, group in groups.items():
        group["truncated"] = int(group["count"]) >= bound
        group["limit"] = bound
        del name

    return {
        "schema": SCHEMA,
        "query": query,
        "kinds": wanted,
        "matched": total,
        "groups": groups,
        "by_kind": {name: int(group["count"]) for name, group in groups.items()},
        "meaning": (
            "one search across the recorded estate: assets, artefacts, edges, evidence, facts and "
            "detected changes. Results are a shortlist, grouped by kind, and never merged into one "
            "confidence-flattening list"
        ),
        "limits": [
            "search reads the durable catalogue. It searches what has been observed and recorded, so "
            "an empty result means nothing matching has been recorded — not that the bank has none",
            "crypto hits are grouped per usage_state; capability is never counted as use",
            "matching is substring, case-insensitive, and deliberately not fuzzy: a near-miss "
            "presented as a hit is how a search becomes a rumour",
            f"each kind returns at most {bound} hits and says when it was truncated; refine the query "
            "rather than exporting the estate",
            "unresolved relationship candidates are included and labelled with their status, because "
            "they are what a bank most wants to chase",
        ],
    }


def public_group_summary(result: Mapping[str, Any]) -> str:
    """One-line rendering of a search result, for a CLI or a log line."""
    parts = [f"{count} {name.lower()}" for name, count in (result.get("by_kind") or {}).items() if count]
    return ", ".join(parts) or "nothing recorded matches"


__all__ = ["KINDS", "MAX_PER_KIND", "SCHEMA", "public_group_summary", "search"]
