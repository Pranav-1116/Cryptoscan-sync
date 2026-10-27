"""Algorithm registry API — every algorithm the product knows, with its key.

``GET /algorithms``        browsable catalog (filter by family/status/search)
``GET /algorithms/parse``  parse any raw name (AES-256, RS256, TLS_..., ssh-...)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from shared_models.algorithm_registry import catalog, parse_algorithm

router = APIRouter(prefix="/algorithms", tags=["algorithms"])


@router.get("")
@router.get("/")
def list_algorithms(
    family: str | None = None,
    status: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    """The algorithm catalog: canonical names, key sizes, status, quantum impact."""
    entries = catalog()
    if family:
        entries = [e for e in entries if e["family"].lower() == family.lower()]
    if status:
        entries = [e for e in entries if e["status"].upper() == status.upper()]
    if q:
        needle = q.lower()
        entries = [
            e
            for e in entries
            if needle in e["algorithm"].lower()
            or needle in (e.get("notes") or "").lower()
            or needle in e["family"].lower()
        ]
    counts: dict[str, int] = {}
    for e in catalog():
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    families = sorted({e["family"] for e in catalog()})
    return {
        "total_count": len(entries),
        "counts_by_status": counts,
        "families": families,
        "algorithms": entries,
    }


@router.get("/parse")
def parse(name: str = Query(..., min_length=1, description="Raw algorithm name, e.g. AES-256, RS256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")) -> dict[str, Any]:
    """Parse any raw algorithm string into canonical name + key size + verdict."""
    info = parse_algorithm(name)
    if not info.recognized and not info.components and not info.key_size:
        # still return the (UNKNOWN) verdict — the caller decides; but 404-style
        # signal helps typos discoverable
        pass
    return info.to_dict()


@router.get("/parse-many")
def parse_many(names: str = Query(..., description="Comma-separated raw names")) -> dict[str, Any]:
    results = [parse_algorithm(n.strip()).to_dict() for n in names.split(",") if n.strip()]
    if not results:
        raise HTTPException(status_code=400, detail="no names supplied")
    return {
        "total_count": len(results),
        "recognized": sum(1 for r in results if r["recognized"]),
        "results": results,
    }
