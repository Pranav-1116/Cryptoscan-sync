"""Algorithms router — the canonical algorithm catalog and name parser.

Data source is ``shared_models.algorithm_registry`` — the single source of
truth that normalization, policy and CBOM already use for parsing and
classifying cryptographic names. This router exposes that catalog over
HTTP plus a deterministic parser. No AI, no demo data: every value is
derived from the registry.

Endpoints
---------
GET /api/v1/algorithms           catalog (filters: status, family, q)
GET /api/v1/algorithms/parse     parse one name (?name=AES-256)
GET /api/v1/algorithms/parse/many  parse a comma list (?names=AES,DES)
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from api.dependencies import get_current_user
from shared_models.algorithm_registry import catalog, parse_algorithm

router = APIRouter(prefix="/algorithms", tags=["algorithms"])


def list_algorithms(
    status: str | None = None,
    family: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    """Filter the canonical catalog.

    ``status`` (ALLOWED/DEPRECATED/RESTRICTED/DISALLOWED, case-insensitive),
    ``family`` (block-cipher, hash, aead, pke, …, case-insensitive) and
    ``q`` (substring of the canonical name) are AND-combined. The
    unfiltered ``counts_by_status`` / ``families`` are always returned so
    the UI can show filter chips without extra round-trips.
    """
    entries = catalog()
    counts: dict[str, int] = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    families = sorted({e["family"] for e in entries})

    if status:
        s = status.strip().upper()
        entries = [e for e in entries if e["status"] == s]
    if family:
        f = family.strip().lower()
        entries = [e for e in entries if e["family"] == f]
    if q:
        qq = q.strip().lower()
        entries = [e for e in entries if qq in str(e["algorithm"]).lower()]

    return {
        "algorithms": entries,
        "total_count": len(entries),
        "counts_by_status": counts,
        "families": families,
        "source": "shared_models.algorithm_registry",
        "deterministic": True,
    }


def parse(name: str) -> dict[str, Any]:
    """Parse one algorithm name into its canonical AlgorithmInfo dict.

    Unknown names degrade to ``status="UNKNOWN", recognized=False`` —
    never to silence.
    """
    return parse_algorithm(name).to_dict()


def parse_many(names: str) -> dict[str, Any]:
    """Parse a comma-separated list of names; count the recognized ones."""
    raw_items = [n.strip() for n in names.split(",") if n.strip()]
    results = [parse_algorithm(n).to_dict() for n in raw_items]
    return {
        "results": results,
        "total_count": len(results),
        "recognized": sum(1 for r in results if r["recognized"]),
        "deterministic": True,
    }


@router.get("")
def list_catalog(
    status: str | None = Query(None, description="ALLOWED/DEPRECATED/RESTRICTED/DISALLOWED"),
    family: str | None = Query(None, description="block-cipher, hash, aead, pke, kem-pqc, …"),
    q: str | None = Query(None, description="substring of the canonical algorithm name"),
    user: str = Depends(get_current_user),
):
    return list_algorithms(status=status, family=family, q=q)


@router.get("/parse")
def parse_endpoint(
    name: str = Query(..., min_length=1, description="algorithm name, e.g. AES-256 or a TLS suite"),
    user: str = Depends(get_current_user),
):
    return parse(name)


@router.get("/parse/many")
def parse_many_endpoint(
    names: str = Query(..., min_length=1, description="comma-separated names"),
    user: str = Depends(get_current_user),
):
    return parse_many(names)
