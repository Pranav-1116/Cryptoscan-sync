"""The vendor dependency graph over the live estate, as an API.

Guide 178 proved the graph against a recorded payload; this route is the same graph built from
the rows the platform already holds — the vendors, devices, packages, declarations and systems
that ``_gather_inventory`` assembles — so a bank can ask *which of my business systems depend on
this vendor, and how well do I know it* without exporting a spreadsheet first.

Two deliberate limits, stated in the responses rather than implied:

* the mapper reads a named set of sections and lists the ones it does not
  (``not_mapped``), so a thin estate is never confused with a thin mapper;
* runtime usage is **not** mapped: the stored crypto findings are static analysis, so
  ``declared_vs_observed`` answers ``NOT_OBSERVED`` instead of inheriting a runtime claim from a
  file path.

Every answer keeps the module's vocabulary: a refusal is ``ok: false`` with the code the graph
raised, and an unknown question is a 404 rather than an empty list.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from cbom import vbom_estate as ve

router = APIRouter(prefix="/vbom", tags=["vbom"])


def _estate(db: Session, limit: int) -> dict[str, Any]:
    """The gathered inventory → payload → graph, once per request."""
    from api.routers.techbom import _gather_inventory  # noqa: PLC0415 — shared assembler

    inventory = _gather_inventory(db, limit=limit)
    return ve.assess(inventory)


@router.get("/dependency")
def vendor_dependency(
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """Levels, applicability states, refusals and what the mapper could not place."""
    assessed = _estate(db, limit)
    summary = ve.summary(assessed["document"], as_of=assessed["as_of"])
    return {
        "schema": assessed["schema"],
        "as_of": assessed["as_of"],
        "summary": summary,
        "mapped": assessed["mapped"],
        "unmapped": assessed["unmapped"][:50],
        "unmapped_total": len(assessed["unmapped"]),
        "not_mapped": assessed["not_mapped"],
        "statement": assessed["statement"],
        "rule": assessed["rule"],
        "not_proven": assessed["not_proven"],
    }


@router.get("/dependency/questions")
def vendor_dependency_questions(
    user: str = Depends(get_current_user),
) -> dict[str, Any]:
    """The questions this graph answers, and which of them need a subject named."""
    return ve.catalogue()


@router.get("/dependency/vendors/{vendor}")
def vendor_detail(
    vendor: str = Path(..., min_length=1, max_length=200),
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """One vendor: its products, the assets it supplies, and the systems behind them."""
    assessed = _estate(db, limit)
    asked = {name: ve.answer(assessed["document"], name, vendor=vendor)
             for name in ("vendor_products", "vendor_assets", "vendor_systems",
                          "vendor_applications", "risk_propagation", "pqc_posture")}
    if all(not row["ok"] and row["code"] == "UNKNOWN_NODE" for row in asked.values()
           if row["question"] in ("vendor_products", "vendor_assets")):
        raise HTTPException(status_code=404,
                           detail={"code": "UNKNOWN_VENDOR",
                                   "vendor": vendor,
                                   "reason": "no vendor row in this estate matches that name",
                                   "known": sorted(row["name"] for row in
                                                   assessed["document"]["assets"]
                                                   if row["kind"] == "VENDOR")[:20]})
    return {
        "schema": assessed["schema"],
        "vendor": vendor,
        "as_of": assessed["as_of"],
        "answers": asked,
        "refusals": [row for row in assessed["document"].get("refusals") or []
                     if vendor.lower() in str(row.get("subject") or "").lower()][:20],
        "statement": (asked["vendor_products"].get("statement")
                      or asked["vendor_products"].get("reason")),
        "rule": ("a vendor answer is the graph's, not a lookup: the assets, the applications "
                 "and the systems come from paths, and a path that does not exist says so"),
    }


@router.get("/dependency/assets/{asset}")
def asset_detail(
    asset: str = Path(..., min_length=1, max_length=200),
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """One device: vendor → product → model → firmware → asset, and what it fails to answer."""
    assessed = _estate(db, limit)
    asked = {name: ve.answer(assessed["document"], name, asset=asset)
             for name in ("hardware_chain", "hardware_identity", "network_identity")}
    if not asked["hardware_chain"]["ok"] and asked["hardware_chain"]["code"] == "UNKNOWN_NODE":
        raise HTTPException(status_code=404,
                           detail={"code": "UNKNOWN_ASSET", "asset": asset,
                                   "reason": "no asset in this estate matches that name"})
    return {
        "schema": assessed["schema"],
        "asset": asset,
        "as_of": assessed["as_of"],
        "answers": asked,
        "statement": (asked["hardware_chain"].get("statement")
                      or asked["hardware_chain"].get("reason")),
        "rule": ("an asset answer names the vendor, the product and the firmware it runs — or "
                 "the level at which the estate stops answering"),
    }


@router.get("/dependency/export")
def vendor_dependency_export(
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> dict[str, Any]:
    """The graph as a CycloneDX 1.6 document: components, dependencies and their basis."""
    assessed = _estate(db, limit)
    exported = ve.to_cyclonedx(assessed["document"], as_of=assessed["as_of"])
    return {
        "schema": assessed["schema"],
        "as_of": assessed["as_of"],
        "statement": exported["statement"],
        "components": exported["components"],
        "dependencies": exported["dependencies"],
        "document": exported["document"],
        "not_proven": exported["not_proven"],
    }
