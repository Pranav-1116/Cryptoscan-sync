"""Banking & Regulatory — regulator-ready surfaces over the Technology BOM.

The deliverables bank supervisors now demand (ECB quantum/AI letters, UK FCA
PS21/3, RBI PQC guidance) map to one data problem: a complete cryptographic
inventory, a harvest-now-decrypt-later register, a dated migration roadmap and
vendor/HSM readiness attestations. This router turns the materialized BOM into
exactly those documents — same unified model, no separate bank silo.

Mainframe extracts (RACF RACDCERT LIST text, ICSF key CSV) ingest into the SAME
crypto-asset table the scanners write, so z/OS crypto lands in the unified BOM,
the xBOM correlation and the assurance surfaces automatically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.models import CryptoAsset, HardwareAsset

router = APIRouter(prefix="/banking", tags=["banking-regulatory"])

_MAINFRAME_LANGUAGES = ("zos-racf", "zos-icsf")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _resolve_state(db: Session, version: int | None) -> dict[str, Any]:
    # Same materialization as /technology-bom — one BOM, many consumers.
    from api.routers.techbom import _resolve_state as _techbom_state

    return _techbom_state(db, version)


def _hsm_rows(db: Session) -> list[dict[str, Any]]:
    from sqlalchemy import or_

    rows = db.execute(
        select(HardwareAsset).where(
            or_(HardwareAsset.device_type == "hsm", HardwareAsset.hsm.isnot(None))
        )).scalars().all()
    return [h.to_dict() if hasattr(h, "to_dict") else {
        "asset_id": h.asset_id, "manufacturer": h.manufacturer, "model": h.model,
        "firmware": h.firmware, "hsm": h.hsm,
        "crypto_capabilities": h.crypto_capabilities,
    } for h in rows]


def _mainframe_rows(db: Session) -> list[CryptoAsset]:
    return list(db.execute(
        select(CryptoAsset).where(CryptoAsset.source_language.in_(_MAINFRAME_LANGUAGES))
        .order_by(CryptoAsset.created_at)).scalars().all())


def _mainframe_public(rows: list[CryptoAsset]) -> list[dict[str, Any]]:
    from cbom.banking import quantum_vulnerability

    out = []
    for r in rows:
        vuln = quantum_vulnerability(r.algorithm, r.key_size)
        out.append({
            "algorithm": r.algorithm,
            "key_size": r.key_size,
            "purpose": r.purpose or "",
            "location": r.file_path,
            "source_language": r.source_language,
            "quantum": {"transition": vuln["transition"], "deadline": vuln["deadline"]},
        })
    return out


# --------------------------------------------------------------------------- #
# surfaces
# --------------------------------------------------------------------------- #

@router.get("/overview")
def banking_overview_endpoint(
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Combined regulatory readiness surface (HNDL + roadmap + HSM + mainframe)."""
    from cbom.banking import banking_overview as _overview

    state = _resolve_state(db, version)
    mf = _mainframe_rows(db)
    return {
        "source": "technology_bom",
        "environment": state.get("environment"),
        "snapshot_id": state.get("snapshot_id"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overview": _overview(state, hsms=_hsm_rows(db), mainframe_assets=[
            {"source": (r.source_language or "").replace("zos-", "")} for r in mf]),
    }


@router.get("/hndl")
def banking_hndl(
    version: int | None = Query(None),
    horizon_years: int = Query(5, ge=1, le=100),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Harvest-Now-Decrypt-Later exposure register over the current BOM."""
    from cbom.banking import hndl_register

    state = _resolve_state(db, version)
    reg = hndl_register(state, horizon_years=horizon_years)
    reg["source"] = "technology_bom"
    return reg


@router.get("/roadmap")
def banking_roadmap(
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Migration roadmap anchored on NIST IR 8547 (2030 deprecated / 2035 disallowed)."""
    from cbom.banking import migration_roadmap

    state = _resolve_state(db, version)
    rm = migration_roadmap(state)
    rm["source"] = "technology_bom"
    return rm


@router.get("/hsm")
def banking_hsm_fleet(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """HSM fleet PQC + FIPS readiness from the hardware inventory."""
    from cbom.banking import assess_hsm_fleet

    return {"source": "hardware_inventory", "fleet": assess_hsm_fleet(_hsm_rows(db))}


@router.get("/action-plan")
def banking_action_plan(
    version: int | None = Query(None),
    framework: str = Query("generic", pattern="^(ecb|rbi|fca|generic)$"),
    institution: str = Query("", max_length=200),
    require_baseline: bool = Query(False),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """A supervisor-ready action plan: assessment -> register -> phased plan -> owners.

    Shape follows what the ECB letters demand (assessment, action plan with
    named owners, resources, timelines; a cryptographic inventory in practice),
    and what RBI/FCA PQC guidance expects (HNDL exposure, migration roadmap,
    third-party readiness). Evidence anchors point at the BOM snapshot.
    """
    from cbom.assurance import evaluate_admission
    from cbom.banking import assess_hsm_fleet, hndl_register, migration_roadmap

    state = _resolve_state(db, version)
    hndl = hndl_register(state)
    roadmap = migration_roadmap(state)
    fleet = assess_hsm_fleet(_hsm_rows(db))
    admission = evaluate_admission(state, require_baseline=require_baseline)
    mf_rows = _mainframe_rows(db)

    framework_refs = {
        "ecb": [
            "ECB supervisory letter on cyber resilience (action plans due Oct 31, 2026); "
            "quantum follow-up letter pre-announced by the ECB Chair",
            "ECB crypto-risk expectations: cryptographic inventory, migration roadmap, "
            "HNDL exposure, third-party readiness, crypto-agility metrics",
        ],
        "rbi": [
            "RBI cybersecurity framework for regulated entities; PQC readiness "
            "attestation aligned to NIST IR 8547 transition milestones",
        ],
        "fca": [
            "FCA PS21/3 operational resilience — emerging-risk scenario testing "
            "including quantum compromise of public-key controls",
        ],
        "generic": [
            "NIST IR 8547: public-key algorithms deprecated after 2030, "
            "disallowed after 2035",
        ],
    }

    return {
        "document": "cryptographic-risk-action-plan",
        "framework": framework,
        "institution": institution or None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "references": framework_refs[framework],
        "evidence": {
            "snapshot_id": state.get("snapshot_id"),
            "fingerprint": state.get("fingerprint"),
            "environment": state.get("environment"),
            "state_version": state.get("state_version"),
        },
        "assessment": {
            "total_crypto_instances": state.get("total_components"),
            "admission": {"decision": admission.get("decision"),
                          "blocking": admission.get("blocking_count"),
                          "warnings": admission.get("warn_count")},
            "hndl": {"at_risk": hndl["at_risk"], "total": hndl["total"],
                     "by_exposure": hndl["by_exposure"]},
            "hsm_fleet": {"total": fleet["total"], "pqc_ready": fleet["pqc_ready"],
                          "pqc_gap": fleet["pqc_gap"]},
            "mainframe_inventory": {"total": len(mf_rows),
                                    "by_source": {s: sum(1 for r in mf_rows
                                                         if r.source_language == s)
                                                  for s in _MAINFRAME_LANGUAGES
                                                  if any(r.source_language == s
                                                         for r in mf_rows)}},
        },
        "hndl_register": hndl["entries"],
        "phases": roadmap["phases"],
        "attestation": (
            "Produced from the continuously materialized Technology BOM; "
            "re-generate at any time and verify against the evidence fingerprint."
        ),
    }


# --------------------------------------------------------------------------- #
# mainframe ingest
# --------------------------------------------------------------------------- #

class MainframeIngest(BaseModel):
    kind: str  # "racdcert" | "icsf_csv"
    content: str
    persist: bool = True


@router.post("/mainframe/ingest")
def banking_mainframe_ingest(
    payload: MainframeIngest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Ingest a z/OS security extract into the unified crypto inventory.

    ``kind=racdcert`` parses RACF ``RACDCERT LIST`` text; ``kind=icsf_csv``
    parses an ICSF key-inventory CSV (LABEL,ALGORITHM,KEYBITS,USAGE,STATUS).
    Rows persist as CryptoAssets (source_language=zos-*) so mainframe crypto
    appears in the BOM, xBOM correlation and assurance surfaces.
    """
    from cbom.banking import normalize_icsf_csv, normalize_racdcert

    if payload.kind == "racdcert":
        assets = normalize_racdcert(payload.content)
    elif payload.kind == "icsf_csv":
        assets = normalize_icsf_csv(payload.content)
    else:
        raise HTTPException(status_code=422, detail="kind must be 'racdcert' or 'icsf_csv'")

    inserted, duplicates = 0, 0
    for a in assets:
        existing = db.execute(
            select(CryptoAsset.id).where(
                CryptoAsset.file_path == a["file_path"],
                CryptoAsset.algorithm == a["algorithm"],
                CryptoAsset.key_size == a["key_size"],
            ).limit(1)).scalar_one_or_none()
        if existing is not None:
            duplicates += 1
            continue
        if payload.persist:
            db.add(CryptoAsset(
                algorithm=a["algorithm"],
                purpose=(a.get("purpose") or "signature"),
                key_size=a.get("key_size"),
                file_path=a["file_path"],
                line_number=0,
                source_language=a["source_language"],
                confidence="HIGH",
            ))
            inserted += 1
    if payload.persist and inserted:
        db.commit()

    return {
        "kind": payload.kind,
        "parsed": len(assets),
        "inserted": inserted,
        "duplicates": duplicates,
        "persisted": bool(payload.persist),
        "assets": assets,
    }


@router.get("/mainframe")
def banking_mainframe_inventory(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Mainframe crypto already in the unified inventory (from ingest)."""
    rows = _mainframe_rows(db)
    return {
        "source": "technology_bom",
        "total": len(rows),
        "by_source": {s: sum(1 for r in rows if r.source_language == s)
                      for s in _MAINFRAME_LANGUAGES if any(r.source_language == s for r in rows)},
        "assets": _mainframe_public(rows),
    }
