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

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
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
    jurisdiction: str = Query("", max_length=8),
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

    # A jurisdiction pack pins the regulatory references (and implied framework)
    # for cross-border banking groups reporting into a specific supervisor.
    jurisdiction_pack = None
    if jurisdiction:
        from cbom.regulators import jurisdiction_pack as _pack

        jurisdiction_pack = _pack(jurisdiction)
        if jurisdiction_pack is None:
            raise HTTPException(status_code=404, detail=f"unknown jurisdiction: {jurisdiction}")

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
        "framework": jurisdiction_pack["framework"] if jurisdiction_pack else framework,
        "jurisdiction": jurisdiction_pack["code"] if jurisdiction_pack else None,
        "jurisdiction_display": jurisdiction_pack["display"] if jurisdiction_pack else None,
        "milestones": jurisdiction_pack["milestones"] if jurisdiction_pack else [],
        "institution": institution or None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "references": (
            [
                f'{m["label"]}' + (f' — {m["date"]}' if m.get("date") else "")
                for m in (jurisdiction_pack["milestones"] if jurisdiction_pack else [])
            ]
            or framework_refs[framework]
        ),
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
                extra={k: a[k] for k in ("status", "expires", "label", "signature_algorithm",
                                         "scope", "usage", "activated_at")
                       if a.get(k) not in (None, "")},
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


# --------------------------------------------------------------------------- #
# Deep mainframe discovery (multi-source z/OS extracts)
# --------------------------------------------------------------------------- #

@router.post("/mainframe/analyze")
def banking_mainframe_analyze(
    payload: MainframeIngest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Deep z/OS analysis: parse any supported extract and assess WITHOUT persisting.

    ``kind`` extends the ingest set: ``racdcert`` (rich RACF parse),
    ``icsf_csv`` (CKDS/PKDS), ``db2_tls`` (DB2 SSL config), and
    ``cics_tcpservice`` (CICS TLS edge). Returns parsed findings plus the
    aggregated mainframe assessment (cleartext, weak transport, expiring
    certificates, quantum-vulnerable public-key material).
    """
    from cbom.mainframe import INGEST_KINDS, mainframe_assessment

    parser = INGEST_KINDS.get(payload.kind)
    if parser is None:
        raise HTTPException(status_code=422, detail=f"kind must be one of {sorted(INGEST_KINDS)}")
    findings = parser(payload.content)
    return {"kind": payload.kind, "findings": findings, "assessment": mainframe_assessment(findings)}


@router.get("/mainframe/assessment")
def banking_mainframe_assessment(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Assessment over mainframe crypto already persisted in the inventory."""
    from cbom.mainframe import mainframe_assessment

    rows = []
    for r in _mainframe_rows(db):
        rows.append({"source": (r.source_language or "").replace("zos-", ""),
                     "algorithm": r.algorithm, "key_size": r.key_size,
                     "purpose": r.purpose, "file_path": r.file_path,
                     "extra": r.extra or {}})
    return {"source": "technology_bom", "assessment": mainframe_assessment(rows)}


# --------------------------------------------------------------------------- #
# HSM deep assessment (PKCS#11 artifacts)
# --------------------------------------------------------------------------- #

class HsmParseRequest(BaseModel):
    slots_text: str = ""
    objects_text: str = ""
    cex_text: str = ""
    manufacturer: str = ""
    model: str = ""


@router.post("/hsm/parse")
def banking_hsm_parse(
    payload: HsmParseRequest,
    user: str = Depends(get_current_user),
):
    """Assess one HSM from pasted PKCS#11/CEX artifacts (no persistence)."""
    from cbom.hsm_pkcs11 import assess_hsm_deep

    row = {"asset_id": payload.model or "adhoc",
           "manufacturer": payload.manufacturer, "model": payload.model,
           "slots_text": payload.slots_text, "objects_text": payload.objects_text,
           "cex_text": payload.cex_text}
    return {"assessment": assess_hsm_deep([row])}


@router.get("/hsm/deep")
def banking_hsm_deep(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Fleet-deep HSM assessment over the hardware inventory (PKCS#11-aware).

    Reads stored artifacts when present: ``hsm.pkcs11_slots`` /
    ``hsm.pkcs11_objects`` JSON fields on the hardware asset (populated by
    asset-sync or the parse endpoint payloads).
    """
    from cbom.hsm_pkcs11 import assess_hsm_deep

    rows = []
    for h in _hsm_rows(db):
        hsm_info = h.get("hsm") if isinstance(h.get("hsm"), Mapping) else {}
        rows.append({
            **h,
            "slots_text": str(hsm_info.get("pkcs11_slots", "") or ""),
            "objects_text": str(hsm_info.get("pkcs11_objects", "") or ""),
            "cex_text": str(hsm_info.get("cex_adapters", "") or ""),
        })
    return {"source": "hardware_inventory", "fleet": assess_hsm_deep(rows)}


# --------------------------------------------------------------------------- #
# FIPS registry (CMVP certificate numbers)
# --------------------------------------------------------------------------- #

def _fips_registry_path() -> Path:
    from cbom.integrations import default_registry_path

    return default_registry_path(Path(os.environ.get("CRYPTOSCAN_ROOT") or Path.cwd()))


@router.get("/fips")
def banking_fips_lookup(
    module: str = Query(..., min_length=2),
    user: str = Depends(get_current_user),
):
    """CMVP certificate lookup for a crypto module ('validated cert #xxxx')."""
    from cbom.integrations import fips_lookup, load_fips_registry

    return fips_lookup(module, load_fips_registry(_fips_registry_path()))


@router.get("/fips/registry")
def banking_fips_registry(user: str = Depends(get_current_user)):
    """The module→certificate registry backing /banking/fips."""
    from cbom.integrations import load_fips_registry

    entries = sorted(load_fips_registry(_fips_registry_path()).values(),
                     key=lambda e: str(e.get("module")))
    return {"path": str(_fips_registry_path()), "count": len(entries), "entries": entries}


class FipsRegistryEntry(BaseModel):
    module: str
    vendor: str = ""
    standard: str = "FIPS 140"
    cert: str = ""
    note: str = ""


@router.post("/fips/registry")
def banking_fips_registry_add(
    entry: FipsRegistryEntry,
    user: str = Depends(get_current_user),
):
    """Record a CMVP certificate you have verified (never inferred)."""
    from cbom.integrations import load_fips_registry, save_fips_registry

    path = _fips_registry_path()
    save_fips_registry([entry.model_dump()], path)
    return {"ok": True, "count": len(load_fips_registry(path))}


# --------------------------------------------------------------------------- #
# Regulator export + enterprise integrations + compliance crosswalk
# --------------------------------------------------------------------------- #

def _system_owners(db: Session) -> dict[str, str]:
    """application-name → owning team from the systems inventory (owner assignment)."""
    from db.models import System

    pairs = db.execute(select(System.name, System.owner)).all()
    return {str(name).strip().lower(): str(owner or "unassigned")
            for name, owner in pairs if name}


@router.get("/action-plan/export")
def banking_action_plan_export(
    format: str = Query("html", pattern="^(html|csv|json)$"),
    version: int | None = Query(None),
    framework: str = Query("ecb", pattern="^(ecb|rbi|fca|generic)$"),
    institution: str = Query("", max_length=200),
    require_baseline: bool = Query(False),
    jurisdiction: str = Query("", max_length=8),
    lang: str = Query("en", max_length=8),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One-click supervisory artifact: the action plan as HTML (print→PDF),
    CSV (HNDL register) or JSON. Owners are assigned from the systems
    inventory where applications match."""
    from cbom.integrations import ACTION_PLAN_I18N, render_action_plan_csv, render_action_plan_html

    if lang not in ACTION_PLAN_I18N:
        raise HTTPException(status_code=422, detail=f"lang must be one of {sorted(ACTION_PLAN_I18N)}")
    plan = banking_action_plan(version=version, framework=framework,
                               institution=institution, require_baseline=require_baseline,
                               jurisdiction=jurisdiction, user=user, db=db)
    owners = _system_owners(db)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    jcode = jurisdiction or framework
    base = f"action-plan-{jcode}-{stamp}"
    if format == "html":
        return Response(content=render_action_plan_html(plan, owners, lang=lang),
                        media_type="text/html; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{base}.html"'})
    if format == "csv":
        return Response(content=render_action_plan_csv(plan, owners),
                        media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{base}-hndl-register.csv"'})
    return Response(content=json.dumps(plan, indent=2, default=str),
                    media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{base}.json"'})


@router.get("/integrations/servicenow")
def banking_integrations_servicenow(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Crypto assets (incl. mainframe) → ServiceNow CMDB import payloads."""
    from cbom.integrations import to_servicenow_cmdb

    records = [r.to_dict() for r in db.execute(select(CryptoAsset)).scalars().all()]
    return to_servicenow_cmdb(records)


@router.get("/integrations/qualys")
def banking_integrations_qualys(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Weak/quantum-exposed crypto → Qualys-style detection CSV download."""
    from cbom.integrations import to_qualys_csv

    records = []
    for r in db.execute(select(CryptoAsset)).scalars().all():
        records.append({"asset": r.file_path, "algorithm": r.algorithm,
                        "key_size": r.key_size, "purpose": r.purpose,
                        "source": (r.source_language or "").replace("zos-", "") or "scanner"})
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(content=to_qualys_csv(records),
                    media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="crypto-detections-{stamp}.csv"'})


@router.get("/compliance-crosswalk")
def banking_compliance_crosswalk(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """ISO 27001:2022 / SOC 2 control crosswalk over the platform's evidence surfaces."""
    from cbom.integrations import procurement_trust_package, soc2_iso_crosswalk

    state = _resolve_state(db, None)
    xw = soc2_iso_crosswalk()
    xw["trust_package"] = procurement_trust_package({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overview": {"total_components": state.get("total_components"),
                     "environment": state.get("environment"),
                     "snapshot_id": state.get("snapshot_id")},
    })
    return xw


# --------------------------------------------------------------------------- #
# International: jurisdiction packs, SWIFT CSP, key lifecycle
# --------------------------------------------------------------------------- #

@router.get("/jurisdictions")
def banking_jurisdictions(user: str = Depends(get_current_user)):
    """Supervisory jurisdictions the platform ships packs for (group operations)."""
    from cbom.regulators import JURISDICTION_PACKS

    packs = [{"code": p["code"], "display": p["display"], "region": p["region"],
              "regulators": p["regulators"], "languages": p["languages"],
              "milestones": len(p["milestones"]), "artifacts": p["artifacts"]}
             for p in JURISDICTION_PACKS.values()]
    return {"count": len(packs), "jurisdictions": packs}


@router.get("/jurisdiction/{code}")
def banking_jurisdiction(
    code: str,
    version: int | None = Query(None),
    institution: str = Query("", max_length=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One jurisdiction pack + the action plan pinned to its regulator/milestones."""
    from cbom.regulators import jurisdiction_pack as _pack

    pack = _pack(code)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"unknown jurisdiction: {code}")
    plan = banking_action_plan(version=version, framework=pack["framework"],
                               institution=institution, jurisdiction=pack["code"],
                               user=user, db=db)
    return {
        "pack": pack,
        "action_plan": plan,
        "artifacts": pack["artifacts"],
    }


@router.get("/keys")
def banking_key_lifecycle(
    version: int | None = Query(None),
    source: str = Query("", max_length=100,
                        description="comma-separated source filter: icsf, racf, scanner…"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """NIST SP 800-57 key-state register over the unified inventory.

    Covers persisted z/OS keys/certificates (status/expires from the extracts)
    and scanner-found keys with recorded state, so rotation and compromised-key
    registers come from ONE place.
    """
    from cbom.regulators import key_lifecycle

    wanted = {s.strip().lower() for s in (source or "").split(",") if s.strip()}
    rows: list[dict[str, Any]] = []
    for r in db.execute(select(CryptoAsset)).scalars().all():
        extra = r.extra if isinstance(r.extra, dict) else {}
        row_source = (r.source_language or "").replace("zos-", "") or "scanner"
        if wanted and row_source not in wanted:
            continue
        rows.append({
            "label": extra.get("label") or "",
            "file_path": r.file_path,
            "algorithm": r.algorithm,
            "key_size": r.key_size,
            "status": extra.get("status") or "",
            "expires": extra.get("expires") or "",
            "activated_at": extra.get("activated_at") or "",
            "source": row_source,
        })
    reg = key_lifecycle(rows)
    reg["source"] = "technology_bom"
    return reg


@router.get("/swift-csp")
def banking_swift_csp(
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """SWIFT CSP / CSCF evidence mapping for the annual attestation."""
    from cbom.mainframe import mainframe_assessment
    from cbom.regulators import swift_cscf_assessment

    from cbom.hsm_pkcs11 import assess_hsm_deep

    state = _resolve_state(db, version)
    mf_rows = [{"source": (r.source_language or "").replace("zos-", ""),
                "algorithm": r.algorithm, "key_size": r.key_size,
                "file_path": r.file_path,
                **(r.extra if isinstance(r.extra, dict) else {})}
               for r in _mainframe_rows(db)]
    hsm_rows = [{**h,
                 "slots_text": str(((h.get("hsm") or {}) if isinstance(h.get("hsm"), Mapping) else {}).get("pkcs11_slots", "") or ""),
                 "objects_text": str(((h.get("hsm") or {}) if isinstance(h.get("hsm"), Mapping) else {}).get("pkcs11_objects", "") or ""),
                 "cex_text": str(((h.get("hsm") or {}) if isinstance(h.get("hsm"), Mapping) else {}).get("cex_adapters", "") or "")}
                for h in _hsm_rows(db)]
    return {
        "source": "technology_bom",
        "cscf": swift_cscf_assessment(state, hsm_fleet=assess_hsm_deep(hsm_rows),
                                      mainframe=mainframe_assessment(mf_rows)),
    }
