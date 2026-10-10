"""CycloneDX 1.5 CBOM catalog, export, ingest, and comparison."""

from __future__ import annotations

import logging
import os

from db.tenancy import filtered_get

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_job_repository
from api.schemas.cbom_schemas import (
    CbomRef,
    CustomCbomRequest,
    DiffCbomRequest,
    IngestCbomRequest,
)
from cbom.generator import CbomGenerator
from cbom.builders.dependency_builder import build_estate_dependencies
from cbom.inventory import (
    bom_system_name,
    records_from_bom,
    search_records,
    semantic_diff,
    summarize_records,
    validate_document,
)
from db.models.scan import Scan
from db.repositories.asset_repository import AssetRepository
from db.repositories.evidence_repository import EvidenceRepository
from db.repositories.scan_repository import ScanRepository
from db.repositories.system_repository import SystemRepository
from db.repositories.vulnerability_repository import VulnerabilityRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cbom", tags=["cbom"])


def _server_keyring() -> dict[str, str]:
    """Verification keyring: dedicated CBOM keys when configured, else the
    API's own SECRET_KEY as primary. Secrets never travel in request bodies."""
    import os

    from api.config.settings import get_settings

    from cbom.config.settings import parse_retired_secrets

    primary = os.environ.get("CRYPTOSCAN_CBOM_SECRET") or getattr(
        get_settings(), "SECRET_KEY", ""
    )
    ring = parse_retired_secrets(os.environ.get("CRYPTOSCAN_CBOM_RETIRED_SECRETS", ""))
    kid = os.environ.get("CRYPTOSCAN_CBOM_KEY_ID")
    if kid and primary:
        ring.setdefault(kid, primary)
    else:
        ring.setdefault("primary", primary)
    return ring


def _render(bom: dict, fmt: str, signed: bool | str):
    generator = CbomGenerator()
    # "jsf" selects the CycloneDX-spec standard enveloped signature
    # (top-level ``signature`` field, report 08 P2#6); True keeps the
    # legacy JWS-in-metadata-property form for backward compatibility.
    standard = isinstance(signed, str) and signed.lower() == "jsf"
    if signed:
        from api.config.settings import get_settings

        # CBOM signing key: dedicated secret when configured, else the API's
        # own SECRET_KEY (production gate already rejects weak values).
        # Never a hardcoded fallback.
        import os

        secret = os.environ.get("CRYPTOSCAN_CBOM_SECRET") or getattr(
            get_settings(), "SECRET_KEY", ""
        )
        key_id = os.environ.get("CRYPTOSCAN_CBOM_KEY_ID") or None
        if not secret:
            raise HTTPException(
                status_code=503,
                detail="CBOM signing requested but no signing key is configured "
                "(set CRYPTOSCAN_CBOM_SECRET)",
            )
        # Asymmetric JWS (spec §23–24: real JWS, not HMAC): configure
        # CRYPTOSCAN_CBOM_SIGN_ALG=rs256|es256 plus a PEM private key path
        # in CRYPTOSCAN_CBOM_PRIVATE_KEY (or the PEM literal itself). Falls
        # back to the legacy HS256 path when no private key is configured.
        sign_alg = (os.environ.get("CRYPTOSCAN_CBOM_SIGN_ALG") or "hmac").lower()
        private_key_path = os.environ.get("CRYPTOSCAN_CBOM_PRIVATE_KEY", "")
        if sign_alg in {"rs256", "es256"} and private_key_path:
            from pathlib import Path


            pem = (
                private_key_path
                if "-----BEGIN" in private_key_path
                else Path(private_key_path).read_text(encoding="utf-8")
            )
            alg = "RS256" if sign_alg == "rs256" else "ES256"
            if standard:
                if fmt == "xml":
                    raise HTTPException(
                        status_code=400,
                        detail="JSF enveloped signatures apply to the JSON "
                        "serialization; use fmt=json with signed=jsf",
                    )
                bom = generator.sign_standard(bom, pem, alg=alg, key_id=key_id or sign_alg.upper())
            else:
                bom = generator.sign_jws(bom, pem, alg=alg, key_id=key_id or sign_alg.upper())
        else:
            if standard:
                if fmt == "xml":
                    raise HTTPException(
                        status_code=400,
                        detail="JSF enveloped signatures apply to the JSON "
                        "serialization; use fmt=json with signed=jsf",
                    )
                bom = generator.sign_standard(bom, secret, alg="HS256", key_id=key_id)
            else:
                bom = generator.sign(bom, secret, key_id=key_id)
    if fmt == "xml":
        return Response(content=generator.to_xml(bom), media_type="application/xml")
    return JSONResponse(bom)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _portfolio_max_assets() -> int:
    """Bounded estate CBOMs (audit 14 §3): no unbounded query, no silent truncation."""
    try:
        return max(1, int(os.environ.get("PORTFOLIO_MAX_ASSETS", "50000")))
    except ValueError:
        return 50_000


def _located_assets(db: Session) -> tuple[list[dict[str, Any]], int]:
    """All crypto assets with their system location, in a bounded set-based query.

    One JOIN (crypto_assets ⟕ system_assets ⟕ systems) replaces the old
    per-system ``assets_for`` loop (N+1 queries) and the silent 5000-row
    ``list_assets`` page cap. An asset linked to several systems appears
    once per system (same semantics as before); unlinked assets land in the
    ``unassigned`` bucket. The result is capped at ``PORTFOLIO_MAX_ASSETS``
    (default 50k) — the caller reports the truncation explicitly instead of
    the old behavior where the estate CBOM quietly stopped at 5000 assets.
    """
    from db.models.crypto_asset import CryptoAsset
    from db.models.system import System
    from db.models.system_asset import SystemAsset
    from sqlalchemy import select

    rows = db.execute(
        select(CryptoAsset, System)
        .outerjoin(SystemAsset, SystemAsset.asset_id == CryptoAsset.id)
        .outerjoin(System, System.id == SystemAsset.system_id)
    ).all()
    located: list[dict[str, Any]] = []
    for asset, system in rows:
        data = asset.to_dict()
        data["system_id"] = system.id if system is not None else None
        data["system_name"] = system.name if system is not None else "unassigned"
        located.append(data)
    total = len(located)
    limit = _portfolio_max_assets()
    if total > limit:
        logger.warning(
            "portfolio_assets_truncated",
            extra={"total": total, "limit": limit},
        )
        return located[:limit], total
    return located, total


def _records_for_system(db: Session, system_id: str) -> tuple[Any, list[Any]]:
    repo = SystemRepository(db)
    system = repo.get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    return system, repo.assets_for(system_id)


def _records_for_scan(db: Session, scan_id: str) -> tuple[Scan, list[Any]]:
    scan = filtered_get(db, Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    # CBOM generation consumes evidence: retracted (soft-deleted) findings
    # must not appear as components in the inventory.
    return scan, EvidenceRepository(db).get_all_for_scan(scan_id, include_deleted=False)


def _resolve_ref(db: Session, ref) -> tuple[str, str | None, list[Any]]:
    if ref.bom is not None:
        check = validate_document(ref.bom)
        if not check["ok"]:
            raise HTTPException(status_code=422, detail="; ".join(check["errors"]))
        return bom_system_name(ref.bom), None, records_from_bom(ref.bom)
    if ref.system_id:
        system, records = _records_for_system(db, ref.system_id)
        return system.name, system.id, records
    if ref.scan_id:
        scan, records = _records_for_scan(db, ref.scan_id)
        return scan.target_location, scan.id, records
    raise HTTPException(status_code=422, detail="Provide system_id, scan_id, or bom")


@router.get("")
@router.get("/")
def cbom_catalog(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    coverage: str | None = None,
    q: str | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    sys_repo = SystemRepository(db)
    systems, system_total = sys_repo.list_systems(page=page, page_size=page_size, coverage=coverage, q=q)
    catalog = [sys_repo.catalog_row(system) for system in systems]
    coverage_totals = sys_repo.coverage_summary()
    algorithms = AssetRepository(db).algorithm_counts()
    scans, scan_total = ScanRepository(db).list_scans(page=1, page_size=20)
    scan_sources = []
    for scan in scans:
        stats = scan.statistics if isinstance(scan.statistics, dict) else {}
        scan_sources.append(
            {
                "source_type": "scan",
                "source_id": scan.id,
                "name": scan.target_location,
                "status": scan.status,
                "components": stats.get("total_findings"),
                "scanned_at": _iso(getattr(scan, "scan_start", None) or getattr(scan, "created_at", None)),
                "spec": "CycloneDX 1.5",
            }
        )
    return {
        "spec": "CycloneDX 1.5",
        "systems": catalog,
        "scans": scan_sources,
        "page": page,
        "page_size": page_size,
        "coverage": coverage_totals,
        "totals": {
            "systems": system_total,
            "scans": scan_total,
            "components": sum(int(item.get("components") or 0) for item in catalog),
            "unknown_crypto": coverage_totals.get("unknown_crypto"),
            "with_cbom": coverage_totals.get("with_cbom"),
            "coverage_pct": coverage_totals.get("coverage_pct"),
            "algorithms": algorithms,
        },
    }


@router.get("/coverage")
def cbom_coverage(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    return SystemRepository(db).coverage_summary()


class ScanUncoveredRequest(BaseModel):
    limit: int = 25


@router.post("/scan-uncovered")
def cbom_scan_uncovered(
    background_tasks: BackgroundTasks,
    body: ScanUncoveredRequest | None = None,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
    jobs=Depends(get_job_repository),
):
    from api.routers.trigger import enqueue_scan_job

    from cloud_scanner.estate import CAMPAIGN_LOOKAHEAD, plan_campaign

    limit = min(max(int((body.limit if body else 25) or 25), 1), 100)
    lookahead = min(max(limit * 40, 200), CAMPAIGN_LOOKAHEAD)
    planned = plan_campaign(SystemRepository(db).list_uncovered(limit=lookahead), limit=limit)
    queued = []
    skipped = []
    for item in planned:
        target = (item.get("target") or "").strip()
        if not target:
            skipped.append({"id": item.get("system_id"), "name": item.get("name"), "reason": "no_target"})
            continue
        result = enqueue_scan_job(
            jobs,
            background_tasks,
            repo_url=target,
            branch=item.get("branch") or "main",
            triggered_by=user,
            job_type=item.get("job_type") or "COVERAGE",
            system_id=item.get("system_id"),
        )
        queued.append({**item, "job_id": result.job_id})
    remaining = max(0, int(SystemRepository(db).coverage_summary().get("scannable") or 0) - len(queued))
    git_n = sum(1 for item in queued if item.get("job_type") != "CLOUD")
    cloud_n = sum(1 for item in queued if item.get("job_type") == "CLOUD")
    return {
        "queued": len(queued),
        "git_jobs": git_n,
        "cloud_jobs": cloud_n,
        "skipped": skipped,
        "remaining": remaining,
        "jobs": queued,
        "message": (
            f"Queued {git_n} git scans and {cloud_n} cloud account inventories. "
            "Cryptography stays unknown on systems that have not been scanned."
        ),
    }


@router.get("/portfolio")
def cbom_portfolio(
    fmt: str = Query("json"),
    signed: bool | str = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    records, total_assets = _located_assets(db)
    limit = _portfolio_max_assets()
    truncated = total_assets > limit
    system_components, dependencies = _portfolio_dependencies(db, records)
    metadata_properties = [
        {"name": "cryptoscan:scope", "value": "estate"},
        {"name": "cryptoscan:systems", "value": str(len({row.get("system_id") for row in records if row.get("system_id")}))},
        {"name": "cryptoscan:assets", "value": str(len(records))},
    ]
    if truncated:
        # explicit, machine-readable truncation — never a silent 5000-row stop
        metadata_properties += [
            {"name": "cryptoscan:truncated", "value": "true"},
            {"name": "cryptoscan:asset_limit", "value": str(limit)},
            {"name": "cryptoscan:assets_total", "value": str(total_assets)},
        ]
    bom = CbomGenerator().from_records(
        records,
        name="cryptoscan-portfolio",
        version="aggregate",
        dependencies=dependencies or None,
        metadata_properties=metadata_properties,
    )
    if system_components:
        bom["metadata"]["component"]["bom-ref"] = PORTFOLIO_ROOT_REF
        bom["components"] = list(bom["components"]) + system_components
    return _render(bom, fmt, signed)


PORTFOLIO_ROOT_REF = "root:cryptoscan-portfolio"


def _portfolio_dependencies(db: Session, records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Real CycloneDX dependency graph for the estate CBOM.

    root → every business system (plus an `unassigned` bucket when assets are not attached to a system);
    system → its crypto assets + the systems it depends on (``system_dependencies`` table, i.e. the
    edges imported from cryptoscan-systems.yml / the systems import). Every ref points at a component
    in this BOM, so downstream CycloneDX tooling can walk blast radius across systems.

    Set-based (audit 14 §3): one query loads every system, one loads every
    dependency edge — no per-system ``dependencies_for`` round trips.
    """
    from db.models.system_dependency import SystemDependency
    from sqlalchemy import select as sa_select

    systems, _trunc = SystemRepository(db).list_all_bounded()
    if not systems:
        return [], []
    sys_ref = {s.id: f"system:{s.name}" for s in systems}
    assets_by_system: dict[str | None, list[str]] = {}
    for row in records:
        ref = row.get("id") or row.get("evidence_id") or row.get("finding_id")
        if ref:
            assets_by_system.setdefault(row.get("system_id"), []).append(str(ref))
    # one query for the whole edge list, grouped by parent (no N+1)
    edges_by_parent: dict[str, list[str]] = {}
    for edge in db.execute(sa_select(SystemDependency)).scalars():
        if edge.child_id != edge.parent_id:
            edges_by_parent.setdefault(edge.parent_id, []).append(edge.child_id)
    components: list[dict[str, Any]] = []
    deps: list[dict[str, Any]] = []
    for s in systems:
        props = [
            {"name": "cryptoscan:system:id", "value": s.id},
            {"name": "cryptoscan:system:criticality", "value": str(s.criticality or "")},
            {"name": "cryptoscan:system:business_unit", "value": str(s.business_unit or "")},
            {"name": "cryptoscan:system:coverage_status", "value": str(s.coverage_status or "")},
            {"name": "cryptoscan:system:environment", "value": str(getattr(s, "environment", "") or "")},
        ]
        components.append({"type": "application", "name": s.name, "bom-ref": sys_ref[s.id],
                           "properties": [p for p in props if p["value"]]})
        depends = list(assets_by_system.get(s.id, []))
        depends += [sys_ref[cid] for cid in edges_by_parent.get(s.id, []) if cid in sys_ref]
        if depends:
            deps.append({"ref": sys_ref[s.id], "dependsOn": depends})
    top = list(sys_ref.values())
    unassigned = assets_by_system.get(None, [])
    if unassigned:
        components.append({"type": "application", "name": "unassigned", "bom-ref": "system:unassigned",
                           "properties": [{"name": "cryptoscan:system:coverage_status", "value": "unassigned"}]})
        deps.append({"ref": "system:unassigned", "dependsOn": unassigned})
        top.append("system:unassigned")
    deps.insert(0, {"ref": PORTFOLIO_ROOT_REF, "dependsOn": top})
    return components, deps


@router.get("/search")
def cbom_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(200, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    located = AssetRepository(db).search_located(q, limit=limit)
    hits = search_records(located, q, limit=limit)
    return {"query": q, "total_count": len(hits), "matches": hits}


@router.post("/validate")
def cbom_validate(
    body: IngestCbomRequest,
    user: str = Depends(get_current_user),
):
    document = validate_document(body.bom)
    crypto = records_from_bom(body.bom)
    return {
        **document,
        "crypto_components": len(crypto),
        "name": bom_system_name(body.bom),
    }


@router.get("/assess/portfolio")
def cbom_assess_portfolio(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Estate-wide crypto posture: every system with assets, assessed and
    ranked worst-first, plus an aggregate estate score."""
    from cbom.assessment import assess_cbom

    systems, _trunc = SystemRepository(db).list_all_bounded()
    results = []
    for system in systems:
        assets = SystemRepository(db).assets_for(system.id)
        if not assets:
            continue
        records = []
        for asset in assets:
            data = asset.to_dict() if hasattr(asset, "to_dict") else {"algorithm": "UNKNOWN"}
            data["system_id"] = system.id
            data["system_name"] = system.name
            records.append(data)
        bom = CbomGenerator().from_records(records, name=system.name)
        report = assess_cbom(bom)
        results.append(
            {
                "system_id": system.id,
                "name": system.name,
                "environment": system.environment,
                "components": report["subject"]["components"],
                "score": report["score"],
                "grade": report["grade"],
                "findings": len(report["findings"]),
                "disallowed": report["summary"]["designations"].get("DISALLOWED", 0),
                "quantum_vulnerable": len(report["summary"]["quantum_vulnerable_algorithms"]),
                "top_recommendation": report["recommendations"][0] if report["recommendations"] else None,
            }
        )
    results.sort(key=lambda r: (r["score"], r["name"]))
    estate_score = round(sum(r["score"] for r in results) / len(results)) if results else None
    estate_grade = (
        "A" if estate_score is None or estate_score >= 90
        else "B" if estate_score >= 75
        else "C" if estate_score >= 60
        else "D" if estate_score >= 40
        else "F"
    )
    return {
        "estate": {
            "score": estate_score,
            "grade": None if estate_score is None else estate_grade,
            "systems_assessed": len(results),
        },
        "systems": results,
    }


@router.post("/verify")
def cbom_verify(
    body: IngestCbomRequest,
    user: str = Depends(get_current_user),
):
    """Verify a CBOM's signature against the server-side keyring.

    Returns the full check-by-check report (never a bare boolean) plus
    structural validation — suitable for audit trails.
    """
    if not body.bom:
        raise HTTPException(status_code=422, detail="bom is required")
    report = CbomGenerator().verify_report(body.bom, _server_keyring())
    document = validate_document(body.bom)
    return {
        "signature": report,
        "document": document,
        "ok": report["ok"] and document["ok"],
        "name": bom_system_name(body.bom),
    }


@router.post("/assess")
def cbom_assess(
    ref: CbomRef,
    user: str = Depends(get_current_user),
):
    """Crypto-posture assessment (score/grade/findings/recommendations) for an
    inline CBOM, a scan, or a system. The DB session is resolved lazily so
    inline-BOM assessments stay dependency-free."""
    from cbom.assessment import assess_cbom

    if ref.bom is not None:
        return assess_cbom(ref.bom)
    db = next(get_db_session())  # type: ignore[arg-type]
    try:
        name, _source_id, records = _resolve_ref(db, ref)
        bom = CbomGenerator().from_records(records, name=name)
        return assess_cbom(bom)
    finally:
        db.close()


def ingest_document(
    *,
    bom: dict,
    db: Session,
    system_name: str | None = None,
    owner: str | None = None,
    environment: str | None = None,
) -> dict:
    """Load a validated CBOM document into the crypto inventory.

    Shared by POST /cbom/ingest and any scanner that wants to persist what it
    just produced, so there is exactly one ingestion path: same validation, same
    signature gate, same asset replacement semantics.
    """
    check = validate_document(bom)
    if not check["ok"]:
        raise HTTPException(status_code=422, detail="; ".join(check["errors"]))
    props = {
        item.get("name")
        for item in ((bom.get("metadata") or {}).get("properties") or [])
    }
    if props & {"cryptoscan:jws", "cryptoscan:signature"}:
        signature = CbomGenerator().verify_report(bom, _server_keyring())
        if not signature["ok"]:
            raise HTTPException(
                status_code=422,
                detail=f"CBOM signature verification failed: {signature['error']}",
            )
    records = records_from_bom(bom)
    if not records:
        raise HTTPException(status_code=422, detail="No cryptographic components in document")
    name = (system_name or bom_system_name(bom)).strip()
    if not name:
        raise HTTPException(status_code=422, detail="system_name is required")
    sys_repo = SystemRepository(db)
    system = sys_repo.get_or_create(
        name, owner=owner, environment=environment,
        description="Imported from CycloneDX CBOM",
    )
    extra = dict(system.extra or {})
    extra["cbom"] = {
        "spec_version": bom.get("specVersion"),
        "serial_number": bom.get("serialNumber"),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "component_count": len(records),
        "source": "ingest",
    }
    system.extra = extra
    stored = AssetRepository(db).replace_for_scan(
        f"cbom-ingest:{system.id}",
        [
            {
                "algorithm": item["algorithm"],
                "purpose": item.get("purpose"),
                "mode": item.get("mode"),
                "key_size": item.get("key_size"),
                "file_path": item.get("file_path") or f"cbom://{item.get('name') or item['algorithm']}",
                "line_number": int(item.get("line_number") or 0),
                "confidence": "HIGH",
                "scanner_ids": ["cbom-ingest"],
                "libraries": [],
                "dedup_key": item.get("id"),
            }
            for item in records
        ],
    )
    for asset in stored:
        sys_repo.attach_asset(system.id, asset.id)
    sys_repo.stamp_scan(
        system.id,
        scan_id=None,
        status="CURRENT",
        component_count=len(stored),
        algorithms=dict(Counter(item["algorithm"] for item in records)),
    )
    summary = summarize_records(
        stored,
        source_type="system",
        source_id=system.id,
        name=system.name,
        environment=system.environment,
    )
    return {"system": system.to_dict(), "imported": len(stored), "summary": summary}


@router.post("/ingest")
def cbom_ingest(
    body: IngestCbomRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    check = validate_document(body.bom)
    if not check["ok"]:
        raise HTTPException(status_code=422, detail="; ".join(check["errors"]))
    return ingest_document(bom=body.bom, db=db, system_name=body.system_name,
                           owner=body.owner, environment=body.environment)


@router.post("/diff")
def cbom_diff(
    body: DiffCbomRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    left_name, left_id, left_records = _resolve_ref(db, body.left)
    right_name, right_id, right_records = _resolve_ref(db, body.right)
    # Semantic diff (report 08 P2#8): attribute deltas between the same
    # logical component (algorithm at a location) are classified —
    # ALGORITHM_CHANGED / PARAMETER_CHANGED / LOCATION_CHANGED /
    # VERSION_CHANGED — instead of surfacing as an added+removed pair.
    # The response keeps the historical added/removed/unchanged/counts
    # shape and adds ``changed`` + ``counts.changed``.
    result = semantic_diff(left_records, right_records)
    result["left"] = {"name": left_name, "source_id": left_id, "components": len(left_records)}
    result["right"] = {"name": right_name, "source_id": right_id, "components": len(right_records)}
    return result


@router.get("/scan/{scan_id}")
def cbom_for_scan(
    scan_id: str,
    fmt: str = Query("json"),
    signed: bool | str = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    scan, rows = _records_for_scan(db, scan_id)
    # Observed cascade edges — the same real graph the export renders
    # (provider files, business systems, wave properties), instead of the
    # generator's root-fan-out fallback. Every ref points at a component in
    # this BOM: cascade nodes are appended as file/system components.
    from api.routers.export import _cascade_dependencies

    cascade = (scan.statistics or {}).get("cascade") or {}
    extra_components, dependencies = _cascade_dependencies(
        f"root:{scan.id}", cascade, rows)
    bom = CbomGenerator().from_records(
        rows,
        name=scan.target_location,
        version=scan.target_commit or scan.target_branch or "unknown",
        tool_version=scan.scanner_version,
        dependencies=dependencies or None,
        scan_id=scan.id,
        metadata_properties=(
            [{"name": "cryptoscan:dependencies", "value": "scan-cascade"}]
            if dependencies else None),
    )
    if extra_components:
        bom.setdefault("components", []).extend(extra_components)
    if dependencies:
        # the root ref must resolve: point it at the metadata application
        # component, exactly as the export path does
        component = (bom.setdefault("metadata", {})
                     .setdefault("component", {}))
        component.setdefault("type", "application")
        component["bom-ref"] = f"root:{scan.id}"
    return _render(bom, fmt, signed)


@router.get("/system/{system_id}")
def cbom_for_system(
    system_id: str,
    fmt: str = Query("json"),
    signed: bool | str = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    system, assets = _records_for_system(db, system_id)
    records = []
    for asset in assets:
        data = asset.to_dict() if hasattr(asset, "to_dict") else {"algorithm": getattr(asset, "algorithm", "UNKNOWN")}
        data["system_id"] = system.id
        data["system_name"] = system.name
        records.append(data)
    # Real edges, not a root-fan-out: the system depends on the crypto assets
    # registered to it, plus its registered inter-system dependencies in both
    # directions (upstream callers keep their direction — that is the point).
    from db.models.system_dependency import SystemDependency

    system_edges = [
        {"parent": d.parent_id, "child": d.child_id, "relation": d.relation}
        for d in db.query(SystemDependency).filter(
            (SystemDependency.parent_id == system.id)
            | (SystemDependency.child_id == system.id)).all()
    ]
    dependencies = build_estate_dependencies(
        system.id, [str(r.get("id")) for r in records if r.get("id")],
        system_edges)
    bom = CbomGenerator().from_records(
        records, name=system.name, version=system.environment or "unknown",
        dependencies=dependencies,
        metadata_properties=[
            {"name": "cryptoscan:dependencies", "value": "estate-linkage"},
        ],
        scan_id=f"system:{system.id}")
    return _render(bom, fmt, signed)


@router.post("/custom")
def cbom_custom(
    body: CustomCbomRequest,
    fmt: str = Query("json"),
    signed: bool | str = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    if not body.asset_ids:
        raise HTTPException(status_code=422, detail="asset_ids is required")
    repo = AssetRepository(db)
    records = []
    missing = []
    for asset_id in body.asset_ids:
        row = repo.get_by_id(asset_id)
        if row is None:
            missing.append(asset_id)
            continue
        payload = row.to_dict() if hasattr(row, "to_dict") else {
            "id": getattr(row, "id", asset_id),
            "algorithm": getattr(row, "algorithm", "UNKNOWN"),
            "mode": getattr(row, "mode", None),
            "key_size": getattr(row, "key_size", None),
            "purpose": getattr(row, "purpose", None),
            "file_path": getattr(row, "file_path", None),
            "line_number": getattr(row, "line_number", None),
        }
        if body.include_evidence and hasattr(row, "evidence_links"):
            payload["evidence_ids"] = [link.evidence_id for link in row.evidence_links]
        records.append(payload)
    if missing and not records:
        raise HTTPException(status_code=404, detail=f"Assets not found: {missing}")
    vulns = None
    if body.include_vulnerabilities:
        try:
            rows, _ = VulnerabilityRepository(db).list_vulns(page=1, page_size=200)
            vulns = [item.to_dict() if hasattr(item, "to_dict") else item for item in rows]
        except Exception:
            vulns = None
    bom = CbomGenerator().from_records(records, name=body.name, vulnerabilities=vulns)
    return _render(bom, fmt, signed)


# ------------------------------- NBOM ---------------------------------- #
# A CBOM inventories the cryptography in the estate's *code*. An NBOM
# inventories what is exposed *on the wire* — listeners, the certificates and
# suites they serve, and the tunnels between sites — with the dependency graph
# that says what breaks when one of them is replaced. Neither sees what the
# other sees: code scanning cannot find a load balancer terminating TLS 1.0
# for a legacy partner, and network scanning cannot find an algorithm chosen
# at runtime from configuration.

class NbomRequest(BaseModel):
    """Estate to inventory.

    endpoints: [{host, port, protocol?, tls_version?, cipher_suite?,
                 certificate?: {...}, device?, observed?}]
    An endpoint that was never successfully probed must set observed=false; it
    is inventoried but excluded from every verdict.
    """
    endpoints: list[dict] = []
    tunnels: list[dict] = []
    devices: list[dict] = []
    estate: str | None = None


@router.post("/nbom")
def nbom_build(body: NbomRequest, user: str = Depends(get_current_user)):
    """Build a CycloneDX 1.5 Network BOM with its dependency graph."""
    from cbom.nbom import build_nbom, summarise

    if not (body.endpoints or body.tunnels):
        raise HTTPException(status_code=400, detail="endpoints or tunnels required")
    bom = build_nbom(body.endpoints, tunnels=body.tunnels,
                     devices=body.devices, estate=body.estate)
    return {"nbom": bom, "summary": summarise(bom)}


@router.post("/nbom/cascade")
def nbom_cascade(body: NbomRequest, ref: str = Query(..., description="bom-ref to trace"),
                 user: str = Depends(get_current_user)):
    """Everything affected by replacing one component — the migration blast radius."""
    from cbom.nbom import build_nbom, cascade

    bom = build_nbom(body.endpoints, tunnels=body.tunnels,
                     devices=body.devices, estate=body.estate)
    return cascade(bom, ref)


# Statuses that mean the probe never completed a handshake. Same set the
# telecom classifier uses: an endpoint we could not reach is unknown, and must
# not be inventoried as though we had observed it to be healthy.
_NBOM_UNREACHABLE = {"DNS_FAILED", "TIMEOUT", "PORT_CLOSED", "CONNECT_ERROR", ""}


def _gather_network_inventory(db: Session, *, limit: int = 2000) -> dict[str, list[dict]]:
    """Build NBOM inputs from real rows: network scan probes + certificates.

    The network scanner already stores each run's probe results in
    ``network_scan_runs.result``; every probe carries the endpoint, the
    negotiated TLS version and cipher suite, and the certificate chain it was
    served. That is exactly an NBOM, so the BOM is derived from the scan rather
    than re-declared by hand.

    Newest run wins per endpoint, so a re-scan supersedes rather than
    duplicates.
    """
    from sqlalchemy import desc, select as _select

    from db.models.network_scan_run import NetworkScanRun

    runs = db.execute(
        _select(NetworkScanRun).order_by(desc(NetworkScanRun.created_at)).limit(limit)
    ).scalars().all()

    endpoints: dict[str, dict] = {}
    for run in runs:
        for probe in ((run.result or {}).get("probes") or []):
            raw = str(probe.get("endpoint") or "").strip()
            if not raw or raw in endpoints:
                continue  # first sighting is the newest run
            host, _, port = raw.rpartition(":")
            if not host:
                host, port = raw, ""
            chain = probe.get("certificates") or []
            leaf = chain[0] if chain else {}
            status = str(probe.get("status") or "").upper()
            endpoints[raw] = {
                "host": host,
                "port": int(port) if str(port).isdigit() else port,
                "protocol": probe.get("starttls") or "tls",
                "tls_version": probe.get("tls_version"),
                "cipher_suite": probe.get("cipher_suite"),
                "observed": status not in _NBOM_UNREACHABLE,
                "service": probe.get("alpn"),
                "certificate": {
                    "subject": leaf.get("subject"),
                    "issuer": leaf.get("issuer"),
                    "serial_number": leaf.get("serial_number"),
                    "public_key_algorithm": leaf.get("public_key_algorithm"),
                    "public_key_size": leaf.get("public_key_size"),
                    "not_after": str(leaf.get("not_after") or "") or None,
                    "is_self_signed": leaf.get("is_self_signed"),
                    "expiry_status": leaf.get("expiry_status"),
                } if leaf else None,
            }
    return {"endpoints": list(endpoints.values())}


@router.get("/nbom")
def nbom_live(db: Session = Depends(get_db_session), user: str = Depends(get_current_user)):
    """The Network BOM for this estate, derived from stored network scans.

    Empty until a network scan has run — an estate with no scan renders zeroes
    rather than a fabricated inventory.
    """
    from cbom.nbom import build_nbom, summarise

    gathered = _gather_network_inventory(db)
    bom = build_nbom(gathered["endpoints"], estate="network-estate")
    return {"nbom": bom, "summary": summarise(bom),
            "source": "live" if gathered["endpoints"] else "empty"}
