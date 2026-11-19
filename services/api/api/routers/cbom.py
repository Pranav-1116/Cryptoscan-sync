"""CycloneDX 1.5 CBOM catalog, export, ingest, and comparison."""

from __future__ import annotations

import hashlib
import json
import logging
import os

from db.tenancy import filtered_get

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, get_job_repository, require_auditor, require_roles
from api.schemas.cbom_schemas import (
    CbomRef,
    CustomCbomRequest,
    DiffCbomRequest,
    IngestCbomRequest,
)
from cbom.generator import CbomGenerator
from cbom.snapshot_diff import diff_snapshots
from cbom.builders.dependency_builder import build_estate_dependencies
from cbom.inventory import (
    bom_system_name,
    records_from_bom,
    search_records,
    semantic_diff,
    summarize_records,
    validate_document,
)
from db.models.cbom_snapshot import CbomSnapshot, normalize_for_snapshot
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
    if fmt not in {"json", "xml", "cyclonedx16"}:
        raise HTTPException(status_code=422, detail="fmt must be json, xml or cyclonedx16")
    if fmt == "cyclonedx16":
        from cbom.cyclonedx16 import to_cyclonedx16
        try:
            bom = to_cyclonedx16(bom)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Native CBOM export failed schema/reference validation") from exc
    bom = _apply_signature(bom, signed, fmt=fmt)
    if fmt == "cyclonedx16":
        from cbom.cyclonedx16 import validate_cyclonedx16
        if not validate_cyclonedx16(bom)["ok"]:
            raise HTTPException(status_code=422, detail="Signed native CBOM failed schema/reference validation")
    generator = CbomGenerator()
    if fmt == "xml":
        return Response(content=generator.to_xml(bom), media_type="application/xml")
    return JSONResponse(bom)


def _apply_signature(bom: dict, signed: bool | str, *, fmt: str = "json") -> dict:
    """Sign the document in place-form (returns the mutated dict).

    "jsf" selects the CycloneDX-spec standard enveloped signature
    (top-level ``signature`` field, report 08 P2#6); True keeps the
    legacy JWS-in-metadata-property form for backward compatibility.
    Shared by the live render path and snapshot creation so a pinned
    snapshot carries the same signature a live export would.
    """
    generator = CbomGenerator()
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
    return bom


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


def _attach_business_context(data: dict, system) -> None:
    """Export supplied business context, not an independent ownership attestation."""
    data["application"] = system.name
    for field in ("owner", "criticality"):
        if getattr(system, field, None) is not None:
            data[field] = getattr(system, field)
    extra = system.extra if isinstance(system.extra, dict) else {}
    if "data_classification" in extra:
        data["data_classification"] = extra["data_classification"]
    retention = extra.get("data_retention_years", extra.get("retention_years"))
    if retention is not None:
        data["retention_years"] = retention


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

    from sqlalchemy import func
    from db.import_provenance import archived_legacy_clause
    from api.routers.cbom_legacy import refuse_unreviewed_export
    refuse_unreviewed_export(db)
    active = ~archived_legacy_clause()
    limit = _portfolio_max_assets()
    rows = db.execute(
        select(CryptoAsset, System, func.count().over().label("total"))
        .outerjoin(SystemAsset, SystemAsset.asset_id == CryptoAsset.id)
        .outerjoin(System, System.id == SystemAsset.system_id)
        .where(active).order_by(CryptoAsset.id, System.id).limit(limit)
    ).all()
    from api.routers.cbom_legacy import refuse_legacy_records
    refuse_legacy_records([row[0] for row in rows])
    total = int(rows[0][2]) if rows else 0
    located: list[dict[str, Any]] = []
    for asset, system, _total in rows:
        data = asset.to_dict()
        data["system_id"] = system.id if system is not None else None
        data["system_name"] = system.name if system is not None else "unassigned"
        if system is not None:
            _attach_business_context(data, system)
        located.append(data)
    if total > limit:
        logger.warning(
            "portfolio_assets_truncated",
            extra={"total": total, "limit": limit},
        )
        return located, total
    return located, total


def _records_for_system(db: Session, system_id: str) -> tuple[Any, list[Any]]:
    repo = SystemRepository(db)
    system = repo.get_by_id(system_id)
    if system is None:
        raise HTTPException(status_code=404, detail="System not found")
    from api.routers.cbom_legacy import refuse_unreviewed_export
    refuse_unreviewed_export(db, system_id=system_id)
    assets = repo.assets_for(system_id)
    from api.routers.cbom_legacy import refuse_legacy_records
    refuse_legacy_records(assets)
    return system, assets


def _records_for_scan(db: Session, scan_id: str) -> tuple[Scan, list[Any]]:
    scan = filtered_get(db, Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    from api.routers.evidence_disposition import export_refused_reason
    refused = export_refused_reason(db, scan_id)
    if refused:
        raise HTTPException(status_code=409, detail=refused)
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
    catalog = sys_repo.catalog_rows(systems)
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


def _live_bom_documents(db: Session, *, limit: int = 2000) -> tuple[dict, dict]:
    """Build cross-BOM documents and source coverage from tenant-scoped rows.

    The HBOM layer here is still the TechBOM hardware projection; the
    INDEPENDENT, unified estate HBOM (round 71) lives on its own surface —
    ``routers/hbom.py`` serves the document generated from persisted
    ``hardware_assets`` rows with pinning. NBOM comes from the same stored
    probes as GET /cbom/nbom. A missing source is reported in coverage,
    not represented by a fabricated BOM.
    """
    from api.routers.techbom import _environment_of, _gather_inventory
    from cbom.nbom import build_nbom
    from cbom.technology_bom import materialize_technology_bom
    from vendor_intel.vbom import build_vbom

    inv = _gather_inventory(db, limit=limit)
    cbom_doc = CbomGenerator().from_records(inv.get("crypto") or [], name="estate")
    techbom_doc = materialize_technology_bom(
        inv, environment=_environment_of(db), state_version=0)
    boms = {"cbom": cbom_doc, "techbom": techbom_doc}
    coverage = {
        "cbom": {"status": "present" if inv["crypto"] else "absent",
                 "source": "crypto_assets", "components": len(cbom_doc.get("components") or [])},
        "techbom": {"status": "present" if techbom_doc["total_components"] else "absent",
                    "source": "technology-bom inventory", "components": techbom_doc["total_components"]},
    }

    hardware = techbom_doc["layers"]["hbom"]
    coverage["hbom"] = {
        "status": "present" if hardware["count"] else "absent",
        "source": "technology-bom.layers.hbom (hardware_assets)",
        "components": hardware["count"], "independent_generator": False,
    }
    if hardware["count"]:
        boms["hbom"] = hardware

    # Do not materialize an empty NBOM: its absence means no stored probes,
    # not a successfully surveyed network with no components.
    network = _gather_network_inventory(db, limit=limit)
    coverage["nbom"] = {
        "status": "present" if network["endpoints"] else "absent",
        "source": "network_scan_runs.result.probes", "endpoints": len(network["endpoints"]),
    }
    if network["endpoints"]:
        boms["nbom"] = build_nbom(network["endpoints"], estate="network-estate")
        coverage["nbom"]["components"] = len(boms["nbom"]["components"])
    else:
        coverage["nbom"]["components"] = 0

    try:
        vbom_doc = build_vbom(db).to_cyclonedx()
    except Exception as exc:  # an unavailable source must not become an empty BOM
        logger.info("cross_links_vbom_unavailable",
                    extra={"error_type": type(exc).__name__})
        coverage["vbom"] = {"status": "unavailable", "source": "vendor_intel.vbom",
                            "components": 0}
    else:
        boms["vbom"] = vbom_doc
        count = len(vbom_doc.get("components") or [])
        coverage["vbom"] = {"status": "present" if count else "absent",
                            "source": "vendor_intel.vbom", "components": count}
    return boms, coverage


@router.get("/cross-links")
def cbom_cross_links(
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Cross-BOM links + conflicts over the live inventory (46, round 36).

    Associates available inventory projections by canonical grouping key,
    never by an inferred physical asset ID. HBOM is the TechBOM hardware
    projection; NBOM is built from persisted network probes.
    """
    from cbom.cross_bom import cross_boms

    boms, coverage = _live_bom_documents(db, limit=limit)
    return cross_boms(boms) | {"live": True, "limit": limit, "coverage": coverage}



@router.get("/query")
def cbom_query(
    identity: str | None = Query(None, description="Canonical identity, e.g. crypto:RSA-2048"),
    kind: str | None = Query(None, description="Component kind: crypto, vendor, application, hardware, endpoint, network-device"),
    bom: str | None = Query(None, description="Restrict to one available BOM: cbom, techbom, vbom, hbom, nbom"),
    algorithm: str | None = Query(None, description="Crypto components by algorithm (case-insensitive)"),
    linked_only: bool = Query(False, description="Only identities present in 2+ BOMs"),
    unlinked_only: bool = Query(False, description="Only identities present in exactly 1 BOM (coverage gaps)"),
    conflicts_only: bool = Query(False, description="Only unambiguous cross-BOM value disagreements"),
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Unified query over every BOM (46 unified query layer, round 37).

    Searches the available CBOM, TechBOM, VBOM, HBOM projection and NBOM.
    Canonical grouping keys are associations, not physical asset identity;
    coverage names missing sources and the HBOM's shared provenance.
    """
    from cbom.bom_query import query_boms

    boms, coverage = _live_bom_documents(db, limit=limit)
    return query_boms(
        boms, identity=identity, kind=kind, bom=bom, algorithm=algorithm,
        linked_only=linked_only, unlinked_only=unlinked_only,
        conflicts_only=conflicts_only,
    ) | {"live": True, "limit": limit, "coverage": coverage}


@router.get("/coverage")
def cbom_coverage(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Scan coverage, plus what an asset count over that coverage may say.

    ``inventory.statement`` is the sentence an operator can quote, and
    ``quotable.phrasing`` says whether the count is a total or a floor.
    """
    from cbom.coverage_render import inventory_coverage, quotable_counts
    from db.models.crypto_asset import CryptoAsset

    summary = SystemRepository(db).coverage_summary()
    assets = int(db.query(CryptoAsset).count() or 0)
    block = inventory_coverage(summary, assets=assets)
    return {**summary, "inventory": block, "quotable": quotable_counts(block)}


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
    import uuid

    from api import cbom_provenance

    records, total_assets = _located_assets(db)
    limit = _portfolio_max_assets()
    truncated = total_assets > limit
    systems, _systems_truncated = SystemRepository(db).list_all_bounded()
    # evidence chain + ownership mapping per asset; placeholder rows removed
    provenance = cbom_provenance.enrich_records(db, records, systems)
    system_components, dependencies, edge_summary = _portfolio_dependencies(db, records, systems=systems)
    distinct_assets = len({str(row.get("id")) for row in records if row.get("id")})
    registered = len(systems)
    system_records = len(system_components)
    metadata_properties = [
        {"name": "cryptoscan:scope", "value": "estate"},
        # registered business systems; the unassigned bucket is not a system
        {"name": "cryptoscan:systems", "value": str(registered)},
        {"name": "cryptoscan:portfolio:system_components", "value": str(system_records)},
        {"name": "cryptoscan:portfolio:systems_with_assets",
         "value": str(len({row.get("system_id") for row in records if row.get("system_id")}))},
        {"name": "cryptoscan:assets", "value": str(distinct_assets)},
        {"name": "cryptoscan:portfolio:asset_system_rows", "value": str(len(records))},
        {"name": "cryptoscan:export:run_id", "value": str(uuid.uuid4())},
        {"name": "cryptoscan:export:profile_version", "value": cbom_provenance.EXPORT_PROFILE_VERSION},
        {"name": "cryptoscan:export:generated_by", "value": str(user)},
        {"name": "cryptoscan:export:collectors", "value": json.dumps(provenance["collectors"])},
        {"name": "cryptoscan:export:source_revisions", "value": json.dumps(provenance["source_revisions"])},
        {"name": "cryptoscan:export:mapping_summary", "value": json.dumps(
            {"by_status": provenance["mapping_counts"], "unmapped_reasons": provenance["unmapped_reasons"],
             "basis": "asset-to-system links; candidates come from scan targets or claimed endpoints, never names"},
            sort_keys=True)},
        {"name": "cryptoscan:export:evidence_summary", "value": json.dumps(
            {"assets_with_linked_evidence": provenance["evidence_linked_assets"],
             "assets_without_linked_evidence": provenance["evidence_unlinked_assets"],
             "confidence_is_not_verification": True}, sort_keys=True)},
        {"name": "cryptoscan:export:relationship_summary", "value": json.dumps(edge_summary, sort_keys=True)},
        {"name": "cryptoscan:export:coverage_denominator", "value": json.dumps(
            {"registered_systems": registered, "assets_exported": distinct_assets, "assets_total": total_assets,
             "meaning": "counts of what CryptoScan holds; unscanned estate is not in the denominator"},
            sort_keys=True)},
        {"name": "cryptoscan:collection:failures", "value": json.dumps(cbom_provenance.failed_collections(db),
                                                                        sort_keys=True)},
    ]
    if provenance["excluded"]:
        metadata_properties.append({"name": "cryptoscan:export:excluded_candidates", "value": json.dumps(
            {"count": len(provenance["excluded"]), "items": provenance["excluded"][:50],
             "basis": "placeholder or bookkeeping rows are not cryptographic assets"}, sort_keys=True)})
    org = cbom_provenance.organization(db)
    if org:
        metadata_properties.append({"name": "cryptoscan:organization", "value": json.dumps(org, sort_keys=True)})
    # Review item 18: an estate CBOM states its coverage in the document, so the
    # asset count cannot be read downstream as "the bank has N".
    from cbom.coverage_render import document_properties, inventory_coverage
    coverage_block = inventory_coverage(SystemRepository(db).coverage_summary(),
                                        assets=total_assets)
    metadata_properties += document_properties(coverage_block)
    from api.routers.cbom_legacy_controlled import retained_metadata
    metadata_properties += retained_metadata(db)
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
UNASSIGNED_REF = "system:unassigned"


def _portfolio_dependencies(db: Session, records: list[dict[str, Any]], *, systems: list[Any] | None = None
                            ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Real CycloneDX dependency graph for the estate CBOM.

    root → every business system (plus an `unassigned` bucket when assets are not attached to a system);
    system → its crypto assets + the systems it depends on (``system_dependencies`` table, i.e. the
    edges imported from cryptoscan-systems.yml / the systems import). Every ref points at a component
    in this BOM, so downstream CycloneDX tooling can walk blast radius across systems.

    CycloneDX ``dependencies`` entries cannot carry metadata, so each system→system
    edge's provenance (id, type, basis, confidence, verification, evidence ref,
    first/last seen) travels on the parent system component as
    ``cryptoscan:system:dependency_edges``. Asset membership edges carry the
    asset's own ``cryptoscan:mapping_*`` properties. None of these edges is a
    runtime-verified call path.

    Set-based (audit 14 §3): one query loads every system, one loads every
    dependency edge — no per-system ``dependencies_for`` round trips.
    """
    from api.cbom_provenance import edge_record
    from db.models.system_dependency import SystemDependency
    from sqlalchemy import select as sa_select

    if systems is None:
        systems, _trunc = SystemRepository(db).list_all_bounded()
    if not systems:
        return [], [], {"system_edges": 0}
    sys_ref = {s.id: f"system:{s.name}" for s in systems}
    assets_by_system: dict[str | None, list[str]] = {}
    for row in records:
        ref = row.get("id") or row.get("evidence_id") or row.get("finding_id")
        if ref and str(ref) not in assets_by_system.setdefault(row.get("system_id"), []):
            assets_by_system[row.get("system_id")].append(str(ref))
    # one query for the whole edge list, grouped by parent (no N+1)
    edges_by_parent: dict[str, list[Any]] = {}
    for edge in db.execute(sa_select(SystemDependency)).scalars():
        if edge.child_id != edge.parent_id:
            edges_by_parent.setdefault(edge.parent_id, []).append(edge)
    components: list[dict[str, Any]] = []
    deps: list[dict[str, Any]] = []
    by_basis: dict[str, int] = {}
    by_verification: dict[str, int] = {}
    edge_total = 0
    for s in sorted(systems, key=lambda item: sys_ref[item.id]):
        props = [
            {"name": "cryptoscan:system:id", "value": s.id},
            {"name": "cryptoscan:system:kind", "value": "REGISTERED_SYSTEM"},
            {"name": "cryptoscan:system:criticality", "value": str(s.criticality or "")},
            {"name": "cryptoscan:system:business_unit", "value": str(s.business_unit or "")},
            {"name": "cryptoscan:system:coverage_status", "value": str(s.coverage_status or "")},
            {"name": "cryptoscan:system:environment", "value": str(getattr(s, "environment", "") or "")},
            {"name": "cryptoscan:system:owner", "value": str(getattr(s, "owner", "") or "")},
            {"name": "cryptoscan:system:last_scanned_at", "value": str(_iso(getattr(s, "last_scanned_at", None)) or "")},
            {"name": "cryptoscan:system:asset_count", "value": str(len(assets_by_system.get(s.id, [])))},
        ]
        edges = [edge_record(edge, sys_ref[s.id], sys_ref[edge.child_id])
                 for edge in edges_by_parent.get(s.id, []) if edge.child_id in sys_ref]
        edges.sort(key=lambda item: item["target"])
        for item in edges:
            by_basis[item["basis"]] = by_basis.get(item["basis"], 0) + 1
            by_verification[item["verification_status"]] = by_verification.get(item["verification_status"], 0) + 1
        edge_total += len(edges)
        if edges:
            props.append({"name": "cryptoscan:system:dependency_edges", "value": json.dumps(edges, sort_keys=True)})
        components.append({"type": "application", "name": s.name, "bom-ref": sys_ref[s.id],
                           "properties": [p for p in props if p["value"]]})
        depends = list(assets_by_system.get(s.id, []))
        depends += [item["target"] for item in edges]
        if depends:
            deps.append({"ref": sys_ref[s.id], "dependsOn": depends})
    top = [sys_ref[s.id] for s in sorted(systems, key=lambda item: sys_ref[item.id])]
    unassigned = assets_by_system.get(None, [])
    if unassigned:
        components.append({"type": "application", "name": "unassigned", "bom-ref": UNASSIGNED_REF,
                           "description": "Bucket for assets with no recorded system link; not a business system. "
                                          "Each asset's cryptoscan:mapping_reason says why.",
                           "properties": [{"name": "cryptoscan:system:coverage_status", "value": "unassigned"},
                                          {"name": "cryptoscan:system:kind", "value": "UNMAPPED_BUCKET_NOT_A_SYSTEM"},
                                          {"name": "cryptoscan:system:asset_count", "value": str(len(unassigned))}]})
        deps.append({"ref": UNASSIGNED_REF, "dependsOn": unassigned})
        top.append(UNASSIGNED_REF)
    deps.insert(0, {"ref": PORTFOLIO_ROOT_REF, "dependsOn": top})
    summary = {
        "system_edges": edge_total,
        "system_edges_by_basis": dict(sorted(by_basis.items())),
        "system_edges_by_verification": dict(sorted(by_verification.items())),
        "asset_membership_edges": sum(len(v) for v in assets_by_system.values()),
        "root_edges": len(top),
        "runtime_verified_edges": 0,
        "basis": "declared or observed relationships from the system registry; not runtime call proof",
    }
    return components, deps, summary


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
    crypto = records_from_bom(body.bom) if document["ok"] else []
    return {
        **document,
        "crypto_components": len(crypto),
        "name": bom_system_name(body.bom) if document["ok"] else None,
    }


@router.get("/assess/portfolio")
def cbom_assess_portfolio(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Estate-wide crypto posture: every system with assets, assessed and
    ranked worst-first, plus an aggregate estate score."""
    from api.routers.cbom_legacy_controlled import refuse_partial_assessment
    refuse_partial_assessment(db)
    from cbom.assessment import assess_cbom

    from api.routers.cbom_legacy import refuse_unreviewed_export
    refuse_unreviewed_export(db)
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
        metadata = ref.bom.get("metadata") or {}
        properties = metadata.get("properties") or [] if isinstance(metadata, dict) else []
        if any(isinstance(p, dict) and p.get("name") == "cryptoscan:inventory_completeness"
               and p.get("value") == "PARTIAL_RETAINED_MIXED_EVIDENCE" for p in properties):
            raise HTTPException(409, "Partial retained-history document cannot establish a clean posture grade")
        return assess_cbom(ref.bom)
    from contextlib import contextmanager
    with contextmanager(get_db_session)() as db:
        if ref.system_id:
            from api.routers.cbom_legacy_controlled import refuse_partial_assessment
            refuse_partial_assessment(db, ref.system_id)
        name, _source_id, records = _resolve_ref(db, ref)
        bom = CbomGenerator().from_records(records, name=name)
        return assess_cbom(bom)


require_cbom_writer = require_roles("superadmin", "ciso", "security_analyst")
IMPORT_SOURCE_BASIS = "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS"


def ingest_document(
    *,
    bom: dict,
    db: Session,
    system_name: str | None = None,
    owner: str | None = None,
    environment: str | None = None,
    actor: str | None = None,
) -> dict:
    """Load a validated CBOM document into the crypto inventory.

    Shared by POST /cbom/ingest and any scanner that wants to persist what it
    just produced, so there is exactly one ingestion path: same validation, same
    signature gate, same asset replacement semantics.
    """
    check = validate_document(bom)
    if not check["ok"]:
        raise HTTPException(status_code=422, detail="; ".join(check["errors"]))
    metadata = bom.get("metadata") or {}
    if (not isinstance(metadata, dict) or not isinstance(metadata.get("properties", []), list)
            or any(not isinstance(prop, dict) or not isinstance(prop.get("name"), str)
                   or not isinstance(prop.get("value"), str) for prop in metadata.get("properties", []))
            or (metadata.get("component") is not None and not isinstance(metadata["component"], dict))):
        raise HTTPException(status_code=422, detail="Malformed CBOM metadata/properties")
    if "signature" in bom and (not isinstance(bom["signature"], dict) or not bom["signature"].get("value")):
        raise HTTPException(status_code=422, detail="Unsupported or empty CBOM signature envelope")
    props = {
        item.get("name")
        for item in ((bom.get("metadata") or {}).get("properties") or [])
        if isinstance(item, dict)
    }
    if "signature" in bom or props & {"cryptoscan:jws", "cryptoscan:signature"}:
        signature = CbomGenerator().verify_report(bom, _server_keyring())
        if not signature["ok"]:
            raise HTTPException(
                status_code=422,
                detail=f"CBOM signature verification failed: {signature['error']}",
            )
    # Validate storage limits before any database mutation (including legacy
    # 1.4/1.5 shapes, whose historical validator is deliberately permissive).
    if len(bom.get("components") or []) > 10000:
        raise HTTPException(status_code=422, detail="CBOM import limit is 10000 components; split the document explicitly")
    for component in bom.get("components") or []:
        if not isinstance(component, dict) or component.get("components"):
            raise HTTPException(status_code=422, detail="Algorithm metadata import requires flat component objects; flatten nested documents explicitly")
        crypto = component.get("cryptoProperties") or {}
        if bom.get("specVersion") == "1.6" and crypto and crypto.get("assetType") != "algorithm":
            raise HTTPException(status_code=422, detail="This importer supports algorithm metadata only; certificate, key and protocol records need their dedicated inventory workflows")
    try:
        records = records_from_bom(bom)
    except (ValueError, TypeError, AttributeError, OverflowError):
        raise HTTPException(status_code=422, detail="Malformed cryptographic component metadata") from None
    for item in records:
        if (len(item["algorithm"]) > 80 or len(str(item.get("purpose") or "")) > 50
                or any(value is not None and (not isinstance(value, str) or len(value) > 50)
                       for value in (item.get("mode"), item.get("purpose"), item.get("padding")))
                or not 0 <= item["line_number"] <= 2147483647
                or (item.get("key_size") is not None and not 0 <= item["key_size"] <= 2147483647)):
            raise HTTPException(status_code=422, detail="Cryptographic component exceeds inventory field limits")
    if not records:
        raise HTTPException(status_code=422, detail="No cryptographic components in document")
    name = (system_name or bom_system_name(bom)).strip()
    if not name or len(name) > 200:
        raise HTTPException(status_code=422, detail="system_name must contain 1 to 200 characters")
    try:
        document_sha256 = hashlib.sha256(json.dumps(bom, sort_keys=True, separators=(",", ":"),
                                                   ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(status_code=422, detail="CBOM must contain finite, serializable JSON values") from None
    identities = {}
    for item in records:
        for context in item.get("business_contexts") or []:
            if any(not isinstance(value, (str, int, float)) or isinstance(value, bool) or len(str(value)) > 1000
                   for value in context.values()):
                raise HTTPException(status_code=422, detail="Business context must contain scalar declarations of at most 1000 characters")
        key = (item["algorithm"], item.get("purpose"), item["file_path"], item["line_number"])
        metadata = {field: item.get(field) for field in ("mode", "padding", "key_size", "business_contexts", "parameter_set_identifier")}
        if key in identities and identities[key] != metadata:
            raise HTTPException(status_code=422, detail="Conflicting component declarations at the same inventory location")
        identities[key] = metadata
    sys_repo = SystemRepository(db)
    system = sys_repo.get_or_create(
        name, owner=owner, environment=environment,
        description="Imported from CycloneDX CBOM",
    )
    # Serialize concurrent imports to an existing system. A first-create
    # race is rejected by the estate/name unique index and returned as 409.
    from db.models.system import System
    db.execute(select(System).where(System.id == system.id).with_for_update().execution_options(populate_existing=True)).scalar_one()
    extra = dict(system.extra or {})
    import_receipt = {
        "spec_version": bom.get("specVersion"),
        "serial_number": bom.get("serialNumber"),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "component_count": len(records),
        "source": "ingest",
        "imported_by": actor,
        "source_basis": IMPORT_SOURCE_BASIS,
        "document_sha256": document_sha256,
    }
    extra["cbom_import"] = import_receipt
    if not isinstance(extra.get("cbom"), dict) or extra["cbom"].get("source") != "scan":
        extra["cbom"] = import_receipt
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
                "confidence": "LOW",
                "scanner_ids": ["cbom-ingest"],
                "cbom_import": {
                    **{key: item[key] for key in ("business_contexts", "parameter_set_identifier", "key_size_basis", "padding") if key in item},
                    "system_id": system.id,
                    "document_sha256": document_sha256,
                    "source_basis": IMPORT_SOURCE_BASIS,
                },
                "libraries": [],
                "dedup_key": item.get("id"),
            }
            for item in records
        ],
        import_system_id=system.id,
    )
    for asset in stored:
        sys_repo.attach_asset(system.id, asset.id)
    # Metadata import is NOT scanner execution: preserve last_scan_id,
    # last_scanned_at and coverage_status, including an existing failed scan.
    db.flush()
    summary = summarize_records(
        stored,
        source_type="system",
        source_id=system.id,
        name=system.name,
        environment=system.environment,
    )
    return {"system": system.to_dict(), "imported": len(stored), "summary": summary,
            "document_sha256": document_sha256, "source_basis": IMPORT_SOURCE_BASIS,
            # What judged the document, and what the judge could not use. A
            # substituted format rule is named here rather than passing silently.
            "validation": {
                "basis": check.get("validation_basis"),
                "format_checks": check.get("format_checks"),
                "warnings": check.get("warnings") or [],
            }}


@router.post("/ingest")
def cbom_ingest(
    body: IngestCbomRequest,
    user: str = Depends(require_cbom_writer),
    db: Session = Depends(get_db_session),
):
    try:
        result = ingest_document(bom=body.bom, db=db, system_name=body.system_name,
                                 owner=body.owner, environment=body.environment, actor=user)
        from db.repositories.user_repository import UserRepository
        UserRepository(db).audit(user, "cbom.ingest", target_type="system", target_id=result["system"]["id"],
                                 detail={"document_sha256": result["document_sha256"], "assets": result["imported"],
                                         "source_basis": IMPORT_SOURCE_BASIS})
        # Commit BEFORE returning success, not in the request-scoped yield
        # dependency teardown, which can run after the response is delivered.
        db.commit()
        return result
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Concurrent inventory update; reload current inventory before retrying") from None
    except SQLAlchemyError:
        db.rollback()
        logger.error("CBOM import database transaction failed; outcome unconfirmed")
        raise HTTPException(status_code=503, detail="Import outcome unconfirmed; reload current inventory before retrying") from None
    except Exception:
        db.rollback()
        raise


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


@router.get("/evidence/{content_hash}")
def cbom_components_for_evidence_hash(
    content_hash: str,
    limit: int = Query(100, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Reverse evidence lookup: which CBOM components cite this hash.

    deep/25 §3.5: the forward direction existed — every generated CBOM
    component carries an evidence block with content_hash/chain_hash —
    but there was no way to start from a hash (e.g. spotted in a
    downloaded BOM) and find the scans/components that cite it. This is
    that query. Retracted (soft-deleted) evidence is excluded: it no
    longer renders as a component. Bounded, with an explicit truncation
    flag.
    """
    from db.models.evidence_record import EvidenceRecord

    cleaned = content_hash.strip().lower()
    if len(cleaned) != 64 or any(c not in "0123456789abcdef" for c in cleaned):
        raise HTTPException(status_code=422, detail="content_hash must be 64 hex characters")

    rows = (
        db.query(EvidenceRecord)
        .filter(EvidenceRecord.content_hash == cleaned)
        .filter(EvidenceRecord.deleted_at.is_(None))
        .order_by(EvidenceRecord.created_at.desc())
        .limit(limit + 1)
        .all()
    )
    truncated = len(rows) > limit
    components = [
        {
            "evidence_id": row.id,
            "scan_id": row.scan_id,
            "cbom_url": f"/api/v1/cbom/scan/{row.scan_id}",
            "algorithm": row.algorithm,
            "key_size": row.key_size,
            "mode": row.mode,
            "padding": row.padding,
            "purpose": row.purpose,
            "file_path": row.file_path,
            "line_number": row.line_number,
            "confidence": row.confidence,
            "compliance_status": row.compliance_status,
            "chain_position": row.chain_position,
            "chain_hash": row.chain_hash,
        }
        for row in rows[:limit]
    ]
    return {
        "content_hash": cleaned,
        "count": len(components),
        "truncated": truncated,
        "components": components,
    }


def _scan_bom(db: Session, scan_id: str) -> tuple[Scan, dict]:
    """The deterministic scan-CBOM rendering shared by the live route and
    snapshot creation — one construction path, so a pinned snapshot is the
    same document a live export would render from the same evidence."""
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
    return scan, bom


@router.get("/scan/{scan_id}")
def cbom_for_scan(
    scan_id: str,
    fmt: str = Query("json"),
    signed: bool | str = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    scan, bom = _scan_bom(db, scan_id)
    return _render(bom, fmt, signed)


def _snapshot_signature_form(signed: bool | str) -> str:
    if not signed:
        return "none"
    if isinstance(signed, str) and signed.lower() == "jsf":
        return "jsf"
    return "jws"


def _snapshot_out(row: CbomSnapshot) -> dict:
    out = row.to_dict()
    out["snapshot_id"] = row.id
    out["verify_path"] = f"/api/v1/cbom/snapshots/{row.id}"
    return out


@router.post("/scan/{scan_id}/snapshot")
def create_scan_snapshot(
    scan_id: str,
    signed: bool | str = False,
    user: str = Depends(require_auditor),
    db: Session = Depends(get_db_session),
):
    """Freeze ONE deterministic rendering of the scan's CBOM (§4.4, round 45).

    The live route regenerates from current evidence on every call; a
    snapshot pins the exact document, content-addressed by SHA-256 over
    its serialization. Identical renderings collapse to one row (idempotent).
    The scan_id keeps the chain snapshot → scan → evidence → hash chain.
    """
    scan, bom = _scan_bom(db, scan_id)
    bom = _apply_signature(bom, signed, fmt="json")
    # anchor the wall-clock to the scan: identical (scan, evidence, signature)
    # must hash identically or content addressing is meaningless
    scan_time = scan.scan_end or scan.created_at
    bom = normalize_for_snapshot(
        bom, scan_timestamp_iso=scan_time.isoformat() if scan_time else None)
    document = CbomGenerator().to_json(bom)
    content_hash = hashlib.sha256(document.encode("utf-8")).hexdigest()
    existing = (
        db.query(CbomSnapshot)
        .filter(CbomSnapshot.scan_id == scan.id,
                CbomSnapshot.content_hash == content_hash)
        .one_or_none()
    )
    if existing is not None:
        out = _snapshot_out(existing)
        out["created"] = False
        out["note"] = ("An identical rendering is already pinned for this scan "
                       "(content-addressed); the existing snapshot is returned.")
        return out
    row = CbomSnapshot(
        scan_id=scan.id,
        content_hash=content_hash,
        format="json",
        signed=_snapshot_signature_form(signed),
        generator="api",
        payload=bom,
        component_count=len(bom.get("components") or []),
        created_by=user,
        snapshotted_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    out = _snapshot_out(row)
    out["created"] = True
    out["note"] = ("Snapshot pinned. GET the verify_path for the exact stored "
                   "document — it is served verbatim, never regenerated.")
    return out


@router.get("/scan/{scan_id}/snapshots")
def list_scan_snapshots(
    scan_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Every pinned snapshot for one scan, newest first."""
    scan = filtered_get(db, Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    rows = (
        db.query(CbomSnapshot)
        .filter(CbomSnapshot.scan_id == scan.id)
        .order_by(CbomSnapshot.created_at.desc())
        .limit(100)
        .all()
    )
    return {
        "scan_id": scan.id,
        "snapshots": [_snapshot_out(r) for r in rows],
        "count": len(rows),
        "note": ("Each snapshot is a pinned rendering; the live route "
                 "regenerates from current evidence and may differ."),
    }


@router.get("/snapshots/{snapshot_id}")
def get_cbom_snapshot(
    snapshot_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Serve the EXACT persisted snapshot document — verbatim, never
    regenerated — with an integrity self-check (recomputed hash over the
    stored payload must equal the pinned content_hash)."""
    row = filtered_get(db, CbomSnapshot, snapshot_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    recomputed = hashlib.sha256(
        CbomGenerator().to_json(row.payload).encode("utf-8")
    ).hexdigest()
    integrity_ok = recomputed == row.content_hash
    out = _snapshot_out(row)
    out["integrity"] = "OK" if integrity_ok else "MISMATCH"
    out["integrity_note"] = (
        "SHA-256 over the stored payload matches the pinned content hash."
        if integrity_ok else
        "Stored payload does NOT match its pinned content hash — the "
        "document was mutated after pinning. Do not trust it."
    )
    out["payload"] = row.payload
    out["scan_verify_path"] = f"/api/v1/scans/{row.scan_id}/verify"
    return out


@router.get("/snapshots/{snapshot_id}/diff")
def diff_cbom_snapshot(
    snapshot_id: str,
    against: str = Query(..., description="snapshot_id of the baseline to diff against"),
    key_by: str = Query("asset_key", pattern="^(asset_key|bom_ref)$",
                        description="asset_key: identity-spine keyed, stable across scans "
                                    "(evidence churn ignored); bom_ref: exact per-scan "
                                    "evidence identity, same-scan mutations visible"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Compare two pinned snapshots (§4.4, round 56).

    ``GET /snapshots/{id}/diff?against={baseline}`` answers the operator's
    question after a re-scan: what changed between the two pins — added
    components (new crypto), removed components (retired findings) and
    field-level drift on survivors (key size, mode, compliance verdict,
    confidence). The diff is computed from the two content-addressed
    payloads on every call, never stored; its trustworthiness is the
    pins'. Same-scan pairs show evidence drift; cross-scan pairs show
    estate drift — both are valid comparisons of the documents.
    """
    target = filtered_get(db, CbomSnapshot, snapshot_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    baseline = filtered_get(db, CbomSnapshot, against)
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline snapshot not found")
    result = diff_snapshots(baseline.payload, target.payload, key_by=key_by)
    return {
        "target": {
            "snapshot_id": target.id,
            "scan_id": target.scan_id,
            "content_hash": target.content_hash,
            "snapshotted_at": target.snapshotted_at.isoformat() if target.snapshotted_at else None,
            "verify_path": f"/api/v1/cbom/snapshots/{target.id}",
        },
        "baseline": {
            "snapshot_id": baseline.id,
            "scan_id": baseline.scan_id,
            "content_hash": baseline.content_hash,
            "snapshotted_at": baseline.snapshotted_at.isoformat() if baseline.snapshotted_at else None,
            "verify_path": f"/api/v1/cbom/snapshots/{baseline.id}",
        },
        "diff": result,
        "note": (
            "Computed from the two pinned payloads (never stored). "
            "'added' = present in the target snapshot only."
        ),
    }


@router.get("/system/{system_id}")
def cbom_for_system(
    system_id: str,
    fmt: str = Query("json"),
    signed: bool | str = False,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from api.routers.cbom_legacy_controlled import retained_system_metadata
    system, assets = _records_for_system(db, system_id)
    records = []
    for asset in assets:
        data = asset.to_dict() if hasattr(asset, "to_dict") else {"algorithm": getattr(asset, "algorithm", "UNKNOWN")}
        data["system_id"] = system.id
        data["system_name"] = system.name
        _attach_business_context(data, system)
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
            *retained_system_metadata(system),
        ],
        scan_id=f"system:{system.id}")
    if fmt == "cyclonedx16":
        # Self-contained native profile: named neighboring systems must be
        # tenant-visible components, not unresolved strings pretending to be
        # external BOM links. Preserve incoming/outgoing edge direction.
        from db.models.system import System
        neighbor_ids = {str(edge[key]) for edge in system_edges for key in ("parent", "child")} - {str(system.id)}
        neighbors = db.query(System).filter(System.id.in_(neighbor_ids)).all() if neighbor_ids else []
        if {str(row.id) for row in neighbors} != neighbor_ids:
            raise HTTPException(status_code=422, detail="System relationships include unavailable context")
        bom["metadata"]["component"]["bom-ref"] = f"system:{system.id}"
        bom["components"] += [{"type": "application", "name": row.name, "bom-ref": f"system:{row.id}"} for row in neighbors]
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
    from api.routers.cbom_legacy import refuse_unreviewed_export
    refuse_unreviewed_export(db, asset_ids=body.asset_ids)
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
    from api.routers.cbom_legacy import refuse_legacy_records
    refuse_legacy_records(records)
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
def _gather_network_inventory(db: Session, *, limit: int = 2000, endpoint_limit: int | None = None, include_coverage: bool = False) -> dict:
    """Build NBOM inputs from real rows: network scan probes + certificates.

    The network scanner already stores each run's probe results in
    ``network_scan_runs.result``; every probe carries the endpoint, the
    negotiated TLS version and cipher suite, and the certificate chain it was
    served. That is exactly an NBOM, so the BOM is derived from the scan rather
    than re-declared by hand.

    Newest run wins per endpoint, so a re-scan supersedes rather than
    duplicates. The probe→endpoint mapping itself lives in
    ``cbom.nbom.probe_to_endpoint`` (round 53) so the API, the cross-BOM
    query and the offline probe script share ONE contract.
    """
    from sqlalchemy import desc, select as _select

    from cbom.nbom import probe_to_endpoint
    from db.models.network_scan_run import NetworkScanRun

    runs = db.execute(
        _select(NetworkScanRun).order_by(desc(NetworkScanRun.created_at), NetworkScanRun.id).limit(limit + 1)
    ).scalars().all()

    endpoints: dict[str, dict] = {}
    endpoints_truncated = False
    for run in runs[:limit]:
        for probe in ((run.result or {}).get("probes") or []):
            raw = str(probe.get("endpoint") or "").strip()
            if not raw or raw in endpoints:
                continue  # first sighting is the newest run
            if endpoint_limit is not None and len(endpoints) >= endpoint_limit:
                endpoints_truncated = True
                break
            endpoints[raw] = {**probe_to_endpoint(probe), "scan_run_id": run.id,
                              "recorded_at": run.created_at.isoformat() if run.created_at else None}
        if endpoints_truncated:
            break
    result = {"endpoints": list(endpoints.values())}
    if include_coverage:
        from shared_models.coverage import collection_read
        result["coverage"] = {"network_scan_runs": collection_read(min(len(runs), limit), limit, more=len(runs) > limit),
            "observed_endpoints": collection_read(len(endpoints), endpoint_limit, more=endpoints_truncated, unit="unique endpoint keys from loaded runs")}
    return result


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

class NbomCoverageRequest(BaseModel):
    groups: list[dict] = Field(default_factory=list, description=(
        "one row per target group: target, expected, attempted, observed, failed, "
        "unauthorized, excluded. An observation above the target count is refused, "
        "because it means the target list is stale"))
    as_of: str | None = Field(None, description="ISO timestamp the matrix describes")
    unit: str = Field("endpoint", description="what is being counted")


class NbomCoverageResponse(BaseModel):
    schema_: str = Field(alias="schema")
    status: str
    coverage_pct: float | None
    totals: dict
    groups: list[dict]
    complete_groups: list[str]
    incomplete_groups: list[str]
    unmeasured_groups: list[str]
    claim: dict
    summary: dict
    statement: str


class NbomProbeCoverageRequest(BaseModel):
    name: str = Field("network", description="the target group this ledger belongs to")
    probes: list[dict] = Field(default_factory=list, description=(
        "stored probe rows: endpoint and status. OK/TLS_OK is observed, "
        "TIMEOUT/REFUSED/ERROR is failed, UNAUTHORIZED is unauthorized, and any other "
        "status is refused rather than bucketed"))
    declared: list[str] = Field(default_factory=list, description=(
        "the target list: a declared endpoint no probe touched becomes unattempted"))


class NbomProbeCoverageResponse(BaseModel):
    row: dict
    refused: list[dict]
    statement: str


#: Reading a coverage matrix is an analysis action, not a dashboard read: it says what
#: the estate's network inventory is allowed to claim, so it takes a role.
NBOM_READERS = require_roles("superadmin", "ciso", "security_analyst", "auditor",
                             "supervisor")


@router.post("/nbom/coverage", response_model=NbomCoverageResponse)
def nbom_coverage(body: NbomCoverageRequest,
                  user: str = Depends(NBOM_READERS)) -> Any:
    """The estate network coverage matrix, and what its numbers may be quoted as.

    10,000 expected endpoints and 6,500 observed is 65% and ``PARTIAL``: the NBOM
    describes what was observed, not what exists. ``TOTAL`` is available only when
    every target group is ``COMPLETE``; otherwise the block says ``FLOOR`` and names
    the never-attempted, unauthorized and failed counts.
    """
    from cbom import nbom_coverage as nc

    try:
        block = nc.matrix(body.groups, as_of=body.as_of, unit=body.unit)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {**block, "summary": nc.summary(block)}


@router.post("/nbom/coverage/from-probes", response_model=NbomProbeCoverageResponse)
def nbom_coverage_from_probes(body: NbomProbeCoverageRequest,
                              user: str = Depends(NBOM_READERS)) -> Any:
    """One coverage row from the stored probe ledger, refusals included.

    A timeout is a failure, never an observation; an undocumented status is refused
    instead of being bucketed; and a declared endpoint no probe reached is the gap a
    bare probe count hides.
    """
    from cbom import nbom_coverage as nc

    try:
        return nc.from_probes(body.name, body.probes, declared=body.declared)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))


from api.routers.cbom_legacy import register_legacy_routes
register_legacy_routes(router, require_cbom_writer)

from api.routers.cbom_legacy_controlled import register_controlled_routes
register_controlled_routes(router)

from api.routers.cbom_rescan_inspection import register_rescan_routes
register_rescan_routes(router)
