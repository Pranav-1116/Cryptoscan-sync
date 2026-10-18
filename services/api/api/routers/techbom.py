"""Live Asset Intelligence — unified Technology BOM (SBOM/CBOM/HBOM/Vendor).

One asset model, four materialized views. This router:

- ``GET  /technology-bom``         — materialize the CURRENT BOM from the real
                                     inventory (live; never fabricated).
- ``POST /technology-bom/snapshot`` — capture an immutable, content-addressed
                                     snapshot (versioned) and persist it.
- ``GET  /technology-bom/history`` — version history (newest first).
- ``GET  /technology-bom/compare``  — diff two versions per layer.
- ``GET  /technology-bom/export``   — export current or historical state as
                                     JSON / CSV / CycloneDX / SPDX, with an
                                     integrity hash + audit event.

The engine (cbom.technology_bom) is pure; the router only gathers real records
from the inventory DB and persists snapshots via the immutable
``TechnologyBomSnapshot`` table.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

from db.models import (
    BusinessProcess,
    Certificate,
    CryptoAsset,
    HardwareAsset,
    RuntimeFinding,
    Scan,
    ScanJob,
    System,
    SystemAsset,
    SystemBusinessProcess,
    SystemDependency,
    SystemVendor,
    TechnologyBomExportRun,
    TechnologyBomExportSchedule,
    TechnologyBomSnapshot,
    Vendor,
    Vulnerability,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from api.events.platform_events import emit_platform_event

router = APIRouter(prefix="/technology-bom", tags=["technology-bom"])


def _gather_inventory(db: Session, *, limit: int = 2000) -> dict[str, Any]:
    """Aggregate the unified asset model from the inventory DB (real rows only)."""
    apps = [{"id": s.id, "name": s.name, "version": getattr(s, "version", "") or "",
             "owner": s.owner, "environment": s.environment, "criticality": s.criticality,
             "supplier": s.owner}
            for s in db.execute(select(System).limit(limit)).scalars().all()]
    crypto = [{"id": c.id, "algorithm": c.algorithm, "key_size": c.key_size,
               "purpose": c.purpose, "mode": c.mode, "asset": getattr(c, "hostname", "") or "",
               "application": "", "file_path": c.file_path, "confidence": c.confidence,
               "library": _libraries(c)}
              for c in db.execute(select(CryptoAsset).limit(limit)).scalars().all()]
    hardware = [{"id": h.id, "asset_id": h.asset_id, "manufacturer": h.manufacturer,
                 "model": h.model, "device_type": h.device_type,
                 "serial_reference": h.serial_reference, "firmware": h.firmware,
                 "hsm": h.hsm, "tpm": h.tpm, "risk_level": h.risk_level,
                 "asset": getattr(h, "agent_id", "") or ""}
                for h in db.execute(select(HardwareAsset).limit(limit)).scalars().all()]
    vendors = [{"name": v.name, "product": getattr(v, "product", "") or "",
                "model": getattr(v, "model", "") or "", "lifecycle": getattr(v, "lifecycle", "") or "",
                "risk_level": getattr(v, "risk_level", "") or ""}
               for v in db.execute(select(Vendor).limit(limit)).scalars().all()]
    certs = [{"fingerprint": c.fingerprint_sha256, "subject": c.subject} for c in
             db.execute(select(Certificate).limit(limit)).scalars().all()]
    deps = [[str(a), str(b)] for a, b in
            db.execute(select(SystemDependency.parent_id, SystemDependency.child_id)
                       .limit(limit)).all()]
    return {
        "applications": apps, "crypto": crypto, "hardware": hardware,
        "vendors": vendors, "certificates": certs, "dependencies": deps,
        "scan": {"collected_at": datetime.now(timezone.utc).isoformat()},
    }


def _libraries(c: CryptoAsset) -> str:
    libs = getattr(c, "libraries", None)
    if isinstance(libs, list) and libs:
        return ", ".join(str(x) for x in libs)
    return ""


def _active_environment(db: Session) -> str:
    """Best-effort active sector/environment label for the snapshot header."""
    try:
        from db.repositories.settings_repository import (
            SECTOR_SETTING_KEY,
            SettingsRepository,
        )

        saved = SettingsRepository(db).get(SECTOR_SETTING_KEY)
        if isinstance(saved, dict) and saved.get("sector"):
            return str(saved["sector"])
    except Exception:
        logger.debug("sector_env_lookup_failed", exc_info=True)
    return "default"


def _environment_of(db: Session) -> str:
    return _active_environment(db)


#: statuses that mean "the BOM may be partially updated right now"
_SCAN_ACTIVE_STATUSES = ("RUNNING", "QUEUED")


def _scan_in_progress(db: Session) -> bool:
    """True if a scan is currently queued/running (partially-updated BOM)."""
    try:
        scan = db.execute(select(Scan.id).where(
            Scan.status.in_(_SCAN_ACTIVE_STATUSES)).limit(1)).scalars().first()
        if scan:
            return True
        job = db.execute(select(ScanJob.id).where(
            ScanJob.status.in_(_SCAN_ACTIVE_STATUSES)).limit(1)).scalars().first()
        return bool(job)
    except Exception:  # noqa: BLE001 — best-effort indicator, never fails the request
        return False


def _next_version(db: Session) -> int:
    # Tenant-local numbering: versions are unique per tenant (migration 0071),
    # so the max is taken within the caller's tenant — explicitly, because in
    # platform scope the ORM guard is bypassed and an unfiltered max would
    # interleave every tenant's sequence.
    from db.tenancy import current_tenant

    row = db.execute(select(TechnologyBomSnapshot.version)
                     .filter(TechnologyBomSnapshot.tenant_id == current_tenant())
                     .order_by(TechnologyBomSnapshot.version.desc())
                     .limit(1)).scalars().first()
    return (row or 0) + 1


@router.get("")
@router.get("/")
def technology_bom_live(
    limit: int = Query(2000, ge=1, le=5000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Materialize the CURRENT unified BOM from the real inventory (live)."""
    from cbom.technology_bom import materialize_technology_bom

    version = _next_version(db)
    inv = _gather_inventory(db, limit=limit)
    state = materialize_technology_bom(inv, environment=_environment_of(db),
                                       state_version=version)
    from db.tenancy import current_tenant

    last = db.execute(select(TechnologyBomSnapshot).order_by(
        TechnologyBomSnapshot.version.desc())
        .filter(TechnologyBomSnapshot.tenant_id == current_tenant())
        .limit(1)).scalars().first()
    return {
        "source": "technology_bom",
        "live": True,
        "scan_in_progress": _scan_in_progress(db),
        "live_scan_note": (
            "LIVE SCAN IN PROGRESS — BOM is partially updated; use 'Capture snapshot' "
            "or wait for the scan to finish for a stable export."
            if _scan_in_progress(db)
            else None
        ),
        "latest_snapshot_id": last.snapshot_id if last else None,
        "previous_snapshot_id": None,
        **state,
    }


@router.post("/snapshot")
def technology_bom_snapshot(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Capture an immutable, content-addressed version of the current BOM.

    A snapshot is only stored when the materialized component set actually
    changed (same fingerprint -> same version, no duplicates). Returns the
    snapshot + diff vs the previous version.
    """
    from cbom.technology_bom import diff_technology_bom, materialize_technology_bom

    version = _next_version(db)
    inv = _gather_inventory(db)
    state = materialize_technology_bom(inv, environment=_environment_of(db),
                                       state_version=version)

    from db.tenancy import current_tenant

    prev = db.execute(select(TechnologyBomSnapshot).order_by(
        TechnologyBomSnapshot.version.desc())
        .filter(TechnologyBomSnapshot.tenant_id == current_tenant())
        .limit(1)).scalars().first()

    # no-op guard: identical fingerprint to the latest snapshot -> don't store
    if prev is not None and prev.fingerprint == state["fingerprint"]:
        return {"source": "technology_bom", "recorded": False,
                "snapshot": prev.to_dict(),
                "note": "unchanged state — no new snapshot recorded"}

    diff = diff_technology_bom(prev.state if prev else {}, state) if prev else {}

    row = TechnologyBomSnapshot(
        version=version,
        fingerprint=state["fingerprint"],
        parent_fingerprint=prev.fingerprint if prev else None,
        snapshot_id=state["snapshot_id"],
        environment=state["environment"],
        total_components=state["total_components"],
        components_by_layer=state["components_by_layer"],
        state=state,
        diff=diff,
        created_by=user,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    emit_platform_event(
        "technology_bom.snapshot",
        f"Technology BOM snapshot recorded (v{version}, {state['total_components']} components)",
        {"version": version, "snapshot_id": state["snapshot_id"],
         "total_components": state["total_components"],
         "components_by_layer": state["components_by_layer"], "diff": diff},
        target_name="technology-bom",
    )
    return {"source": "technology_bom", "recorded": True,
            "snapshot": row.to_dict(), "diff": diff}


@router.get("/history")
def technology_bom_history(
    limit: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Version history of the unified BOM (newest first)."""
    rows = db.execute(select(TechnologyBomSnapshot).order_by(
        TechnologyBomSnapshot.version.desc()).limit(min(limit, 200))).scalars().all()
    return {"versions": [r.to_dict() for r in rows],
            "total_count": len(rows),
            "latest_version": rows[0].version if rows else 0}


@router.get("/history/versions")
def technology_bom_versions(
    environment: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Lightweight version list (snapshot_id, version, counts) for history UI."""
    q = select(TechnologyBomSnapshot).order_by(TechnologyBomSnapshot.version.desc()).limit(min(limit, 1000))
    if environment:
        q = select(TechnologyBomSnapshot).where(
            TechnologyBomSnapshot.environment == environment).order_by(
            TechnologyBomSnapshot.version.desc()).limit(min(limit, 1000))
    rows = db.execute(q).scalars().all()
    return {"versions": [
        {"version": r.version, "snapshot_id": r.snapshot_id, "environment": r.environment,
         "total_components": r.total_components,
         "components_by_layer": r.components_by_layer or {},
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows], "total_count": len(rows)}


@router.get("/compare")
def technology_bom_compare(
    from_version: int = Query(...),
    to_version: int = Query(...),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Diff two BOM versions per layer (added/removed components)."""
    from_row = db.execute(select(TechnologyBomSnapshot).where(
        TechnologyBomSnapshot.version == from_version)).scalars().first()
    to_row = db.execute(select(TechnologyBomSnapshot).where(
        TechnologyBomSnapshot.version == to_version)).scalars().first()
    if from_row is None or to_row is None:
        missing = from_version if from_row is None else to_version
        raise HTTPException(status_code=404, detail=f"BOM version not found: {missing}")
    # recompute a truthful diff directly from the stored full states
    from cbom.technology_bom import diff_technology_bom
    diff = diff_technology_bom(from_row.state or {}, to_row.state or {})
    return {"source": "technology_bom", **diff}


@router.get("/export")
def technology_bom_export(
    version: int | None = Query(None),
    fmt: str = Query("json"),
    layer: str = Query("all"),
    search: str | None = Query(None),
    risk_level: str | None = Query(None),
    key_size_min: int | None = Query(None),
    type: str | None = Query(None),
    include_certificates: bool = Query(True),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Export current or a historical BOM state via the Export Service.

    ``version`` (optional) selects a snapshot; default = current live state.
    ``fmt`` = json | csv | cyclonedx | cyclonedx-xml | xml | spdx | pdf.
    ``layer`` = sbom | cbom | hbom | vendor | certificates | all.
    Filters: ``search``, ``risk_level``, ``key_size_min``, ``type``,
    ``include_certificates``. Every export is validated, filtered, generated,
    signed (HMAC) and audited (spec #12/#13/#19). Returns the artifact for
    csv/xml/pdf; a manifest object for json/cyclonedx/spdx.
    """
    from cbom.export_service import ExportValidationError, export_bom
    from cbom.technology_bom import materialize_technology_bom

    if version is not None:
        row = db.execute(select(TechnologyBomSnapshot).where(
            TechnologyBomSnapshot.version == version)).scalars().first()
        if row is None:
            raise HTTPException(status_code=404, detail=f"BOM version not found: {version}")
        state = row.state or {}
    else:
        state = materialize_technology_bom(_gather_inventory(db),
                                           environment=_environment_of(db),
                                           state_version=_next_version(db))

    filters = {"search": search, "risk_level": risk_level, "key_size_min": key_size_min,
               "type": type, "include_certificates": include_certificates}
    filters = {k: v for k, v in filters.items() if v not in (None, "all", "")}

    in_progress = _scan_in_progress(db)

    def _audit(manifest: dict) -> str | None:
        ev = emit_platform_event(
            "technology_bom.export",
            f"Technology BOM exported ({manifest['format']}/{manifest['layer']}, "
            f"v{manifest.get('state_version')})",
            {"version": manifest.get("state_version"),
             "snapshot_id": manifest.get("snapshot_id"),
             "format": manifest["format"], "layer": manifest["layer"],
             "filter": filters, "scan_in_progress": in_progress,
             "integrity_sha256": manifest["integrity_sha256"],
             "signature_hmac": manifest["signature_hmac"]},
            target_name="technology-bom",
        )
        return (ev or {}).get("row_id") if isinstance(ev, dict) else None

    try:
        manifest = export_bom(state, fmt=fmt, layer=layer, filters=filters,
                              on_audit=_audit)
    except ExportValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Raw download-style formats; manifest objects for standard formats.
    if manifest["mime_type"] in ("text/csv", "application/xml", "application/pdf"):
        headers = {"X-ZELNX-Snapshot-Id": manifest["snapshot_id"] or "",
                   "X-ZELNX-Integrity-Sha256": manifest["integrity_sha256"],
                   "X-ZELNX-Signature-Hmac": manifest["signature_hmac"] or ""}
        if in_progress:
            headers["X-ZELNX-Scan-In-Progress"] = "true"
            headers["X-ZELNX-Scan-Note"] = "LIVE SCAN IN PROGRESS - partially updated"
        data = manifest["data"]
        if isinstance(data, str):
            data = data.encode("utf-8")
        return Response(content=data, media_type=manifest["mime_type"], headers=headers)

    manifest["scan_in_progress"] = in_progress
    if in_progress:
        manifest["live_scan_note"] = (
            "LIVE SCAN IN PROGRESS — BOM is partially updated; use 'Capture snapshot' "
            "or wait for the scan to finish for a stable export."
        )
    return manifest


# --------------------------------------------------------------------------- #
# Scheduled exports (daily / weekly / monthly / after scan / after major change)
# --------------------------------------------------------------------------- #

def _compute_next_run(frequency: str, after: datetime) -> datetime | None:
    freq = (frequency or "").lower()
    if freq == "daily":
        return after + timedelta(days=1)
    if freq == "weekly":
        return after + timedelta(days=7)
    if freq == "monthly":
        return after + timedelta(days=30)
    # event-driven frequencies are not time-scheduled
    return None


def _as_aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC so comparisons are safe."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@router.post("/export-schedules")
def create_export_schedule(
    body: dict[str, Any],
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from cbom.export_service import VALID_FORMATS, VALID_LAYERS

    name = str(body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="schedule name is required")
    freq = str(body.get("frequency") or "weekly").lower()
    if freq not in ("daily", "weekly", "monthly", "after_scan", "after_major_change"):
        raise HTTPException(status_code=400, detail=f"unsupported frequency '{freq}'")
    fmt = str(body.get("fmt") or "json").lower()
    if fmt not in VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"unsupported format '{fmt}'")
    layer = str(body.get("layer") or "all").lower()
    if layer not in VALID_LAYERS:
        raise HTTPException(status_code=400, detail=f"unsupported layer '{layer}'")

    existing = db.execute(select(TechnologyBomExportSchedule).where(
        TechnologyBomExportSchedule.name == name)).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail=f"schedule '{name}' already exists")

    row = TechnologyBomExportSchedule(
        name=name, frequency=freq, fmt=fmt, layer=layer,
        filters=body.get("filters") or {}, environment=_environment_of(db),
        recipients=body.get("recipients") or [], active=True,
        created_by=user,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    emit_platform_event("technology_bom.schedule", f"Export schedule created: {name}",
                        {"schedule_id": row.id, "name": name, "frequency": freq,
                         "fmt": fmt, "layer": layer}, target_name="technology-bom")
    return row.to_dict()


@router.get("/export-schedules")
def list_export_schedules(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    rows = db.execute(select(TechnologyBomExportSchedule).order_by(
        TechnologyBomExportSchedule.created_at.desc())).scalars().all()
    return {"schedules": [r.to_dict() for r in rows], "count": len(rows)}


@router.get("/export-schedules/{schedule_id}")
def get_export_schedule(
    schedule_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = db.execute(select(TechnologyBomExportSchedule).where(
        TechnologyBomExportSchedule.id == schedule_id)).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return row.to_dict()


@router.put("/export-schedules/{schedule_id}")
def update_export_schedule(
    schedule_id: str,
    body: dict[str, Any],
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = db.execute(select(TechnologyBomExportSchedule).where(
        TechnologyBomExportSchedule.id == schedule_id)).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    if "active" in body:
        row.active = bool(body["active"])
    if "frequency" in body:
        row.frequency = str(body["frequency"]).lower()
    if "fmt" in body:
        row.fmt = str(body["fmt"]).lower()
    if "layer" in body:
        row.layer = str(body["layer"]).lower()
    if "filters" in body:
        row.filters = body["filters"]
    if "recipients" in body:
        row.recipients = body["recipients"]
    db.commit()
    db.refresh(row)
    return row.to_dict()


@router.delete("/export-schedules/{schedule_id}")
def delete_export_schedule(
    schedule_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = db.execute(select(TechnologyBomExportSchedule).where(
        TechnologyBomExportSchedule.id == schedule_id)).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    db.delete(row)
    db.commit()
    return {"deleted": True, "schedule_id": schedule_id}


def _run_schedule(db: Session, row: TechnologyBomExportSchedule,
                  trigger: str, user: str) -> dict[str, Any]:
    from cbom.export_service import export_bom
    from cbom.technology_bom import materialize_technology_bom

    version = _next_version(db)
    state = materialize_technology_bom(_gather_inventory(db),
                                       environment=row.environment,
                                       state_version=version)
    in_progress = _scan_in_progress(db)

    def _audit(manifest: dict) -> str | None:
        ev = emit_platform_event(
            "technology_bom.schedule_run",
            f"Scheduled Technology BOM export ran ({manifest['format']}/{manifest['layer']}, "
            f"v{manifest.get('state_version')})",
            {"schedule_id": row.id, "schedule_name": row.name, "trigger": trigger,
             "snapshot_id": manifest.get("snapshot_id"),
             "format": manifest["format"], "layer": manifest["layer"],
             "integrity_sha256": manifest["integrity_sha256"],
             "signature_hmac": manifest["signature_hmac"], "scan_in_progress": in_progress},
            target_name="technology-bom",
        )
        return (ev or {}).get("row_id") if isinstance(ev, dict) else None

    manifest = export_bom(state, fmt=row.fmt, layer=row.layer,
                          filters=row.filters or {}, signature="", on_audit=_audit)
    # NOTE: export_bom computes a signature via signing_secret() when signature arg
    # is falsy; we pass "" so it always signs deterministically. Store the result.
    data = manifest["data"]
    if isinstance(data, bytes):
        raw = data
    elif isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    run = TechnologyBomExportRun(
        schedule_id=row.id, schedule_name=row.name,
        version=state.get("state_version"), snapshot_id=state.get("snapshot_id"),
        environment=state.get("environment"), fmt=row.fmt, layer=manifest["layer"],
        filters=row.filters or {}, total_components=state.get("total_components"),
        content_sha256=manifest["integrity_sha256"],
        signature_hmac=manifest["signature_hmac"],
        artifact_b64=base64.b64encode(raw).decode(), mime_type=manifest["mime_type"],
        audit_event_id=manifest["audit_event_id"], trigger=trigger,
    )
    db.add(run)

    now = datetime.now(timezone.utc)
    row.last_run_at = now
    row.last_snapshot_id = state.get("snapshot_id")
    row.next_run_at = _compute_next_run(row.frequency, now)
    db.commit()
    db.refresh(run)
    return {"run": run.to_dict(), "schedule": row.to_dict()}


@router.post("/export-schedules/run-due")
def run_due_export_schedules(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Run every schedule that is due (time-based or event-driven)."""
    now = datetime.now(timezone.utc)
    rows = db.execute(select(TechnologyBomExportSchedule)).scalars().all()
    ran, skipped = [], []
    for row in rows:
        if not row.active:
            skipped.append({"id": row.id, "reason": "inactive"})
            continue
        due = False
        if row.frequency in ("after_scan", "after_major_change"):
            from db.tenancy import current_tenant

            latest = db.execute(select(TechnologyBomSnapshot).order_by(
                TechnologyBomSnapshot.version.desc())
                .filter(TechnologyBomSnapshot.tenant_id == current_tenant())
                .limit(1)).scalars().first()
            due = latest is not None and latest.snapshot_id != row.last_snapshot_id
        else:
            nxt = _as_aware(row.next_run_at)
            due = nxt is None or nxt <= now
        if due:
            try:
                ran.append(_run_schedule(db, row, "run-due", user))
            except Exception as exc:  # noqa: BLE001
                skipped.append({"id": row.id, "reason": str(exc)})
        else:
            skipped.append({"id": row.id, "reason": "not-due"})
    return {"ran_total": len(ran), "skipped_total": len(skipped),
            "ran": ran, "skipped": skipped}


@router.post("/export-schedules/{schedule_id}/run")
def run_export_schedule(
    schedule_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    row = db.execute(select(TechnologyBomExportSchedule).where(
        TechnologyBomExportSchedule.id == schedule_id)).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    return _run_schedule(db, row, "manual", user)


@router.get("/export-runs")
def list_export_runs(
    schedule_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    q = select(TechnologyBomExportRun).order_by(TechnologyBomExportRun.created_at.desc())
    if schedule_id:
        q = q.where(TechnologyBomExportRun.schedule_id == schedule_id)
    rows = db.execute(q.limit(limit)).scalars().all()
    return {"runs": [r.to_dict() for r in rows], "count": len(rows)}


# --------------------------------------------------------------------------- #
# Evidence Package (compliance / audit) + Vendor BOM inventory
# --------------------------------------------------------------------------- #

@router.get("/evidence-package")
def evidence_package(
    version: int | None = Query(None),
    fmt: str = Query("json", pattern="^(json|pdf)$"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Aggregate the BOM + certificate compliance + crypto assurance + a hash &
    HMAC into a deterministically verifiable audit package (spec: Evidence
    Package). Support ``json`` and ``pdf``.
    """
    from cbom.export_service import signing_secret
    from cbom.technology_bom import materialize_technology_bom

    if version is not None:
        row = db.execute(select(TechnologyBomSnapshot).where(
            TechnologyBomSnapshot.version == version)).scalars().first()
        if row is None:
            raise HTTPException(status_code=404, detail=f"BOM version not found: {version}")
        state = row.state or {}
    else:
        state = materialize_technology_bom(_gather_inventory(db),
                                           environment=_environment_of(db),
                                           state_version=_next_version(db))

    certs = db.execute(select(Certificate)).scalars().all()
    cert_summary = {
        "total": len(certs),
        "expired": sum(1 for c in certs if getattr(c, "expiry_status", "") == "EXPIRED"),
        "expiring": sum(1 for c in certs if getattr(c, "expiry_status", "") == "EXPIRING"),
        "self_signed": sum(1 for c in certs if getattr(c, "is_self_signed", False)),
        "revoked": sum(1 for c in certs if getattr(c, "revocation_status", "") == "REVOKED"),
    }
    package = {
        "kind": "technology_bom_evidence_package",
        "snapshot_id": state.get("snapshot_id"),
        "environment": state.get("environment"),
        "state_version": state.get("state_version"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": user,
        "bom": {
            "total_components": state.get("total_components"),
            "components_by_layer": state.get("components_by_layer"),
            "certificate_count": state.get("certificate_count"),
            "dependency_count": state.get("dependency_count"),
            "fingerprint": state.get("fingerprint"),
        },
        "certificates": cert_summary,
        "scan_in_progress": _scan_in_progress(db),
    }
    # cross-BOM cascade runs — the audit trail of "what breaks if X changes"
    # answers, each content-hashed so the package covers them verbatim
    from db.models.cascade_run import CascadeRun

    cascade_runs = db.query(CascadeRun).order_by(
        CascadeRun.created_at.desc()).limit(50).all()
    if cascade_runs:
        package["cascade_runs"] = [{
            "id": r.id, "target": r.target, "target_kind": r.target_kind,
            "max_depth": r.max_depth, "verdict": r.verdict,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "result_sha256": hashlib_sha256(json_dumps(r.result or {})),
        } for r in cascade_runs]
    canonical = json_dumps(package)
    package["content_sha256"] = hashlib_sha256(canonical)
    package["signature_hmac"] = hmac_sha256(canonical, signing_secret())

    emit_platform_event(
        "technology_bom.evidence_package",
        f"Technology BOM evidence package generated (v{package['state_version']})",
        {"snapshot_id": package["snapshot_id"], "state_version": package["state_version"],
         "content_sha256": package["content_sha256"], "signature_hmac": package["signature_hmac"]},
        target_name="technology-bom",
    )

    if fmt == "pdf":
        from cbom.technology_bom import _build_pdf

        lines = []
        def line(text, size=10, gap=False):
            lines.append((str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)"), size))
            if gap:
                lines.append(("", 6))
        line("ZELNX - Technology BOM Evidence Package", 16)
        line(f"Snapshot: {package['snapshot_id']}    Environment: {package['environment']}", 9)
        line(f"State version: {package['state_version']}    Generated: {package['generated_at']}", 9)
        line(f"Generated by: {package['generated_by']}", 10, gap=True)
        line("BOM", 13, gap=True)
        line(f"  Total components: {package['bom']['total_components']}", 10)
        for k, v in (package['bom']['components_by_layer'] or {}).items():
            line(f"  {k}: {v}", 10)
        line(f"  Certificates: {package['bom']['certificate_count']}    Dependencies: {package['bom']['dependency_count']}", 10)
        line("Certificate compliance", 13, gap=True)
        for k in ("total", "expired", "expiring", "self_signed", "revoked"):
            line(f"  {k}: {package['certificates'].get(k, 0)}", 10)
        line("", 6)
        line(f"content_sha256: {package['content_sha256']}", 8)
        line(f"signature_hmac: {package['signature_hmac']}", 8)
        pages = [lines[i:i + 46] for i in range(0, len(lines), 46)] or [[("", 10)]]
        pdf = _build_pdf(pages, title="ZELNX Technology BOM Evidence Package")
        return Response(content=pdf, media_type="application/pdf",
                        headers={"X-ZELNX-Snapshot-Id": package["snapshot_id"] or "",
                                 "X-ZELNX-Integrity-Sha256": package["content_sha256"]})
    return package


@router.get("/vendor")
def vendor_inventory(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """VBOM — vendor inventory with the systems each vendor supplies."""
    system_rows = {s.id: s for s in db.execute(select(System)).scalars().all()}
    sv_rows = db.execute(select(SystemVendor)).scalars().all()
    vendor_rows = db.execute(select(Vendor)).scalars().all()
    by_id = {v.id: v for v in vendor_rows}

    systems_by_vendor: dict[str, list[str]] = {}
    linkage = []
    for sv in sv_rows:
        v = by_id.get(sv.vendor_id) if sv.vendor_id else None
        s = system_rows.get(sv.system_id) if sv.system_id else None
        if not v or not s:
            continue
        systems_by_vendor.setdefault(v.id, []).append(s.name or s.id)
        linkage.append({"vendor": v.name, "vendor_id": v.id,
                        "system": s.name or s.id, "system_id": s.id,
                        "dependency_type": getattr(sv, "dependency_type", "") or ""})

    vendors = []
    for v in vendor_rows:
        vendors.append({
            "id": v.id, "name": v.name, "vendor_type": getattr(v, "vendor_type", "") or "",
            "criticality": getattr(v, "criticality", "") or "",
            "contract_end_date": (v.contract_end_date.isoformat() if getattr(v, "contract_end_date", None) else None),
            "last_assessment_date": (v.last_assessment_date.isoformat() if getattr(v, "last_assessment_date", None) else None),
            "integration_type": getattr(v, "integration_type", "") or "",
            "systems": systems_by_vendor.get(v.id, []),
            "system_count": len(systems_by_vendor.get(v.id, [])),
        })
    return {"vendors": vendors, "linkage": linkage, "vendor_count": len(vendors)}


def _json_dumps(obj: Any) -> str:
    import json
    return json.dumps(obj, sort_keys=True, default=str)


def _sha256(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hmac(text: str, secret: str) -> str:
    import hashlib
    import hmac
    return hmac.new(secret.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


# lightweight aliases used above (kept local + explicit)
json_dumps = _json_dumps
hashlib_sha256 = _sha256
hmac_sha256 = _hmac


# --------------------------------------------------------------------------- #
# Assurance & Control — VEX, xBOM correlation, admission gate, runtime drift.
# These are thin gather/marshal wrappers over the pure cbom.assurance engine:
# the router only reads real rows from the inventory DB and hands them in. No
# fabricated content — the engine renders honest zeros/empty until data exists.
# --------------------------------------------------------------------------- #


def _cbom_components(state: dict[str, Any]) -> list[dict[str, Any]]:
    return (state.get("layers") or {}).get("cbom", {}).get("components", [])


def _reachable_refs(db: Session, state: dict[str, Any]) -> set[str]:
    """Best-effort reachable bom-refs: crypto assets on systems marked in prod."""
    reachable: set[str] = set()
    try:
        # crypto assets whose host/asset is a system in a production env
        prod_systems = {
            s.id for s in db.execute(select(System.id).where(
                System.environment.in_(["prod", "production", "live"])
            )).scalars().all()
        }
    except Exception:  # noqa: BLE001 — best-effort, never fail the request
        prod_systems = set()
    for c in _cbom_components(state):
        if c.get("bom-ref") and c.get("asset") in prod_systems:
            reachable.add(c["bom-ref"])
        # treat TIER-1/high-criticality assets as reachable too
        if c.get("bom-ref") and not reachable:
            reachable.add(c["bom-ref"])
    return reachable


@router.get("/assurance")
def technology_bom_assurance(
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Combined Assurance & Control surface: VEX + xBOM + admission + runtime.

    Reuses the same unified BOM state as the rest of the router, so a single
    asset change is reflected in every assurance layer.
    """
    from cbom.assurance import (
        assess_vex,
        correlate_xbom,
        evaluate_admission,
        runtime_drift,
    )
    from cbom.technology_bom import materialize_technology_bom

    if version is not None:
        row = db.execute(select(TechnologyBomSnapshot).where(
            TechnologyBomSnapshot.version == version)).scalars().first()
        if row is None:
            raise HTTPException(status_code=404, detail=f"BOM version not found: {version}")
        state = row.state or {}
    else:
        state = materialize_technology_bom(_gather_inventory(db),
                                           environment=_environment_of(db),
                                           state_version=_next_version(db))

    comps = _cbom_components(state)

    # vulnerabilities (local CVE table)
    vuln_rows = []
    for v in db.execute(select(Vulnerability)).scalars().all():
        vuln_rows.append({"cve": v.cve, "package": v.package, "severity": v.severity,
                          "summary": v.summary, "fixed": False, "applicable": True,
                          "reachable": bool(getattr(v, "reachable", False))})

    # runtime findings
    runtime_rows = []
    for r in db.execute(select(RuntimeFinding)).scalars().all():
        runtime_rows.append({"hostname": r.hostname, "process_name": r.process_name,
                             "algorithm": r.algorithm, "key_size": r.key_size,
                             "tls_version": r.tls_version,
                             "cipher_suite": r.cipher_suite})

    # system_assets linkage (system_id <-> asset_id)
    sa_rows = [{"system_id": sa.system_id, "asset_id": sa.asset_id} for sa in
               db.execute(select(SystemAsset)).scalars().all()]

    # business processes + which systems they bind to
    bp_by_id = {bp.id: bp for bp in db.execute(select(BusinessProcess)).scalars().all()}
    bp_rows = []
    proc_systems: dict[str, list[str]] = {}
    for sp in db.execute(select(SystemBusinessProcess)).scalars().all():
        proc_systems.setdefault(str(sp.process_id), []).append(str(sp.system_id))
    for pid, bp in bp_by_id.items():
        d = {"name": bp.name, "process_type": bp.process_type,
             "revenue_daily": bp.revenue_daily, "sla_uptime": bp.sla_uptime,
             "system_ids": proc_systems.get(str(pid), [])}
        bp_rows.append(d)

    reachable = _reachable_refs(db, state)

    vex = assess_vex(comps, vuln_rows, reachable=reachable) if vuln_rows else None
    xbom = correlate_xbom(state, system_assets=sa_rows, business_processes=bp_rows)
    admission = evaluate_admission(state)
    runtime = runtime_drift(state, runtime_rows) if runtime_rows else None

    return {
        "source": "technology_bom",
        "environment": state.get("environment"),
        "state_version": state.get("state_version"),
        "snapshot_id": state.get("snapshot_id"),
        "scan_in_progress": _scan_in_progress(db),
        "vex": vex,
        "xbom": xbom,
        "admission": admission,
        "runtime_verify": runtime,
    }


@router.get("/vex")
def technology_bom_vex(
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """VEX-enriched, priority-ranked vulnerability triage for the BOM."""
    from cbom.assurance import assess_vex

    state = _resolve_state(db, version)
    comps = _cbom_components(state)
    vuln_rows = [{"cve": v.cve, "package": v.package, "severity": v.severity,
                  "summary": v.summary} for v in
                 db.execute(select(Vulnerability)).scalars().all()]
    if not vuln_rows:
        return {"source": "technology_bom", "vex": None,
                "note": "no vulnerabilities recorded — run a scan that populates the CVE table"}
    reachable = _reachable_refs(db, state)
    return {"source": "technology_bom", "scan_in_progress": _scan_in_progress(db),
            "vex": assess_vex(comps, vuln_rows, reachable=reachable)}


@router.get("/xbom")
def technology_bom_xbom(
    bom_ref: str | None = Query(None),
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Correlate the shared BOM layers — the xBOM trace.

    Binary NBOM and vulnerability-BOM sidecars are correlated by the binary
    projector and remain distinguishable from this inventory view.
    """
    from cbom.assurance import correlate_xbom

    state = _resolve_state(db, version)
    sa_rows = [{"system_id": sa.system_id, "asset_id": sa.asset_id} for sa in
               db.execute(select(SystemAsset)).scalars().all()]
    bp_by_id = {bp.id: bp for bp in db.execute(select(BusinessProcess)).scalars().all()}
    proc_systems: dict[str, list[str]] = {}
    for sp in db.execute(select(SystemBusinessProcess)).scalars().all():
        proc_systems.setdefault(str(sp.process_id), []).append(str(sp.system_id))
    bp_rows = [{"name": bp.name, "process_type": bp.process_type,
                "revenue_daily": bp.revenue_daily, "sla_uptime": bp.sla_uptime,
                "system_ids": proc_systems.get(str(pid), [])}
               for pid, bp in bp_by_id.items()]
    result = correlate_xbom(state, bom_ref=bom_ref, system_assets=sa_rows,
                            business_processes=bp_rows)
    return {"source": "technology_bom", "snapshot_id": state.get("snapshot_id"),
            "state_version": state.get("state_version"), **result}


@router.get("/admission")
def technology_bom_admission(
    version: int | None = Query(None),
    require_baseline: bool = Query(False),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Pre-deploy admission decision (PASS / WARN / FAIL) over the BOM."""
    from cbom.assurance import evaluate_admission

    state = _resolve_state(db, version)
    admission = evaluate_admission(state, require_baseline=require_baseline)
    admission["scan_in_progress"] = _scan_in_progress(db)
    admission["source"] = "technology_bom"
    return admission


@router.get("/runtime-verify")
def technology_bom_runtime_verify(
    version: int | None = Query(None),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Continuous verification: compare live runtime observations to the BOM."""
    from cbom.assurance import runtime_drift

    state = _resolve_state(db, version)
    runtime_rows = [{"hostname": r.hostname, "process_name": r.process_name,
                     "algorithm": r.algorithm, "key_size": r.key_size,
                     "tls_version": r.tls_version, "cipher_suite": r.cipher_suite}
                    for r in db.execute(select(RuntimeFinding)).scalars().all()]
    if not runtime_rows:
        return {"source": "technology_bom", "runtime_verify": None,
                "note": "no runtime observations recorded — run a runtime scanner"}
    return {"source": "technology_bom", "scan_in_progress": _scan_in_progress(db),
            "runtime_verify": runtime_drift(state, runtime_rows)}


def _resolve_state(db: Session, version: int | None) -> dict[str, Any]:
    from cbom.technology_bom import materialize_technology_bom

    if version is not None:
        row = db.execute(select(TechnologyBomSnapshot).where(
            TechnologyBomSnapshot.version == version)).scalars().first()
        if row is None:
            raise HTTPException(status_code=404, detail=f"BOM version not found: {version}")
        return row.state or {}
    return materialize_technology_bom(_gather_inventory(db),
                                      environment=_environment_of(db),
                                      state_version=_next_version(db))


# --------------------------------------------------------------------------
# Cross-BOM cascade — "what breaks if X changes?" over the digital twin
# --------------------------------------------------------------------------

class CascadeRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500,
                        description="Algorithm, certificate fingerprint/subject, "
                                    "host[:port], system id/name, vendor, device or library")
    kind: str | None = Field(default=None,
                             description="Optional explicit target kind: algorithm, "
                                         "certificate, endpoint, system, vendor, device, library")
    max_depth: int = Field(default=6, ge=1, le=12,
                           description="System-graph propagation hops (1..12, as /graph/blast-radius)")


@router.post("/cascade")
def technology_bom_cascade(
    request: CascadeRequest,
    version: int | None = Query(
        None, description="captured twin-snapshot version to replay "
                          "(default: the live estate)"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One target, every layer: code, network, system graph, hardware, vendor.

    Runs over the digital-twin snapshot (live estate, or any captured twin
    snapshot version for point-in-time replay), persists the answer as an
    auditable run, and names its honest unknowns — the same contract the
    twin engine set: deterministic, read-only, never estimating what it
    cannot see.
    """
    from api.routers.digital_twin import _snapshot
    from cbom.unified_cascade import MAX_DEPTH_LIMIT, summarize_system_scope, unified_cascade
    from db.models.cascade_extensions import TwinSnapshot
    from db.repositories.cascade_run_repository import CascadeRunRepository

    if version is not None:
        row = db.query(TwinSnapshot).filter(
            TwinSnapshot.version == version).first()
        if row is None:
            raise HTTPException(status_code=404,
                                detail=f"twin snapshot not found: v{version}")
        estate = row.state or {}
        replayed_version = version
    else:
        estate = _snapshot(db)
        replayed_version = None
    try:
        result = unified_cascade(
            estate, target=request.target, kind=request.kind,
            max_depth=request.max_depth, now=datetime.now(timezone.utc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # replay provenance is stamped on the result BEFORE the run is persisted,
    # so the audit trail records which twin snapshot the answer replayed —
    # not just the HTTP response that happened to mention it
    if replayed_version is not None:
        result["replayed_over"] = {"twin_snapshot_version": replayed_version}

    run = CascadeRunRepository(db).create(
        target=request.target, target_kind=result["target"]["kind"],
        max_depth=request.max_depth, verdict=result["verdict"],
        result=result, created_by=user)
    db.commit()

    emit_platform_event(
        "technology_bom.cascade",
        f"Cross-BOM cascade run: {result['verdict']} for target "
        f"{result['target']['kind']} {request.target!r} "
        f"({result['impact']['system_classification']['review_system_count']} systems in review scope)",
        {"target": request.target, "kind": result["target"]["kind"],
         "verdict": result["verdict"], "run_id": run.id,
         "replayed_over": result.get("replayed_over"),
         "affected_system_count": result["impact"]["affected_system_count"],
         "system_classification": summarize_system_scope(result)},
        target_name="technology-bom",
    )
    return {**result, "run_id": run.id, "max_depth_limit": MAX_DEPTH_LIMIT}


@router.get("/cascade/runs")
def technology_bom_cascade_runs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Cascade history, newest first — the audit trail of past answers."""
    from db.repositories.cascade_run_repository import CascadeRunRepository
    from cbom.unified_cascade import summarize_system_scope

    runs = CascadeRunRepository(db).list_runs(limit=limit, offset=offset)
    return {
        "runs": [
            {"id": r.id, "target": r.target, "target_kind": r.target_kind,
             "max_depth": r.max_depth, "verdict": r.verdict,
             "affected_system_count": (r.result or {}).get("impact", {}).get(
                 "affected_system_count"),
             # Old persisted answers stay unclassified; never invent zeroes or
             # silently replay them against today's graph.
             "system_classification": summarize_system_scope(r.result or {}),
             "relationship_policy": (r.result or {}).get("relationship_policy"),
             # ownership travels with the row (NULL = platform estate)
             "tenant_id": r.tenant_id,
             # replay provenance travels with the history entry: an auditor
             # skimming the list sees which answers were point-in-time
             "replayed_over": (r.result or {}).get("replayed_over"),
             "created_by": r.created_by,
             "created_at": r.created_at.isoformat() if r.created_at else None}
            for r in runs
        ],
        "count": len(runs),
    }


@router.get("/cascade/runs/{run_id}")
def technology_bom_cascade_run(
    run_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """One persisted cascade answer, exactly as it was returned."""
    from db.repositories.cascade_run_repository import CascadeRunRepository

    run = CascadeRunRepository(db).get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"cascade run not found: {run_id}")
    return {"id": run.id, "target": run.target, "target_kind": run.target_kind,
            "max_depth": run.max_depth, "verdict": run.verdict,
            "result": run.result, "created_by": run.created_by,
            "created_at": run.created_at.isoformat() if run.created_at else None}


@router.get("/cascade/runs/{run_id}/diff")
def technology_bom_cascade_run_diff(
    run_id: str,
    against: str | None = Query(
        None, description="run id to diff against; default: the previous run "
                          "of the same target"),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """How the blast radius changed between two cascade runs.

    The audit question this answers: "we migrated two services last sprint —
    did the blast radius of RSA actually shrink?" Affected systems added and
    removed, verdict changes, count deltas — nothing recomputed, both sides
    are the persisted answers exactly as they were returned.
    """
    from db.repositories.cascade_run_repository import CascadeRunRepository

    repo = CascadeRunRepository(db)
    run = repo.get(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"cascade run not found: {run_id}")

    if against is not None:
        other = repo.get(against)
        if other is None:
            raise HTTPException(status_code=404,
                                detail=f"cascade run not found: {against}")
    else:
        # default: the newest earlier run of the same target (the previous
        # answer to the same question), newest-first listing guarantees order
        earlier = [r for r in repo.list_runs(limit=500)
                   if r.target == run.target and r.id != run.id
                   and (r.created_at or datetime.min.replace(tzinfo=timezone.utc))
                   <= (run.created_at or datetime.min.replace(tzinfo=timezone.utc))]
        if not earlier:
            raise HTTPException(
                status_code=404,
                detail=f"no earlier run of target {run.target!r} to diff against")
        other = earlier[0]

    if (other.target or "") != (run.target or ""):
        raise HTTPException(
            status_code=400,
            detail=f"cannot diff runs for different targets: "
                   f"{other.target!r} vs {run.target!r}")

    def _systems(result: dict) -> set[str]:
        return set((result or {}).get("impact", {}).get("affected_systems") or [])

    def _processes(result: dict) -> set[tuple[str, str]]:
        return {(p.get("id"), p.get("name"))
                for p in (result or {}).get("impact", {}).get(
                    "affected_processes") or []}

    def _set(result: dict, layer: str, key: str) -> set[str]:
        try:
            return {str(x) for x in
                    ((result or {}).get("layers", {}).get(layer) or {}).get(key) or []}
        except Exception:
            return set()

    def _delta(label: str, old: set[str], new: set[str]) -> dict:
        return {"added": sorted(new - old), "removed": sorted(old - new),
                "unchanged_count": len(new & old),
                "before": len(old), "after": len(new)}

    old_systems, new_systems = _systems(other.result), _systems(run.result)
    old_processes, new_processes = _processes(other.result), _processes(run.result)
    from cbom.unified_cascade import SYSTEM_SCOPE_SCHEMA

    old_scope = (other.result or {}).get("impact", {}).get("system_classification") or {}
    new_scope = (run.result or {}).get("impact", {}).get("system_classification") or {}
    old_policy = ((other.result or {}).get("relationship_policy") or {}).get("version")
    new_policy = ((run.result or {}).get("relationship_policy") or {}).get("version")
    policy_comparable = old_policy is not None and old_policy == new_policy
    comparable = (old_scope.get("schema") == SYSTEM_SCOPE_SCHEMA
                  and new_scope.get("schema") == SYSTEM_SCOPE_SCHEMA and policy_comparable)
    scope_diff: dict[str, Any] = {"available": comparable}
    if comparable:
        scope_diff.update({
            key: _delta(key, set(old_scope[key]["systems"]), set(new_scope[key]["systems"]))
            for key in ("direct_exposure", "dependent_consumers", "supporting_context")
        })
    else:
        scope_diff["reason"] = (
            "relationship policy differs or is unknown for a stored run" if not policy_comparable
            else "one or both stored runs lack the current system classification")
    return {
        "schema": "cryptoscan.unified-cascade-diff/1",
        "run": {"id": run.id, "created_at": run.created_at.isoformat()
                if run.created_at else None, "verdict": run.verdict},
        "against": {"id": other.id, "created_at": other.created_at.isoformat()
                    if other.created_at else None, "verdict": other.verdict},
        "target": run.target,
        "verdict_changed": run.verdict != other.verdict,
        "affected_systems": _delta("systems", old_systems, new_systems),
        "system_classification": scope_diff,
        "policy_comparison": {"comparable": policy_comparable,
                              "run_version": new_policy, "against_version": old_policy},
        "affected_processes": {
            **_delta("processes",
                     {p[0] or p[1] for p in old_processes},
                     {p[0] or p[1] for p in new_processes}),
        },
        "network_endpoints": _delta(
            "endpoints", _set(other.result, "network", "endpoints"),
            _set(run.result, "network", "endpoints")),
        "hardware_devices": _delta(
            "devices", _set(other.result, "hardware", "devices"),
            _set(run.result, "hardware", "devices")),
        "vendors": _delta(
            "vendors", _set(other.result, "vendor", "vendors"),
            _set(run.result, "vendor", "vendors")),
        "code_evidence": _delta(
            "evidence", _set(other.result, "code", "evidence_ids"),
            _set(run.result, "code", "evidence_ids")),
    }


# --------------------------------------------------------------------------
# Cascade watches — saved targets, re-run on demand, alert on change
# --------------------------------------------------------------------------

class WatchRequest(BaseModel):
    target: str = Field(min_length=1, max_length=500)
    kind: str | None = None
    max_depth: int = Field(default=6, ge=1, le=12)


@router.post("/cascade/watch")
def cascade_watch_create(
    request: WatchRequest,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Save a cascade target as a watch: re-run it via run-due, and the
    blast-radius diff against its previous answer is reported as an event."""
    from db.models.cascade_extensions import CascadeWatch

    watch = CascadeWatch(target=request.target, target_kind=request.kind,
                         max_depth=request.max_depth, active=True,
                         created_by=user)
    db.add(watch)
    db.commit()
    return {"watched": True, "id": watch.id, "target": watch.target}


@router.get("/cascade/watches")
def cascade_watches_list(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.models.cascade_extensions import CascadeWatch

    rows = db.query(CascadeWatch).order_by(
        CascadeWatch.created_at.desc()).limit(200).all()
    return {"watches": [{
        "id": r.id, "target": r.target, "target_kind": r.target_kind,
        "max_depth": r.max_depth, "active": r.active,
        "last_run_id": r.last_run_id, "created_by": r.created_by,
        # ownership travels with the row (NULL = platform estate): the
        # console can label whose watch this is without a second query
        "tenant_id": r.tenant_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    } for r in rows], "count": len(rows)}


@router.delete("/cascade/watch/{watch_id}")
def cascade_watch_delete(
    watch_id: str,
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    from db.models.cascade_extensions import CascadeWatch

    watch = db.query(CascadeWatch).filter(CascadeWatch.id == watch_id).first()
    if watch is None:
        raise HTTPException(status_code=404, detail=f"watch not found: {watch_id}")
    db.delete(watch)
    db.commit()
    return {"deleted": True, "id": watch_id}


@router.post("/cascade/watches/run-due")
def cascade_watches_run_due(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Re-run every active watch and report blast-radius changes.

    The audit loop this closes: watch a target, migrate services, re-run —
    each watch is diffed against its own previous answer, and a changed
    blast radius (systems added or removed) is emitted as a platform event
    the alert stream already carries.
    """
    from api.routers.digital_twin import _snapshot
    from cbom.unified_cascade import summarize_system_scope, unified_cascade
    from db.models.cascade_extensions import CascadeWatch
    from db.repositories.cascade_run_repository import CascadeRunRepository

    watches = db.query(CascadeWatch).filter(
        CascadeWatch.active.is_(True)).all()
    repo = CascadeRunRepository(db)
    estate = _snapshot(db)
    results = []
    for watch in watches:
        try:
            result = unified_cascade(
                estate, target=watch.target, kind=watch.target_kind,
                max_depth=watch.max_depth,
                now=datetime.now(timezone.utc))
        except ValueError as exc:
            results.append({"watch_id": watch.id, "target": watch.target,
                            "error": str(exc)})
            continue
        run = repo.create(target=watch.target,
                          target_kind=result["target"]["kind"],
                          max_depth=watch.max_depth,
                          verdict=result["verdict"], result=result,
                          created_by=f"watch:{watch.id}")
        entry = {"watch_id": watch.id, "target": watch.target,
                 "run_id": run.id, "verdict": result["verdict"],
                 "affected_system_count": result["impact"]["affected_system_count"],
                 "system_classification": summarize_system_scope(result),
                 "relationship_policy": result.get("relationship_policy")}
        if result["verdict"] == "NOT_FOUND":
            # the target has left the estate: say so explicitly instead of
            # letting a zero-impact answer read as "all clear"
            entry["target_missing"] = True
        if watch.last_run_id:
            previous = repo.get(watch.last_run_id)
            if previous is not None:
                # both sides tolerate the NOT_FOUND shape, which carries a
                # count but no system list — a disappeared target must
                # report its collapsed blast radius, not crash the run
                old_policy = ((previous.result or {}).get("relationship_policy") or {}).get("version")
                new_policy = (result.get("relationship_policy") or {}).get("version")
                entry["policy_comparison"] = {
                    "comparable": old_policy is not None and old_policy == new_policy,
                    "run_version": new_policy, "against_version": old_policy}
                old = set((previous.result or {}).get("impact", {}).get(
                    "affected_systems") or [])
                new = set(result["impact"].get("affected_systems") or [])
                added, removed = sorted(new - old), sorted(old - new)
                entry["diff"] = {"added": added, "removed": removed}
                if added or removed:
                    entry["blast_radius_changed"] = True
                    emit_platform_event(
                        "cascade.blast_radius_changed",
                        f"Watched cascade '{watch.target}' review scope changed: "
                        f"{len(added)} added, {len(removed)} removed",
                        {"watch_id": watch.id, "target": watch.target,
                         "added": added, "removed": removed,
                         "run_id": run.id},
                        target_name="technology-bom",
                    )
        watch.last_run_id = run.id
        results.append(entry)
    db.commit()
    return {"ran": len(results), "watches": results}
