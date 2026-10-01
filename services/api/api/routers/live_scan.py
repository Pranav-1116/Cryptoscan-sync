"""Realtime scanner control — run the actual CryptoScan scanners on demand or
on a background interval and stream progress/findings over SSE.

Endpoints (all behind auth; starting/controlling scans needs an operator role):
  GET  /live-scan/status            runner state + latest snapshot summary
  POST /live-scan/run               start one scan cycle now (background)
  POST /live-scan/start             start the periodic live loop
  POST /live-scan/stop              stop the periodic live loop

Findings stream to every connected console via the existing EventBus as
live_scan.* events; GET /api/v1/events/stream carries them to the frontend.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies import get_current_user, require_roles
from api.security.target_validation import (
    TargetValidationError,
    validate_scan_targets,
)

# HTTP 400 — numeric to avoid clashing with the ``status`` route below.
HTTP_400 = 400

router = APIRouter(prefix="/live-scan", tags=["live-scan"])

_OPERATORS = ("admin", "superadmin", "ciso", "security_analyst", "scanner")


class RunScanRequest(BaseModel):
    # Subset of scanners to run; default = the periodic host set plus the
    # configured vendor realtime poll. Target-based scanners need a value below.
    scanners: list[str] = Field(
        default_factory=lambda: ["vendor", "hardware", "runtime"],
        description=("vendor | hardware | runtime | network | container | ot | cloud "
                     "| source | universal"),
    )
    network_target: Optional[str] = Field(
        default=None, description="host:port for a TLS probe, e.g. example.com:443")
    network_full: bool = False
    container_target: Optional[str] = Field(
        default=None, description="filesystem root, docker-save .tar, or registry image")
    ot_logs: Optional[str] = Field(
        default=None, description="OT/ICS passive log file or directory")
    cloud_live: bool = Field(
        default=False, description="run a read-only live cloud scan (needs cloud creds in env)")
    source_target: Optional[str] = Field(
        default=None, description="source directory for the static crypto-API scanner")
    universal_target: Optional[str] = Field(
        default=None, description="source path for the universal crypto scanner")


class PeriodicRequest(BaseModel):
    interval_seconds: int = Field(default=900, ge=30, le=86400)


def _runner():
    from api.live_scan.runner import get_live_scan_runner

    return get_live_scan_runner()


def _active_tenant_id() -> str | None:
    try:
        from db.tenancy import current_tenant

        return current_tenant()
    except ImportError:
        return None


def _tenant_runner():
    runner = _runner()
    runner.load_persisted_snapshot(tenant_id=_active_tenant_id())
    return runner


@router.get("/status")
def status(user: str = Depends(get_current_user)) -> dict[str, Any]:
    tenant_id = _active_tenant_id()
    r = _tenant_runner()
    snap = r.snapshot_for_tenant(tenant_id)
    summaries: dict[str, Any] = {}
    if snap:
        for key, res in (snap.get("results") or {}).items():
            summaries[key] = {
                "ok": res.get("ok"),
                "elapsed_s": res.get("elapsed_s"),
                "summary": res.get("summary"),
                "error": res.get("error"),
            }
    loop_alive = bool(r._thread and r._thread.is_alive())  # noqa: SLF001
    owns_loop = r._periodic_tenant_id in (None, _active_tenant_id())  # noqa: SLF001
    return {
        "running": r.running,
        "last_run_at": r.last_run_at,
        "periodic": {"enabled": loop_alive and owns_loop, "interval_seconds": r.interval},
        "scanners": summaries,
        "ok_count": snap.get("ok_count") if snap else 0,
        "failed_count": snap.get("failed_count") if snap else 0,
    }


@router.post("/run", status_code=202)
def run_scan(
    body: RunScanRequest,
    user: str = Depends(require_roles(*_OPERATORS)),
) -> dict[str, Any]:
    r = _runner()
    if r.running:
        return {"status": "already_running"}
    r.load_persisted_snapshot(tenant_id=_active_tenant_id())
    targets = {
        "network": body.network_target,
        "network_full": body.network_full,
        "container": body.container_target,
        "ot_logs": body.ot_logs,
        "cloud_live": body.cloud_live,
        "source": body.source_target,
        "universal": body.universal_target,
    }
    # SSRF / path-traversal / shell-injection guard: refuse unsafe scan
    # targets (loopback, cloud-metadata, secret paths, shell metachars)
    # before any real scanner is launched. Fail closed with HTTP 400.
    try:
        targets = validate_scan_targets(targets)
    except TargetValidationError as exc:
        raise HTTPException(
            status_code=HTTP_400,
            detail={"error": "invalid_target", "field": exc.field, "reason": str(exc)},
        )
    return r.start_cycle(
        only=body.scanners,
        targets=targets,
        trigger="manual",
        tenant_id=_active_tenant_id(),
    )


@router.post("/start", status_code=202)
def start_periodic(
    body: PeriodicRequest,
    user: str = Depends(require_roles(*_OPERATORS)),
) -> dict[str, Any]:
    runner = _runner()
    if not runner.running:
        runner.load_persisted_snapshot(tenant_id=_active_tenant_id())
    return runner.start_periodic(
        body.interval_seconds,
        tenant_id=_active_tenant_id(),
    )


@router.get("/inventory")
def inventory(user: str = Depends(get_current_user)) -> dict[str, Any]:
    """Page-ready live inventory (hardware devices, network TLS assets,
    crypto libraries) from the most recent real scan cycle — for the
    Hardware / Network / Libraries dashboards."""
    return _tenant_runner().inventory(tenant_id=_active_tenant_id())


@router.get("/alerts")
def alerts(user: str = Depends(get_current_user)) -> dict[str, Any]:
    """Deterministic, cross-scanner risk aggregation for the Alerts/Risk view."""
    return _tenant_runner().alerts(tenant_id=_active_tenant_id())


@router.get("/drift")
def drift(user: str = Depends(get_current_user)) -> dict[str, Any]:
    """Crypto-relevant changes between the most recent two live scan cycles."""
    return _tenant_runner().drift(tenant_id=_active_tenant_id())


@router.get("/bom")
def bom(user: str = Depends(get_current_user)) -> dict[str, Any]:
    """CBOM (algorithms/libraries/packages + quantum verdicts) and HBOM
    (hardware components) assembled from the live scans."""
    return _tenant_runner().bom(tenant_id=_active_tenant_id())


@router.post("/stop", status_code=202)
def stop_periodic(
    user: str = Depends(require_roles(*_OPERATORS)),
) -> dict[str, Any]:
    return _runner().stop_periodic(tenant_id=_active_tenant_id())
