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

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.dependencies import get_current_user, require_roles

router = APIRouter(prefix="/live-scan", tags=["live-scan"])

_OPERATORS = ("admin", "superadmin", "ciso", "security_analyst", "scanner")


class RunScanRequest(BaseModel):
    # Subset of scanners to run; default = the periodic host set
    # (hardware + runtime). Target-based scanners need a value below.
    scanners: list[str] = Field(
        default_factory=lambda: ["hardware", "runtime"],
        description="hardware | runtime | network | container | ot",
    )
    network_target: Optional[str] = Field(
        default=None, description="host:port for a TLS probe, e.g. example.com:443")
    network_full: bool = False
    container_target: Optional[str] = None
    ot_logs: Optional[str] = None
    cloud_live: bool = Field(
        default=False, description="run a read-only live cloud scan (needs cloud creds in env)")


class PeriodicRequest(BaseModel):
    interval_seconds: int = Field(default=900, ge=30, le=86400)


def _runner():
    from api.live_scan.runner import get_live_scan_runner

    return get_live_scan_runner()


@router.get("/status")
def status(user: str = Depends(get_current_user)) -> dict[str, Any]:
    r = _runner()
    snap = r.last_snapshot
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
    return {
        "running": r.running,
        "last_run_at": r.last_run_at,
        "periodic": {"enabled": loop_alive, "interval_seconds": r.interval},
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
    targets = {
        "network": body.network_target,
        "network_full": body.network_full,
        "container": body.container_target,
        "ot_logs": body.ot_logs,
        "cloud_live": body.cloud_live,
    }
    return r.start_cycle(only=body.scanners, targets=targets, trigger="manual")


@router.post("/start", status_code=202)
def start_periodic(
    body: PeriodicRequest,
    user: str = Depends(require_roles(*_OPERATORS)),
) -> dict[str, Any]:
    return _runner().start_periodic(body.interval_seconds)


@router.post("/stop", status_code=202)
def stop_periodic(
    user: str = Depends(require_roles(*_OPERATORS)),
) -> dict[str, Any]:
    return _runner().stop_periodic()
