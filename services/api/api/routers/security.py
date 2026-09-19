"""ZELNX Security Center — server-owned security posture + 24/7 SOC ops.

Endpoints (all `/api/v1/security/...`):
- `GET /posture`           compute + persist a metadata-only snapshot, return
                           current score + per-signal breakdown + history (and
                           the score drift `delta` vs the previous snapshot).
- `GET /posture/stream`    SSE: pushes a fresh posture snapshot on an interval
                           (default 30s) so the Security Center is live, not
                           polled. Emits `security.posture_drop` on regression.
- `GET /posture/trend`     time-series buckets (score min/avg/max + per-signal
                           averages) for posture-over-time charts.
- `GET /alerts`            unified live threat feed (anomaly flags, live-scan
                           alerts, critical/high runtime findings, failed
                           logins) for incident triage.

Realtime doctrine: every signal is derived from real control-plane data; an
unprovisioned/quiet store reads low (never a fabricated green), and a posture
regression is emitted as a durable `platform.security.*` event consumed by the
SSE stream. Nothing here is simulated.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles
from api.schemas.security_intelligence_schemas import (
    AssetStateRequest,
    CorrelateRequest,
    IdentityResolveRequest,
    RiskChainRequest,
    ScanProfileResolveRequest,
    ScanScheduleRequest,
)
from db.repositories.control_plane_repository import ControlPlaneRepository

router = APIRouter(prefix="/security", tags=["security"])

#: who may manage the org scan/privacy policy (the "Security & Scanning Policy" screen).
_POLICY_OPERATORS = ("admin", "superadmin", "ciso")

POSTURE_STREAM_HEARTBEAT_SECONDS = 15.0
DEFAULT_DROP_THRESHOLD = 5

_ALERT_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _repo(db: Session) -> ControlPlaneRepository:
    return ControlPlaneRepository(db)


def _sse(frame_id: int, event_type: str, data: dict) -> str:
    payload = json.dumps(data, default=str, separators=(",", ":"))
    return f"id: {frame_id}\nevent: {event_type}\ndata: {payload}\n\n"


def _persist_posture(db: Session, posture: dict) -> tuple[ControlPlaneRepository, object, int | None]:
    """Persist the computed posture + resolve the previous snapshot for drift."""
    repo = _repo(db)
    previous = repo.latest_security_posture()
    previous_score = previous.score if previous else None
    row = repo.create_security_posture(
        score=posture["score"],
        agents_total=posture["agents_total"],
        agents_healthy=posture["agents_healthy"],
        plugins_total=posture["plugins_total"],
        plugins_verified=posture["plugins_verified"],
        threats_open=posture["threats_open"],
        threats_critical=posture["threats_critical"],
        failed_logins=posture["failed_logins"],
        cert_total=posture["cert_total"],
        cert_valid_pct=posture["cert_valid_pct"],
        audit_ok=posture["audit_ok"],
        credentials_active=posture["credentials_active"],
        credentials_total=posture["credentials_total"],
        components=posture["components"],
        source="live",
    )
    db.commit()
    db.refresh(row)
    return repo, row, previous_score


@router.get("/posture")
def get_security_posture(
    history_limit: int = Query(60, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Compute + persist the live security posture and return current + history.

    This is the canonical backend contract for the Security Center. Each call
    records a snapshot row (metadata only) so a 24/7 SOC can watch posture over
    time; `history` returns the most recent snapshots newest-first.
    """
    from control_plane.security_posture import build_security_posture, posture_delta

    posture = build_security_posture(db)
    repo, row, previous_score = _persist_posture(db, posture)

    drift = posture_delta(posture["score"], previous_score)
    history = [h.to_dict() for h in repo.list_security_postures(limit=history_limit)]

    return {
        **posture,
        "snapshot_id": row.id,
        "previous_score": drift["previous_score"],
        "delta": drift["delta"],
        "dropped": drift["dropped"],
        "history": history,
    }


@router.get("/posture/stream")
async def posture_stream(
    request: Request,
    interval: int = Query(30, ge=5, le=600),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """SSE: push a freshly-computed posture snapshot each `interval` seconds.

    Emits `security.posture` frames; when the score regresses past the drop
    threshold it also emits `security.posture_drop`. No polling, no fake data.
    """
    from control_plane.security_posture import build_security_posture, posture_delta

    async def gen():
        frame = 0
        repo = _repo(db)
        while True:
            if await request.is_disconnected():
                break
            try:
                posture = build_security_posture(db)
                previous = repo.latest_security_posture()
                previous_score = previous.score if previous else None
                row = repo.create_security_posture(
                    score=posture["score"], agents_total=posture["agents_total"],
                    agents_healthy=posture["agents_healthy"], plugins_total=posture["plugins_total"],
                    plugins_verified=posture["plugins_verified"], threats_open=posture["threats_open"],
                    threats_critical=posture["threats_critical"], failed_logins=posture["failed_logins"],
                    cert_total=posture["cert_total"], cert_valid_pct=posture["cert_valid_pct"],
                    audit_ok=posture["audit_ok"], credentials_active=posture["credentials_active"],
                    credentials_total=posture["credentials_total"], components=posture["components"],
                    source="live",
                )
                db.commit()
                db.refresh(row)
                drift = posture_delta(posture["score"], previous_score)
                payload = {**posture, "snapshot_id": row.id,
                           "previous_score": drift["previous_score"],
                           "delta": drift["delta"], "dropped": drift["dropped"]}
                frame += 1
                yield _sse(frame, "security.posture", payload)
                if drift["dropped"]:
                    frame += 1
                    yield _sse(frame, "security.posture_drop", {
                        "score": posture["score"], "previous_score": drift["previous_score"],
                        "delta": drift["delta"], "ts": datetime.now(timezone.utc).isoformat(),
                    })
                    await _emit_drop_event(posture["score"], drift)
            except Exception:
                # never kill the stream on a transient signal error
                yield _sse(frame + 1, "error", {"detail": "signal unavailable"})
            # heartbeat comment (keeps proxies from closing the idle stream)
            yield f": heartbeat {datetime.now(timezone.utc).isoformat()}\n\n"
            try:
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/posture/history")
def list_security_posture_history(
    limit: int = Query(60, ge=1, le=500),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Recent persistent posture snapshots (newest first) for raw time-series."""
    rows = _repo(db).list_security_postures(limit=limit)
    return {"snapshots": [r.to_dict() for r in rows], "count": len(rows)}


@router.get("/posture/trend")
def posture_trend(
    hours: int = Query(24, ge=1, le=720),
    bucket_minutes: int = Query(30, ge=5, le=360),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Time-series posture buckets (score min/avg/max + per-signal average)."""
    from control_plane.security_posture import posture_delta

    repo = _repo(db)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    # newest-first, enough rows to bucket the window
    rows = [r for r in repo.list_security_postures(limit=5000) if r.created_at and _aware(r.created_at) >= cutoff]
    rows.reverse()  # oldest -> newest

    bucket_secs = bucket_minutes * 60
    buckets: list[dict] = []
    for row in rows:
        ts = _aware(row.created_at)
        bucket_start = int(ts.timestamp() // bucket_secs) * bucket_secs
        key = datetime.fromtimestamp(bucket_start, tz=timezone.utc)
        _idx = int((ts - cutoff).total_seconds() // bucket_secs)
        # find or create a bucket keyed by UTC start time
        if not buckets or (buckets[-1]["start"]).isoformat() != key.isoformat():
            comp_names = set((row.components or {}).keys())
            buckets.append({
                "start": key, "count": 0, "score_sum": 0.0, "score_min": None,
                "score_max": None, "components": {c: {"sum": 0.0, "n": 0} for c in comp_names},
            })
        b = buckets[-1]
        b["count"] += 1
        b["score_sum"] += row.score
        b["score_min"] = row.score if b["score_min"] is None else min(b["score_min"], row.score)
        b["score_max"] = row.score if b["score_max"] is None else max(b["score_max"], row.score)
        for name, comp in (row.components or {}).items():
            bv = b["components"].setdefault(name, {"sum": 0.0, "n": 0})
            bv["sum"] += float(comp.get("value", 0.0) or 0.0)
            bv["n"] += 1

    out_buckets = []
    for b in buckets:
        out_buckets.append({
            "start": b["start"].isoformat(),
            "count": b["count"],
            "score_avg": round(b["score_sum"] / b["count"], 2) if b["count"] else None,
            "score_min": b["score_min"],
            "score_max": b["score_max"],
            "components": {
                name: round(v["sum"] / v["n"], 3) if v["n"] else None
                for name, v in b["components"].items()
            },
        })

    latest = rows[-1] if rows else None
    previous = rows[-2] if len(rows) > 1 else None
    drift = posture_delta(latest.score if latest else 0, previous.score if previous else None) if latest else posture_delta(0, None)
    return {
        "window_hours": hours,
        "bucket_minutes": bucket_minutes,
        "count": len(rows),
        "buckets": out_buckets,
        "latest": {"id": latest.id, "score": latest.score, "created_at": latest.created_at.isoformat() if latest and latest.created_at else None, **drift} if latest else None,
    }


@router.get("/alerts")
def security_alerts(
    limit: int = Query(50, ge=1, le=200),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Unified live threat feed for 24/7 SOC triage, newest+severity first."""
    out: list[dict] = []

    # 1) open anomaly flags (deterministic explainable rules)
    try:
        from db.models.p2 import AnomalyFlag

        flags = list(db.execute(select(AnomalyFlag).where(
            AnomalyFlag.status != "ACKNOWLEDGED").order_by(AnomalyFlag.created_at.desc()).limit(limit)).scalars())
        for f in flags:
            sev = str(getattr(f, "severity", "") or "MEDIUM").upper()
            out.append({
                "id": f"flag:{f.id}", "severity": sev, "kind": "anomaly",
                "title": str(getattr(f, "rule", "") or "anomaly"),
                "detail": str(getattr(f, "explanation", "") or ""),
                "asset": "", "ts": _iso(getattr(f, "created_at", None)),
                "source": "anomaly", "status": str(getattr(f, "status", "OPEN") or "OPEN").upper(),
                "ack_href": f"/api/v1/anomaly/flags/{f.id}/ack",
            })
    except Exception:
        pass

    # 2) live-scan alerts from the running engine (real scanner alerts)
    try:
        from api.live_scan.runner import get_live_scan_runner

        runner = get_live_scan_runner()
        for a in runner.alerts().get("alerts", []):
            sev = str(a.get("severity", "") or "MEDIUM").upper()
            out.append({
                "id": f"live:{a.get('ts')}:{a.get('kind')}:{a.get('asset')}",
                "severity": sev, "kind": str(a.get("kind", "") or "live"),
                "title": str(a.get("title", "") or ""), "detail": str(a.get("detail", "") or ""),
                "asset": str(a.get("asset", "") or ""), "ts": str(a.get("ts", "") or ""),
                "source": "live-scan", "status": "OPEN", "ack_href": None,
            })
    except Exception:
        pass

    # 3) critical/high runtime crypto findings
    try:
        from db.models.runtime_finding import RuntimeFinding

        findings = list(db.execute(select(RuntimeFinding).order_by(RuntimeFinding.last_seen_at.desc()).limit(limit)).scalars())
        for r in findings:
            sev = _severity_from_runtime(r)
            out.append({
                "id": f"rt:{r.id}", "severity": sev, "kind": "runtime",
                "title": f"{r.algorithm or 'crypto'} on {r.process_name or r.hostname or 'host'}",
                "detail": f"weak_tls={getattr(r, 'weak_tls', False)} observations={getattr(r, 'observation_count', 0)}",
                "asset": str(getattr(r, "hostname", "") or ""), "ts": _iso(getattr(r, "last_seen_at", None)),
                "source": "runtime", "status": "OPEN", "ack_href": None,
            })
    except Exception:
        pass

    # 4) recent failed logins
    try:
        from db.models.user import AuditLog

        failed = list(db.execute(select(AuditLog).where(
            AuditLog.outcome == "FAILURE", AuditLog.action.like("%login%"),
        ).order_by(AuditLog.created_at.desc()).limit(limit)).scalars())
        for e in failed:
            out.append({
                "id": f"auth:{e.id}", "severity": "HIGH", "kind": "auth",
                "title": f"failed login for {e.actor}",
                "detail": str(e.detail or ""), "asset": "",
                "ts": _iso(getattr(e, "created_at", None)),
                "source": "audit", "status": "OPEN", "ack_href": None,
            })
    except Exception:
        pass

    out.sort(key=lambda a: (_ALERT_SEVERITY_ORDER.get(a["severity"], 99), a["ts"] or ""))
    counts: dict[str, int] = {}
    for a in out:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    return {"alerts": out[:limit], "count": min(len(out), limit), "counts": counts, "generated_at": datetime.now(timezone.utc).isoformat()}


# --------------------------------------------------------------------------- #


_POLICY_KEY = "scan_policy"


def _active_sector(db: Session) -> str | None:
    """The org's active sector (from the sector setting), for policy seeding."""
    try:
        from db.repositories.settings_repository import SECTOR_SETTING_KEY, SettingsRepository

        saved = SettingsRepository(db).get(SECTOR_SETTING_KEY)
        if isinstance(saved, dict) and saved.get("sector"):
            return str(saved["sector"])
    except Exception:  # noqa: BLE001 — best-effort
        pass
    try:
        from db.repositories.onboarding_repository import OnboardingRepository

        org = OnboardingRepository(db).get_default_org()
        if org is not None and getattr(org, "sector", None):
            return str(org.sector)
    except Exception:  # noqa: BLE001 — best-effort
        pass
    return None


def _default_policy() -> dict:
    """Conservative per-sector-default scan + privacy policy (fail-safe)."""
    try:
        from privacy.policy import build_policy
        return build_policy({}, {}, sector=None).to_dict()
    except Exception:  # noqa: BLE001
        return {"scan": {"mode": "read-only", "intensity": "low"}, "privacy": {}}


@router.get("/policy")
def get_scan_policy(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The org's current Scanning & Security Policy (§25)."""
    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == _POLICY_KEY)).scalars().first()
    existing = _default_policy()
    if row is not None and row.value:
        try:
            import json
            stored = json.loads(row.value)
            # ensure both halves always present (deterministic contract)
            existing = {"scan": stored.get("scan") or existing["scan"],
                        "privacy": stored.get("privacy") or existing["privacy"]}
        except Exception:  # noqa: BLE001
            pass
    # validate+normalize the policy so the UI always sees real bounds, and
    # reflect the sector profile so a chosen sector actually enforces (§26)
    sector = _active_sector(db)
    try:
        from privacy.policy import apply_sector_overrides, build_policy
        bundle = build_policy(existing.get("scan"), existing.get("privacy"), sector=sector or None)
        if sector:
            bundle = apply_sector_overrides(bundle, sector)
        existing = bundle.to_dict()
    except Exception:  # noqa: BLE001
        pass
    return {"source": "security_policy", "policy": existing, "sector": sector}


@router.put("/policy", status_code=200)
def put_scan_policy(
    body: dict = Body(default={}),
    user: str = Depends(require_roles(*_POLICY_OPERATORS)),
    db: Session = Depends(get_db_session),
):
    """Persist the org's Scanning & Security Policy. Fail-safe: we refuse to
    enable sensitive-data collection or a non-read-only/high mode; the stored
    value is the normalized policy (unknown keys dropped)."""
    from db.models.app_setting import AppSetting

    scan = (body or {}).get("scan") or {}
    privacy = (body or {}).get("privacy") or {}
    sector = _active_sector(db)
    try:
        from privacy.policy import apply_sector_overrides, build_policy

        bundle = build_policy(scan, privacy, sector=sector or None)
        if sector:
            # the stored policy can never be looser than the sector profile
            bundle = apply_sector_overrides(bundle, sector)
        normalized = bundle.to_dict()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"invalid policy: {exc}")

    # fail-safe guardrails (never loosened through this endpoint)
    if normalized["privacy"].get("collect_private_keys") or normalized["privacy"].get("collect_secrets"):
        raise HTTPException(status_code=422, detail="sensitive-data collection is not permitted")
    if normalized["scan"].get("mode") != "read-only":
        raise HTTPException(status_code=422, detail="scan mode must be read-only")
    if normalized["scan"].get("intensity") not in ("off", "low", "medium"):
        raise HTTPException(status_code=422, detail="intensity must be off/low/medium")

    import json
    row = db.execute(select(AppSetting).where(AppSetting.key == _POLICY_KEY)).scalars().first()
    if row is None:
        row = AppSetting(key=_POLICY_KEY, value=json.dumps(normalized), updated_by=user)
        db.add(row)
    else:
        row.value = json.dumps(normalized)
        row.updated_by = user
    db.commit()
    db.refresh(row)
    from api.events.platform_events import emit_platform_event
    emit_platform_event("security.policy_updated",
                        f"scan/privacy policy updated by {user}",
                        {"updated_by": user, "mode": normalized["scan"]["mode"],
                         "intensity": normalized["scan"]["intensity"]}, target_name="security")
    return {"source": "security_policy", "updated": True, "policy": normalized, "sector": sector}


@router.post("/gate")
def evaluate_gate(
    body: dict = Body(default={}),
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Run the unified scanner gate on a proposed scan request, BEFORE anything
    spins up. Returns permit/deny with the ordered control chain and audit
    record. Always read-only (never starts a scan)."""
    try:
        from privacy.gate import ScannerGate
        from privacy.policy import apply_sector_overrides, build_policy
        from privacy.ratelimit import Limits

        scan = (body or {}).get("scan") or {}
        privacy = (body or {}).get("privacy") or {}
        sector = (body or {}).get("sector")
        # default to the persisted policy if none supplied
        if not scan and not privacy:
            pol = get_scan_policy(user="", db=db)["policy"]
            scan, privacy = pol.get("scan") or {}, pol.get("privacy") or {}
        bundle = build_policy(scan, privacy, sector=sector or None)
        if sector:
            bundle = apply_sector_overrides(bundle, sector)
        gate = ScannerGate(policy=bundle, limits=Limits())
        decision = gate.evaluate(
            actor=str((body or {}).get("actor") or user),
            tenant=str((body or {}).get("tenant") or ""),
            environment=str((body or {}).get("environment") or ""),
            targets=(body or {}).get("targets") or {},
            credentials=(body or {}).get("credentials") or {},
            scanners=(body or {}).get("scanners") or [],
            scope_includes=(body or {}).get("scope") or {},
        )
        return {"source": "security_gate", **decision.to_dict(), "policy": bundle.to_dict()}
    except Exception as exc:  # noqa: BLE001 — gate must not crash the API
        raise HTTPException(status_code=500, detail=f"gate evaluation failed: {exc}")


# --------------------------------------------------------------------------- #
# Security intelligence — deterministic decision modules (no DB writes).
# These expose the pure engines as read-mostly endpoints so the frontend and
# any automations can resolve identities, scan profiles, finding correlation,
# verification state and scan triggers without re-implementing the logic.
# --------------------------------------------------------------------------- #


@router.get("/profiles")
def list_scan_profiles(user: str = Depends(get_current_user)):
    """The sanctioned scan profiles (spec #8) that a scan may be run under."""
    try:
        from privacy.profiles import SCAN_PROFILES
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"profiles unavailable: {exc}")
    return {"profiles": [p.to_dict() for p in SCAN_PROFILES.values()], "count": len(SCAN_PROFILES)}


@router.post("/profiles/resolve")
def resolve_scan_profile(
    body: ScanProfileResolveRequest,
    user: str = Depends(get_current_user),
):
    """Resolve a named profile to a concrete policy + limits, clamped by the
    org's sector so a profile can never loosen sector protection (spec #8)."""
    try:
        from privacy.profiles import resolve_profile
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"profiles unavailable: {exc}")
    profile_id = body.profile.strip()
    if not profile_id:
        raise HTTPException(status_code=422, detail="profile is required")
    try:
        resolved = resolve_profile(
            profile_id, sector=body.sector or None,
            scan=body.scan, privacy=body.privacy, limits=body.limits,
        )
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown profile '{profile_id}'")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=422, detail=f"failed to resolve profile: {exc}")
    return {
        "source": "security_profiles",
        "profile": resolved["profile"],
        "policy": resolved["policy"].to_dict(),
        "limits": resolved["limits"].to_dict(),
        "sector": body.sector,
    }


@router.post("/intelligence/identity/resolve")
def resolve_asset_identity(body: IdentityResolveRequest, user: str = Depends(get_current_user)):
    """Cross-scanner identity resolution (spec #1). Given a batch of scanner
    observations, return ONE canonical asset per real asset with all aliases."""
    try:
        from privacy.identity import AssetObservation, resolve_identities
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"identity engine unavailable: {exc}")
    if not body.observations:
        raise HTTPException(status_code=422, detail="observations are required")
    obs = []
    for entry in body.observations:
        try:
            obs.append(AssetObservation(
                source=entry.source,
                ids={str(k): str(v) for k, v in entry.ids.items() if v is not None},
                attrs=dict(entry.attrs),
                observed_at=entry.observed_at,
            ))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=422, detail=f"invalid observation: {exc}")
    result = resolve_identities(obs)
    return {"source": "identity_resolution", **result.to_dict()}


@router.post("/intelligence/correlate")
def correlate_findings(body: CorrelateRequest, user: str = Depends(get_current_user)):
    """Finding deduplication (spec #21): collapse the same root cause seen by
    many scanners into ONE finding carrying corroborating evidence."""
    try:
        from privacy.correlation import correlate_findings
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"correlation engine unavailable: {exc}")
    findings = body.findings
    if not findings:
        raise HTTPException(status_code=422, detail="findings are required")
    merged = correlate_findings(findings)
    return {"source": "finding_correlation", "deduplicated": merged, "count": len(merged),
            "inputs": len(findings), "deduped_by": max(0, len(findings) - len(merged))}


@router.post("/intelligence/chain")
def build_risk_chain(body: RiskChainRequest, user: str = Depends(get_current_user)):
    """Finding correlation -> attack/dependency chain (spec #22): turn related
    findings into a single compound business risk."""
    try:
        from privacy.correlation import build_chain
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"correlation engine unavailable: {exc}")
    asset_id = body.asset_id.strip()
    findings = body.findings
    if not asset_id:
        raise HTTPException(status_code=422, detail="asset_id is required")
    chain = build_chain(
        asset_id, findings,
        critical_asset=body.critical_asset,
        business_value=body.business_value,
    )
    return {"source": "risk_chain", **chain}


@router.post("/intelligence/state")
def asset_state(body: AssetStateRequest, user: str = Depends(get_current_user)):
    """Verification + freshness state for an asset (spec #23, #24, #25).

    Returns an honest display status — an asset that has not been observed
    within its freshness window is never reported as healthy/green."""
    import time as _time
    try:
        from privacy.state import confidence_from_sources, health_for_asset, staleness
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"state engine unavailable: {exc}")
    confidence = confidence_from_sources(
        {str(k): str(v) for k, v in body.sources.items()},
        verified=body.verified,
    )
    now = body.now if body.now is not None else _time.time()
    freshness = staleness(body.last_seen_epoch, now=now)
    health = health_for_asset(
        {"verification": body.verification, "last_seen_epoch": body.last_seen_epoch},
        now=now,
    )
    return {"source": "asset_state", "confidence": confidence.to_dict(),
            "freshness": freshness, "health": health}


@router.post("/intelligence/schedule")
def resolve_schedule(body: ScanScheduleRequest, user: str = Depends(get_current_user)):
    """Scan trigger + incremental decision (spec #10, #11, #12). Resolve a
    cadence keyword to a schedule, map a change event to scan types, and decide
    whether an incremental re-scan is safe given a baseline."""
    import time as _time
    try:
        from privacy.triggers import is_incremental, resolve_schedule
        from privacy.triggers import event_for_change
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"trigger engine unavailable: {exc}")
    cadence = body.cadence or "on_demand"
    schedule = resolve_schedule(cadence)
    scans_for_event = list(event_for_change(body.event)) if body.event else []
    incremental = is_incremental(
        body.scan_type,
        baseline_at=body.baseline_at,
        now=body.now if body.now is not None else _time.time(),
        changed_assets=body.changed_assets,
    ).to_dict()
    return {"source": "scan_schedule", "schedule": schedule.to_dict(),
            "cadence": cadence, "event": body.event, "scans_for_event": scans_for_event,
            "incremental": incremental}


async def _emit_drop_event(score: int, drift: dict) -> None:
    try:
        from api.events.platform_events import emit_platform_event

        emit_platform_event(
            "security.posture_drop",
            f"posture dropped {drift['delta']} -> {score}",
            {"score": score, "previous_score": drift["previous_score"],
             "delta": drift["delta"]},
            target_name="security",
        )
    except Exception:
        pass


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _iso(dt: datetime | None) -> str | None:
    return _aware(dt).isoformat() if dt else None


def _severity_from_runtime(row) -> str:
    try:
        impact = str(getattr(row, "quantum_impact", "") or "").lower()
        if "critical" in impact or "high" in impact or getattr(row, "weak_tls", False):
            return "CRITICAL" if "critical" in impact else "HIGH"
        if "medium" in impact:
            return "MEDIUM"
    except Exception:
        pass
    return "MEDIUM"
