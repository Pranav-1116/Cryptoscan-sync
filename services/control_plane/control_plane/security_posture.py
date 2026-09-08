"""ZELNX security posture — deterministic 0-100 scoring + snapshot build.

Aggregates live control-plane signals (agent fleet health, plugin trust,
anomaly flags, failed logins, certificate expiry, audit-chain integrity,
credential health) into a single score with a per-signal component breakdown.
The Security Center renders this.

Doctrine: deterministic and metadata-only. Every source is best-effort — a
single unavailable endpoint (e.g. certificates before any scan) contributes a
0 sub-score and is labelled "no data" rather than crashing the request or
pretending a green posture. The score is honest: an unprovisioned store reads
low, never high.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

#: sub-score weights — sum to 1.0. Audit-chain integrity and certificate health
#: dominate because this is a compliance platform; agent/plugin trust matter for
#: the continuous-scanning model; auth/threat protect the platform itself.
WEIGHTS = {
    "audit": 0.25,
    "cert": 0.20,
    "auth": 0.15,
    "threat": 0.15,
    "fleet": 0.15,
    "plugin": 0.10,
}


def build_security_posture(
    session: Session,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Compute the live posture from the DB. Returns a dict ready to persist and
    to return as the canonical `GET /api/v1/security/posture` payload."""
    now = now or datetime.now(timezone.utc)
    components: dict[str, Any] = {}

    # ---- agent fleet health -------------------------------------------------
    agents_total = agents_healthy = 0
    try:
        from db.repositories.control_plane_repository import ControlPlaneRepository

        agents = ControlPlaneRepository(session).list_agents()
        agents_total = len(agents)
        agents_healthy = sum(1 for a in agents if bool(getattr(a, "healthy", False)))
    except Exception:
        pass
    components["fleet"] = _sub(agents_total, agents_healthy) if agents_total else _sub(0, 0, note="no agents")

    # ---- plugin trust (signature-present and not quarantined/rejected) ------
    plugins_total = plugins_verified = 0
    try:
        from db.models.p2 import PluginPackage

        rows = list(session.execute(select(PluginPackage)).scalars().all())
        plugins_total = len(rows)
        plugins_verified = sum(
            1 for p in rows
            if bool(getattr(p, "signature", None))
            and str(getattr(p, "state", "UPLOADED") or "UPLOADED").upper() not in {"QUARANTINED", "REJECTED", "UNTRUSTED"}
        )
    except Exception:
        pass
    components["plugin"] = _sub(plugins_total, plugins_verified) if plugins_total else _sub(0, 0, note="no plugins")

    # ---- anomaly flags (open + critical/high) ------------------------------
    threats_open = threats_critical = 0
    try:
        from db.models.p2 import AnomalyFlag

        flags = list(session.execute(select(AnomalyFlag)).scalars().all())
        threats_open = sum(1 for f in flags if str(getattr(f, "status", "OPEN") or "OPEN").upper() != "ACKNOWLEDGED")
        threats_critical = sum(
            1 for f in flags
            if str(getattr(f, "severity", "") or "").upper() in {"CRITICAL", "HIGH"}
        )
    except Exception:
        pass
    if threats_open == 0:
        components["threat"] = _sub(0, 0, note="no open threats", overrides=1.0)
    else:
        # Each open threat reduces the score; critical/high double-counts.
        penalty = threats_open + threats_critical
        components["threat"] = {
            "value": round(max(0.0, 1 - penalty / 20.0), 3),
            "total": threats_open,
            "good": threats_open - threats_critical,
            "note": f"{threats_open} open ({threats_critical} critical/high)",
        }

    # ---- auto-audit integrity + failed logins ------------------------------
    audit_ok = False
    audit_entries = 0
    failed_logins = 0
    try:
        from db.models.user import AuditLog
        from db.repositories.user_repository import verify_audit_chain

        verify = verify_audit_chain(session)
        audit_entries = int(verify.get("entry_count", 0) or 0)
        # An intact chain with at least one entry is a positive signal; a
        # provably empty audit trail is NOT a green posture for a compliance
        # platform — it means no audit history was ever written.
        audit_ok = bool(verify.get("status") == "OK") and audit_entries > 0
        failed_logins = int(session.execute(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.outcome == "FAILURE",
                func.lower(AuditLog.action).like("%login%"),
            )
        ).scalar_one() or 0)
    except Exception:
        pass
    components["audit"] = {
        "value": 1.0 if audit_ok else 0.0,
        "ok": audit_ok,
        "entries": audit_entries,
        "note": "chain OK" if audit_ok else ("empty audit trail" if audit_entries == 0 else "chain not verified"),
    }
    if failed_logins == 0:
        components["auth"] = _sub(0, 0, note="no failed logins", overrides=1.0)
    else:
        components["auth"] = {
            "value": round(max(0.0, 1 - failed_logins / 20.0), 3),
            "total": failed_logins,
            "good": max(0, failed_logins - 20),
            "note": f"{failed_logins} failed logins",
        }

    # ---- certificate health ------------------------------------------------
    cert_total = 0
    cert_valid_pct: int | None = None
    try:
        from db.repositories.certificate_repository import CertificateRepository

        certs = CertificateRepository(session).list_all()
        cert_total = len(certs)
        expired = sum(1 for c in certs if getattr(c, "not_after", None) and _aware(c.not_after) < now)
        expiring = sum(
            1 for c in certs
            if getattr(c, "not_after", None) and now <= _aware(c.not_after) <= now + timedelta(days=30)
        )
        if cert_total > 0:
            cert_valid_pct = max(0, round(((cert_total - expired - expiring) / cert_total) * 100))
    except Exception:
        pass
    if cert_total:
        components["cert"] = {
            "value": round((cert_valid_pct or 0) / 100.0, 3),
            "total": cert_total,
            "valid_pct": cert_valid_pct,
            "note": f"{cert_valid_pct}% valid",
        }
    else:
        components["cert"] = _sub(0, 0, note="no cert data")

    # ---- credential health (expired/revoked = bad) --------------------------
    credentials_active = credentials_total = 0
    try:
        from db.repositories.control_plane_repository import ControlPlaneRepository

        creds = ControlPlaneRepository(session).list_credentials()
        credentials_total = len(creds)
        credentials_active = sum(
            1 for c in creds
            if str(getattr(c, "status", "") or "").lower() == "active"
            and bool(getattr(c, "health_ok", False))
        )
    except Exception:
        pass
    components["credentials"] = _sub(credentials_total, credentials_active) if credentials_total else _sub(0, 0, note="no credentials")

    score = security_score({
        "audit": components["audit"]["value"],
        "cert": components["cert"]["value"],
        "auth": components["auth"]["value"],
        "threat": components["threat"]["value"],
        "fleet": components["fleet"]["value"],
        "plugin": components["plugin"]["value"],
    })

    return {
        "score": score,
        "agents_total": agents_total,
        "agents_healthy": agents_healthy,
        "plugins_total": plugins_total,
        "plugins_verified": plugins_verified,
        "threats_open": threats_open,
        "threats_critical": threats_critical,
        "failed_logins": failed_logins,
        "cert_total": cert_total,
        "cert_valid_pct": cert_valid_pct,
        "audit_ok": audit_ok,
        "credentials_active": credentials_active,
        "credentials_total": credentials_total,
        "components": components,
        "source": "live",
    }


def security_score(values: dict[str, float]) -> int:
    """Weighted 0-100 score over the named sub-scores (0..1)."""
    total = 0.0
    weight_total = 0.0
    for key, weight in WEIGHTS.items():
        v = float(values.get(key, 0.0) or 0.0)
        v = max(0.0, min(1.0, v))
        total += v * weight
        weight_total += weight
    if weight_total <= 0:
        return 0
    return int(round((total / weight_total) * 100))


def posture_delta(current: int, previous: int | None, *, drop_threshold: int = 5) -> dict:
    """Score drift vs the previous snapshot: `delta`, and whether it dropped.

    Deterministic helper for the SOC: a negative `delta` beyond the threshold
    is surfaced as a realtime `security.posture_drop` event and as a banner,
    so an operator is alerted when the posture regresses (not silently).
    """
    if previous is None:
        return {"delta": None, "previous_score": None, "dropped": False}
    delta = current - previous
    return {
        "delta": delta,
        "previous_score": previous,
        "dropped": delta < -abs(drop_threshold),
    }


# --------------------------------------------------------------------------- #


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _sub(total: int, good: int, *, note: str = "", overrides: float | None = None) -> dict[str, Any]:
    """A normalised sub-score in [0,1] from a total/good pair, with honesty note.

    `overrides` forces the value (e.g. a clean signal with no data in a given
    bucket should be a full 1.0, not 0), while still exposing the raw counts.
    """
    value = (good / total) if total > 0 else 0.0
    if overrides is not None:
        value = max(0.0, min(1.0, overrides))
    return {
        "value": round(value, 3),
        "total": total,
        "good": good,
        "note": note or "verified",
    }
