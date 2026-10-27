"""Deterministic anomaly detection API (P2, no AI/ML).

* POST /anomaly/analyze      run statistical tests over a submitted series
* POST /anomaly/scan         scan stored telemetry (runtime findings over time)
* GET  /anomaly/flags        list persisted anomaly flags
* POST /anomaly/flags/{id}/ack   acknowledge a flag

Uses explainable rule-based statistics (z-score, EWMA control, rate-of-change,
frequency shift) — every result carries a rule name and human explanation.
"""

from __future__ import annotations

from db.tenancy import filtered_get

import logging
from datetime import datetime, timezone

from anomaly.detect import (
    Anomaly,
    detect_series,
    frequency_shift,
)
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session, require_roles

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/anomaly", tags=["anomaly"])

_MIN_POINTS = 6


class AnalyzeRequest(BaseModel):
    metric: str = Field("value", max_length=128)
    values: list[float] = Field(default_factory=list, max_length=10000)
    timestamps: list[float] | None = None
    labels: list[str] | None = Field(None, max_length=10000)
    frequency_target: str | None = None
    baseline_proportion: float | None = Field(None, ge=0.0, le=1.0)
    persist: bool = False


def _to_dict(a: Anomaly, metric: str) -> dict:
    return {
        "rule": a.rule,
        "metric": metric,
        "severity": a.severity.value if hasattr(a.severity, "value") else str(a.severity),
        "score": a.score,
        "value": a.value,
        "explanation": a.explanation,
        "context": a.context,
        "timestamp": a.timestamp,
    }


@router.post("/analyze")
def analyze(body: AnalyzeRequest, db: Session = Depends(get_db_session),
            user: str = Depends(get_current_user)):
    if len(body.values) < _MIN_POINTS and not body.labels:
        raise HTTPException(status_code=422, detail=f"need at least {_MIN_POINTS} points")

    anomalies = [
        _to_dict(a, body.metric)
        for a in detect_series(body.values, timestamps=body.timestamps)
    ]
    if body.labels and body.frequency_target and body.baseline_proportion is not None:
        shift = frequency_shift(
            body.labels,
            target=body.frequency_target,
            baseline_proportion=body.baseline_proportion,
        )
        if shift:
            anomalies.append(_to_dict(shift, f"frequency:{body.frequency_target}"))

    if body.persist:
        _persist(db, anomalies, user)
    return {
        "metric": body.metric,
        "points": len(body.values),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }


def _persist(db: Session, anomalies: list[dict], actor: str) -> int:
    from db.models.p2 import AnomalyFlag

    for a in anomalies:
        db.add(
            AnomalyFlag(
                rule=a["rule"],
                severity=a["severity"],
                metric=a["metric"],
                score=float(a.get("score") or 0.0),
                value=float(a.get("value") or 0.0),
                explanation=a["explanation"],
                context=a.get("context") or {},
                observed_at=datetime.now(timezone.utc),
                status="OPEN",
            )
        )
    db.commit()

    # surface HIGH severity anomalies onto the platform event bus so the
    # command center / alerting sees them deterministically (no AI).
    try:
        from api.events.bus import get_event_bus

        for a in anomalies:
            if str(a.get("severity", "")).upper() == "HIGH":
                get_event_bus().publish(
                    "anomaly.detected",
                    {"rule": a["rule"], "metric": a["metric"],
                     "severity": a["severity"], "explanation": a["explanation"]},
                    source="anomaly",
                )
    except Exception:  # noqa: BLE001 — eventing must never block analysis
        logger.debug("anomaly event publish skipped", exc_info=True)
    return len(anomalies)


@router.post("/scan")
def scan_telemetry(
    persist: bool = True,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "security_analyst", "ciso")),
):
    """Scan stored runtime findings aggregated by day for statistical anomalies."""

    from db.models.runtime_finding import RuntimeFinding
    from sqlalchemy import func as sa_func

    # daily counts of weak/risky findings
    rows = db.execute(
        select(
            sa_func.date(RuntimeFinding.last_seen_at).label("day"),
            sa_func.count().label("cnt"),
        ).group_by("day").order_by("day")
    ).all()
    series = [float(r.cnt) for r in rows]
    anomalies: list[dict] = []
    if len(series) >= _MIN_POINTS:
        anomalies = [_to_dict(a, "daily_runtime_findings") for a in detect_series(series)]

    # frequency shift: algorithm mix among findings
    alg_rows = db.execute(select(RuntimeFinding.algorithm)).all()
    labels = [r[0] for r in alg_rows if r[0]]
    if labels:
        shift = frequency_shift(labels, target="DES", baseline_proportion=0.05, tolerance=0.10)
        if shift:
            anomalies.append(_to_dict(shift, "frequency:DES"))

    if persist and anomalies:
        _persist(db, anomalies, user)
    return {"days": len(series), "series": series, "anomaly_count": len(anomalies),
            "anomalies": anomalies}


@router.get("/flags")
def list_flags(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db_session),
    user: str = Depends(get_current_user),
):
    from db.models.p2 import AnomalyFlag

    limit = max(1, min(int(limit or 100), 500))
    stmt = select(AnomalyFlag).order_by(AnomalyFlag.created_at.desc()).limit(limit)
    if status:
        stmt = stmt.where(AnomalyFlag.status == status.upper())
    if severity:
        stmt = stmt.where(AnomalyFlag.severity == severity.upper())
    rows = list(db.execute(stmt).scalars())
    return {
        "flags": [
            {
                "id": r.id,
                "rule": r.rule,
                "severity": r.severity,
                "metric": r.metric,
                "score": r.score,
                "value": r.value,
                "explanation": r.explanation,
                "context": r.context,
                "status": r.status,
                "acknowledged_by": r.acknowledged_by,
            }
            for r in rows
        ]
    }


@router.post("/flags/{flag_pk}/ack")
def ack_flag(
    flag_pk: str,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "security_analyst", "ciso")),
):
    from db.models.p2 import AnomalyFlag

    row = filtered_get(db, AnomalyFlag, flag_pk)
    if not row:
        raise HTTPException(status_code=404, detail="flag not found")
    row.status = "ACKNOWLEDGED"
    row.acknowledged_by = user
    db.commit()
    return {"id": row.id, "status": row.status, "acknowledged_by": user}


class BaselineRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list, max_length=100_000)
    name: str | None = None


class DriftRequest(BaseModel):
    baseline: dict
    findings: list[dict] = Field(default_factory=list, max_length=100_000)


@router.post("/baseline")
def seal_baseline(
    body: BaselineRequest,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "security_analyst", "ciso", "auditor")),
):
    """Seal a deterministic cryptographic-posture baseline (SHA-256 fingerprint).

    If no findings are posted, uses the LIVE stored evidence findings.
    """
    from anomaly.baseline import build_baseline

    findings = body.findings or _live_evidence_findings(db)
    baseline = build_baseline(findings)
    out = baseline.to_dict()
    out["name"] = body.name or "crypto-posture"
    out["findings_sealed"] = len(findings)
    out["sealed_by"] = user
    return out


@router.post("/baseline/drift")
def baseline_drift(
    body: DriftRequest,
    db: Session = Depends(get_db_session),
    user: str = Depends(require_roles("admin", "superadmin", "security_analyst", "ciso", "auditor")),
):
    """Compare current findings (posted or LIVE) against a sealed baseline."""
    from anomaly.baseline import baseline_from_dict, compare_baseline

    try:
        baseline = baseline_from_dict(body.baseline)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    findings = body.findings or _live_evidence_findings(db)
    report = compare_baseline(baseline, findings)
    out = report.to_dict()
    out["findings_compared"] = len(findings)

    # HIGH drift surfaces on the event bus (deterministic alerting, no AI)
    if report.drifted:
        try:
            from api.events.bus import get_event_bus

            highs = [d for d in report.drifts if d.severity == "HIGH"]
            if highs:
                get_event_bus().publish(
                    "baseline.drift",
                    {"drift_count": len(highs),
                     "details": [d.detail for d in highs]},
                    source="anomaly",
                )
        except Exception:  # noqa: BLE001
            logger.debug("baseline drift event publish skipped", exc_info=True)
    return out


def _live_evidence_findings(db: Session) -> list[dict]:
    """Pull live stored evidence findings as posture inputs."""
    try:
        from db.repositories.evidence_repository import EvidenceRepository

        rows = EvidenceRepository(db).list_all(limit=100_000)
    except Exception:  # noqa: BLE001
        logger.debug("live evidence lookup failed", exc_info=True)
        return []
    return [
        {
            "algorithm": getattr(r, "algorithm", None),
            "key_size": getattr(r, "key_size", None),
            "is_hardcoded_key": getattr(r, "is_hardcoded_key", None),
            "confidence": getattr(r, "confidence", None),
            "file_path": getattr(r, "file_path", None),
        }
        for r in rows
    ]
