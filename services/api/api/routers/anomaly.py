"""Deterministic anomaly detection API (P2, no AI/ML).

* POST /anomaly/analyze      run statistical tests over a submitted series
* POST /anomaly/scan         scan stored telemetry (runtime findings over time)
* GET  /anomaly/flags        list persisted anomaly flags
* POST /anomaly/flags/{id}/ack   acknowledge a flag

Uses explainable rule-based statistics (z-score, EWMA control, rate-of-change,
frequency shift) — every result carries a rule name and human explanation.
"""

from __future__ import annotations

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

    row = db.get(AnomalyFlag, flag_pk)
    if not row:
        raise HTTPException(status_code=404, detail="flag not found")
    row.status = "ACKNOWLEDGED"
    row.acknowledged_by = user
    db.commit()
    return {"id": row.id, "status": row.status, "acknowledged_by": user}
