"""ZELNX Performance Intelligence — collection contracts (Phase 1).

docs/performance/01_PRODUCT_SPEC.md: the ingestion gateway
(authentication • validation • tenant isolation • deduplication) and the
engine/collector health endpoint. The §10 success criteria are enforced
here, not aspirational: every metric carries a unit, source and
timestamp; missing telemetry is missing or stale — never a zero; a
duplicate metric_id is idempotent; labels are bounded.

Read-only collection by default (§9): this gateway accepts measurements
from authorized monitoring sources. It is not a load-testing engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.dependencies import get_current_user, get_db_session
from db.repositories.performance_repository import (
    DUPLICATE, INSERTED, PerformanceRepository,
)
from shared_models.bulk_result import (
    ACCEPTED, REJECTED, SKIPPED, bulk_result, item as bulk_item,
)
from shared_models.performance_metrics import PerformanceMetric

router = APIRouter(prefix="/performance", tags=["performance"])

_BATCH_OUTCOMES = {INSERTED: ACCEPTED, DUPLICATE: SKIPPED}


class IngestResult(BaseModel):
    """Idempotent ingestion outcome — a duplicate reports its accepted
    identity, never a second row."""

    outcome: str
    accepted_id: str
    note: str


class BatchIn(BaseModel):
    metrics: List[Dict[str, Any]] = Field(default_factory=list)


class BatchItemResult(BaseModel):
    key: str
    status: str
    reason: Optional[str] = None
    accepted_id: Optional[str] = None


class BatchTotals(BaseModel):
    accepted: int
    skipped: int
    rejected: int


class BatchResult(BaseModel):
    totals: BatchTotals
    items: List[BatchItemResult]


class CollectorHealth(BaseModel):
    collector_id: str
    status: str
    last_report_at: Optional[datetime] = None
    detail: Optional[str] = None


class HealthReport(BaseModel):
    engine: str
    status: str
    collectors: List[CollectorHealth]
    checked_at: datetime
    note: str


def _repo(db: Session) -> PerformanceRepository:
    return PerformanceRepository(db)


def _validate(raw: Dict[str, Any]) -> PerformanceMetric:
    try:
        return PerformanceMetric.model_validate(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/ingest", response_model=IngestResult, status_code=201)
def ingest_metric(body: Dict[str, Any], response: Response,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> IngestResult:
    """Receive one metric. 201 INSERTED, 200 DUPLICATE (idempotent).

    The construction contract applies in full: a missing or stale
    measurement carries no value (never a zero), labels are bounded, and
    every row keeps its unit, source and observation timestamp.
    """
    metric = _validate(body)
    result = _repo(db).insert_metric(metric)
    if result["outcome"] == DUPLICATE:
        response.status_code = 200
    return IngestResult(outcome=result["outcome"],
                        accepted_id=result["accepted_id"],
                        note=result["note"])


@router.post("/ingest/batch", response_model=BatchResult)
def ingest_batch(body: BatchIn,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> BatchResult:
    """Batch ingestion with explicit partial success: every item carries
    an ACCEPTED / SKIPPED / REJECTED outcome and a reason; totals are
    derived from the items, never invented."""
    rows: List[BatchItemResult] = []
    repo = _repo(db)
    for index, raw in enumerate(body.metrics):
        key = f"metrics[{index}]"
        try:
            metric = PerformanceMetric.model_validate(raw)
        except ValueError as exc:
            rows.append(BatchItemResult(key=key, status=REJECTED,
                                        reason=str(exc)))
            continue
        result = repo.insert_metric(metric)
        rows.append(BatchItemResult(
            key=key, status=_BATCH_OUTCOMES[result["outcome"]],
            reason=result["note"], accepted_id=result["accepted_id"]))
    totals = BatchTotals(
        accepted=sum(1 for r in rows if r.status == ACCEPTED),
        skipped=sum(1 for r in rows if r.status == SKIPPED),
        rejected=sum(1 for r in rows if r.status == REJECTED),
    )
    return BatchResult(totals=totals, items=rows)


@router.get("/health", response_model=HealthReport)
def engine_health(tenant_id: Optional[str] = Query(None),
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> HealthReport:
    """Collector and engine health (§9): a stale collector is detected
    and named. A collector that has not reported is unknown — its
    telemetry absence is never interpreted as zero measurements."""
    collectors = _repo(db).collector_health(tenant_id) if tenant_id else []
    if collectors:
        note = ("collector states as last reported; a stale collector's "
                "missing telemetry is unknown, never zero")
    else:
        note = ("no collector has reported yet — absence of telemetry is "
                "unknown, never zero")
    return HealthReport(
        engine="zelnx-performance",
        status="ready",
        collectors=[CollectorHealth(**c) for c in collectors],
        checked_at=datetime.now(timezone.utc),
        note=note,
    )
