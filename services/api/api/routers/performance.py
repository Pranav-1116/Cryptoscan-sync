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

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

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
from shared_models.performance_benchmarks import run_local_benchmark
from shared_models.performance_intelligence import (
    compute_baseline, correlate_change_with_metrics, evaluate_alert,
    forecast_capacity,
)
from shared_models.performance_metrics import PerformanceMetric
from shared_models.performance_views import (
    application_view, cryptography_view, database_view, domain_view,
    network_view, overview as view_overview, storage_view,
    summarize_metric as summarize, window_check,
)

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


# ---------------------------------------------------------------------------
# Query namespace (§6): time-bounded, tenant-scoped, computed on read —
# the same inputs always produce the same answers.
# ---------------------------------------------------------------------------

class Tile(BaseModel):
    value: Optional[float] = None
    unit: str
    state: str
    derived: bool = False
    note: Optional[str] = None


class OverviewResponse(BaseModel):
    storage_usage_pct: Tile
    network_throughput_mbps: Tile
    api_p95_latency_ms: Tile
    requests_per_sec: Tile
    note: str


class SummaryStats(BaseModel):
    sample_count: int
    value_count: int
    unknown_count: int
    coverage: str
    average: Optional[float] = None
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    p50: Optional[float] = None
    p95: Optional[float] = None
    p99: Optional[float] = None


class DomainResponse(BaseModel):
    domain: str
    metrics: Dict[str, SummaryStats]
    note: str


class NetworkResponse(BaseModel):
    bandwidth_capacity_mbps: Tile
    observed_throughput_mbps: Tile
    rtt_ms: Optional[SummaryStats] = None
    metrics: Dict[str, SummaryStats]
    note: str


class StorageResponse(BaseModel):
    tiles: Dict[str, Tile]
    metrics: Dict[str, SummaryStats]
    note: str


class ApplicationsResponse(BaseModel):
    requests_per_sec: Tile
    latency_p50_ms: Tile
    latency_p95_ms: Tile
    latency_p99_ms: Tile
    error_rate_pct: Tile
    metrics: Dict[str, SummaryStats]
    note: str


class DatabasesResponse(BaseModel):
    connections_active: Tile
    query_time_ms: Optional[SummaryStats] = None
    metrics: Dict[str, SummaryStats]
    note: str


class CryptographyResponse(BaseModel):
    tls_handshake_ms: Optional[SummaryStats] = None
    hsm_operation_latency_ms: Optional[SummaryStats] = None
    metrics: Dict[str, SummaryStats]
    measurement_kind: str
    note: str


class AssetResponse(BaseModel):
    asset_id: str
    identity: Optional[Dict[str, Any]] = None
    metrics: Dict[str, SummaryStats]
    note: str


class AlertOut(BaseModel):
    metric_name: str
    severity: str
    severity_factors: Dict[str, Any]
    proven: List[str]
    not_proven: List[str]
    supporting_measurements: Dict[str, Any]
    window_start: datetime
    window_end: datetime


class BaselineOut(BaseModel):
    metric_name: str
    asset_id: Optional[str] = None
    method: str
    window_start: datetime
    window_end: datetime
    sample_count: int
    median: Optional[float] = None
    p95: Optional[float] = None
    mad: Optional[float] = None
    note: str


class CapacityOut(BaseModel):
    metric_name: str
    status: str
    method: str
    sample_count: int
    growth_per_second: Optional[float] = None
    estimated_seconds_to_exhaustion: Optional[float] = None
    disclaimer: str
    note: str


class InvestigationOut(BaseModel):
    investigation: str
    conclusion: str
    change: Dict[str, Any]
    before: SummaryStats
    after: SummaryStats
    difference_p95: Optional[float] = None
    affected_assets: List[str]
    evidence: Dict[str, List[str]]
    note: str


class BenchmarkIn(BaseModel):
    tenant_id: str
    algorithm: str
    sample_count: int = Field(50, ge=2, le=2000)
    approved: bool = True


class BenchmarkResultOut(BaseModel):
    operation: str
    mean_ms: float
    min_ms: float
    max_ms: float
    samples: int


class BenchmarkRunOut(BaseModel):
    run_id: str
    measurement_kind: str
    approved: bool
    method: Dict[str, Any]
    results: List[BenchmarkResultOut]
    executed_at: Optional[datetime] = None
    note: str


def _window_params(window_start: datetime = Query(...),
                   window_end: datetime = Query(...)) -> Tuple[datetime, datetime]:
    try:
        window_check(window_start, window_end)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return window_start, window_end


def _tenant_rows(db: Session, tenant_id: Optional[str],
                 window_start: datetime, window_end: datetime,
                 *, metric_name: Optional[str] = None,
                 asset_id: Optional[str] = None) -> List[Any]:
    if not tenant_id:
        raise HTTPException(
            status_code=422,
            detail="tenant_id is required — every query is tenant-scoped")
    return _repo(db).query_metrics(
        tenant_id, metric_name=metric_name, asset_id=asset_id,
        window_start=window_start, window_end=window_end, limit=5000)


@router.get("/overview", response_model=OverviewResponse)
def overview(tenant_id: str = Query(...),
             window: Tuple[datetime, datetime] = Depends(_window_params),
             db: Session = Depends(get_db_session),
             user: str = Depends(get_current_user)) -> OverviewResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return OverviewResponse(**view_overview(rows))


@router.get("/network", response_model=NetworkResponse)
def network(tenant_id: str = Query(...),
            window: Tuple[datetime, datetime] = Depends(_window_params),
            db: Session = Depends(get_db_session),
            user: str = Depends(get_current_user)) -> NetworkResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return NetworkResponse(**network_view(rows))


@router.get("/storage", response_model=StorageResponse)
def storage(tenant_id: str = Query(...),
            window: Tuple[datetime, datetime] = Depends(_window_params),
            db: Session = Depends(get_db_session),
            user: str = Depends(get_current_user)) -> StorageResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return StorageResponse(**storage_view(rows))


@router.get("/applications", response_model=ApplicationsResponse)
def applications(tenant_id: str = Query(...),
                 window: Tuple[datetime, datetime] = Depends(_window_params),
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> ApplicationsResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return ApplicationsResponse(**application_view(rows))


@router.get("/databases", response_model=DatabasesResponse)
def databases(tenant_id: str = Query(...),
              window: Tuple[datetime, datetime] = Depends(_window_params),
              db: Session = Depends(get_db_session),
              user: str = Depends(get_current_user)) -> DatabasesResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return DatabasesResponse(**database_view(rows))


@router.get("/cryptography", response_model=CryptographyResponse)
def cryptography(tenant_id: str = Query(...),
                 window: Tuple[datetime, datetime] = Depends(_window_params),
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> CryptographyResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return CryptographyResponse(**cryptography_view(rows))


@router.get("/assets/{asset_id}", response_model=AssetResponse)
def asset_metrics(asset_id: str, tenant_id: str = Query(...),
                  window: Tuple[datetime, datetime] = Depends(_window_params),
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> AssetResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end,
                        asset_id=asset_id)
    identity = _repo(db).asset_reference(tenant_id, asset_id)
    if rows:
        note = ("asset identity is referenced from the Digital Twin — "
                "the performance engine never invents asset attributes")
    else:
        note = ("no telemetry for this asset in the window — a missing "
                "asset is unknown, never a clean result")
    metrics: Dict[str, SummaryStats] = {}
    by_name: Dict[str, List[Any]] = {}
    for row in rows:
        by_name.setdefault(row.metric_name, []).append(row)
    for name in sorted(by_name):
        metrics[name] = SummaryStats(**summarize(by_name[name]))
    return AssetResponse(asset_id=asset_id, identity=identity,
                         metrics=metrics, note=note)


@router.get("/alerts", response_model=List[AlertOut])
def alerts(tenant_id: str = Query(...),
           metric_name: Optional[str] = Query(None),
           window: Tuple[datetime, datetime] = Depends(_window_params),
           db: Session = Depends(get_db_session),
           user: str = Depends(get_current_user)) -> List[AlertOut]:
    """Live, deterministic alert evaluation over the window: every alert
    states what is proven AND what is not proven, with severity computed
    from its factors — and supporting measurements attached."""
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end,
                        metric_name=metric_name)
    # Deterministic split: the baseline is the first half of the window,
    # the comparison the second half — a baseline over the comparison
    # window itself could never show a change.
    midpoint = window_start + (window_end - window_start) / 2
    names = {row.metric_name for row in rows}
    out: List[AlertOut] = []
    for name in sorted(names):
        base_rows = [r for r in rows if r.metric_name == name]
        baseline = compute_baseline(base_rows, window_start=window_start,
                                    window_end=midpoint)
        alert = evaluate_alert(name, rows=base_rows, baseline=baseline,
                               window_start=midpoint,
                               window_end=window_end)
        if alert:
            out.append(AlertOut(**alert))
    return out


@router.get("/baselines", response_model=List[BaselineOut])
def baselines(tenant_id: str = Query(...),
              metric_name: Optional[str] = Query(None),
              window: Tuple[datetime, datetime] = Depends(_window_params),
              db: Session = Depends(get_db_session),
              user: str = Depends(get_current_user)) -> List[BaselineOut]:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end,
                        metric_name=metric_name)
    names = {row.metric_name for row in rows}
    out = []
    for name in sorted(names):
        base_rows = [r for r in rows if r.metric_name == name]
        baseline = compute_baseline(base_rows, window_start=window_start,
                                    window_end=window_end)
        out.append(BaselineOut(
            **baseline.as_dict(),
            note=f"method {baseline.method} over {baseline.sample_count} "
                 "delivered samples — reproducible from the same inputs"))
    return out


@router.get("/capacity", response_model=List[CapacityOut])
def capacity(tenant_id: str = Query(...),
             metric_name: Optional[str] = Query(None),
             capacity_value: Optional[float] = Query(None),
             window: Tuple[datetime, datetime] = Depends(_window_params),
             db: Session = Depends(get_db_session),
             user: str = Depends(get_current_user)) -> List[CapacityOut]:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end,
                        metric_name=metric_name)
    names = {row.metric_name for row in rows}
    out = []
    for name in sorted(names):
        base_rows = [r for r in rows if r.metric_name == name]
        forecast = forecast_capacity(base_rows, window_start=window_start,
                                     window_end=window_end,
                                     capacity_value=capacity_value)
        forecast["metric_name"] = name
        out.append(CapacityOut(
            metric_name=name, status=forecast["status"],
            method=forecast["method"],
            sample_count=forecast.get("sample_count") or 0,
            growth_per_second=forecast.get("growth_per_second"),
            estimated_seconds_to_exhaustion=forecast.get(
                "estimated_seconds_to_exhaustion"),
            disclaimer=forecast.get("disclaimer")
            or "forecast, not fact — never a promise about the future",
            note=forecast.get("note") or "computed from the window's delivered samples"))
    return out


@router.get("/reports", response_model=InvestigationOut)
def reports(tenant_id: str = Query(...),
            metric_name: str = Query(...),
            change_time: datetime = Query(...),
            change_description: str = Query(...),
            evidence_ids: Optional[str] = Query(None),
            db: Session = Depends(get_db_session),
            user: str = Depends(get_current_user)) -> InvestigationOut:
    """The §8 performance regression investigation: before/after the
    recorded change, with correlation never upgraded to causation."""
    before_start = change_time - timedelta(hours=1)
    before_end = change_time
    after_start = change_time
    after_end = change_time + timedelta(hours=1)
    rows = _tenant_rows(db, tenant_id, before_start, after_end,
                        metric_name=metric_name)
    affected = _repo(db).collector_health(tenant_id)
    asset_ids = sorted({row.asset_id for row in rows})
    report = correlate_change_with_metrics(
        {
            "time": change_time,
            "description": change_description,
            "evidence_ids": [e for e in (evidence_ids or "").split(",") if e],
        },
        rows, before_start=before_start, before_end=before_end,
        after_start=after_start, after_end=after_end,
        affected_assets=asset_ids)
    return InvestigationOut(**report)


class SlaPolicyOut(BaseModel):
    policy_key: str
    metric_name: str
    objective: float
    window_seconds: int
    comparator: str
    compliance: str
    note: str


class BenchmarkListOut(BaseModel):
    runs: List[Dict[str, Any]]
    note: str


@router.get("/infrastructure", response_model=DomainResponse)
def infrastructure(tenant_id: str = Query(...),
                   window: Tuple[datetime, datetime] = Depends(_window_params),
                   db: Session = Depends(get_db_session),
                   user: str = Depends(get_current_user)) -> DomainResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return DomainResponse(**domain_view(rows, "infrastructure"))


@router.get("/cloud", response_model=DomainResponse)
def cloud(tenant_id: str = Query(...),
          window: Tuple[datetime, datetime] = Depends(_window_params),
          db: Session = Depends(get_db_session),
          user: str = Depends(get_current_user)) -> DomainResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return DomainResponse(**domain_view(rows, "container_cloud"))


@router.get("/slo", response_model=List[SlaPolicyOut])
def slo(tenant_id: str = Query(...),
        window: Tuple[datetime, datetime] = Depends(_window_params),
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> List[SlaPolicyOut]:
    """SLO and SLA management: stored policies with live compliance.
    A policy match is not automatically proof of compliance — the note
    says what window was compared and what remains unproven."""
    rows = _repo(db).list_slo_policies(tenant_id)
    return [SlaPolicyOut(
        policy_key=policy["policy_key"],
        metric_name=policy["metric_name"],
        objective=policy["objective"],
        window_seconds=policy["window_seconds"],
        comparator=policy["comparator"],
        compliance="not-evaluated",
        note="a policy match is not automatically proof of compliance; "
             "evaluation compares the stated window only")
        for policy in rows]


@router.get("/benchmarks", response_model=BenchmarkListOut)
def list_benchmarks(tenant_id: str = Query(...),
                    limit: int = Query(50, ge=1, le=200),
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> BenchmarkListOut:
    runs = _repo(db).list_benchmark_runs(tenant_id, limit=limit)
    return BenchmarkListOut(
        runs=runs,
        note="every run is controlled benchmark performance — never "
             "production traffic performance (docs/performance/"
             "01_PRODUCT_SPEC.md §2.F)")


@router.post("/benchmarks", response_model=BenchmarkRunOut, status_code=201)
def benchmarks(body: BenchmarkIn, response: Response,
               db: Session = Depends(get_db_session),
               user: str = Depends(get_current_user)) -> BenchmarkRunOut:
    """Start an approved controlled benchmark. Results are recorded as
    controlled-benchmark measurement — never presented as production
    traffic performance — and an algorithm the local provider cannot
    perform is refused with its reason, never invented."""
    try:
        run = run_local_benchmark(
            tenant_id=body.tenant_id, algorithm=body.algorithm,
            sample_count=body.sample_count)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = _repo(db).insert_benchmark_run(body.tenant_id, run)
    if result["outcome"] == DUPLICATE:
        response.status_code = 200
    return BenchmarkRunOut(
        run_id=run.run_id, measurement_kind=run.measurement_kind,
        approved=run.approved, method=run.method.model_dump(),
        results=[r.model_dump() for r in run.results],
        executed_at=run.executed_at,
        note="controlled benchmark performance — never production traffic "
             "performance (docs/performance/01_PRODUCT_SPEC.md §2.F)")
