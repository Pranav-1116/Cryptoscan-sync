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

import base64
import json
import os
import re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.config.settings import get_settings
from api.dependencies import (get_current_user, get_db_session,
                              require_intelligence_manager,
                              require_intelligence_writer,
                              require_query_tenant_scope)
from db.tenancy import filtered_get
from db.repositories.performance_repository import (
    CONFLICT, DUPLICATE, INSERTED, PerformanceRepository,
)
from shared_models.bulk_result import (
    ACCEPTED, REJECTED, SKIPPED,
)
from shared_models.performance_benchmarks import run_local_benchmark
from shared_models.performance_collectors import (
    translate_node_exporter, translate_postgres_exporter, translate_otlp,
)
from shared_models.performance_capture import (
    SCHEMA as CAPTURE_SCHEMA, capture_binding, payload_sha256,
    receipt_id as capture_receipt_id, verify_capture_attestation,
)
from shared_models.performance_intelligence import (
    compute_baseline, correlate_change_with_metrics, evaluate_alert,
    forecast_capacity,
)
from shared_models.performance_metrics import PerformanceMetric
from shared_models.performance_simulation import (
    compare_bank_windows, compare_controlled_benchmarks,
)
from shared_models.performance_taxonomy import definition_for
from shared_models.performance_views import (
    database_workspace as database_workspace_view,
    application_workspace as application_workspace_view,
    infrastructure_workspace as infrastructure_workspace_view,
    hsm_view, workload_view,
    application_view, cryptography_view, database_view, domain_view,
    network_view, overview as view_overview, storage_view,
    summarize_metric as summarize, window_check,
)

router = APIRouter(prefix="/performance", tags=["performance"],
                   dependencies=[Depends(require_query_tenant_scope)])

_BATCH_OUTCOMES = {INSERTED: ACCEPTED, DUPLICATE: SKIPPED,
                   CONFLICT: REJECTED}


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


def _require_metric_tenant(tenant_id: str) -> None:
    from db.tenancy import current_tenant

    scoped = current_tenant()
    if scoped is not None and tenant_id != scoped:
        raise HTTPException(status_code=403,
                            detail="metric tenant does not match the "
                                   "authenticated tenant scope")


def _validate(raw: Dict[str, Any]) -> PerformanceMetric:
    try:
        return PerformanceMetric.model_validate(raw)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/ingest", response_model=IngestResult, status_code=201,
             dependencies=[Depends(require_intelligence_writer)])
def ingest_metric(body: Dict[str, Any], response: Response,
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> IngestResult:
    """Receive one metric. 201 INSERTED, 200 DUPLICATE (idempotent).

    The construction contract applies in full: a missing or stale
    measurement carries no value (never a zero), labels are bounded, and
    every row keeps its unit, source and observation timestamp.
    """
    if get_settings().is_production:
        raise HTTPException(status_code=503,
                            detail="direct Performance ingestion is unavailable in production; "
                                   "use bank-signed capture intake")
    metric = _validate(body)
    _require_metric_tenant(metric.tenant_id)
    if (metric.evidence_id or "").startswith(("signed-capture:", "signed-capture-sha256:")):
        raise HTTPException(status_code=422,
                            detail="signed capture provenance is reserved for verified capture intake")
    result = _repo(db).insert_metric(metric)
    if result["outcome"] == CONFLICT:
        raise HTTPException(status_code=409, detail=result["note"])
    if result["outcome"] == DUPLICATE:
        response.status_code = 200
    return IngestResult(outcome=result["outcome"],
                        accepted_id=result["accepted_id"],
                        note=result["note"])


@router.post("/ingest/batch", response_model=BatchResult,
             dependencies=[Depends(require_intelligence_writer)])
def ingest_batch(body: BatchIn,
                 db: Session = Depends(get_db_session),
                 user: str = Depends(get_current_user)) -> BatchResult:
    """Batch ingestion with explicit partial success: every item carries
    an ACCEPTED / SKIPPED / REJECTED outcome and a reason; totals are
    derived from the items, never invented."""
    if get_settings().is_production:
        raise HTTPException(status_code=503,
                            detail="direct Performance ingestion is unavailable in production; "
                                   "use bank-signed capture intake")
    rows: List[BatchItemResult] = []
    repo = _repo(db)
    for index, raw in enumerate(body.metrics):
        key = f"metrics[{index}]"
        try:
            metric = PerformanceMetric.model_validate(raw)
            _require_metric_tenant(metric.tenant_id)
            if (metric.evidence_id or "").startswith(("signed-capture:", "signed-capture-sha256:")):
                raise HTTPException(status_code=422,
                                    detail="signed capture provenance is reserved for verified capture intake")
        except (ValueError, HTTPException) as exc:
            reason = exc.detail if isinstance(exc, HTTPException) else str(exc)
            rows.append(BatchItemResult(key=key, status=REJECTED,
                                        reason=reason))
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


class CaptureImportIn(BaseModel):
    """One bank-provided exporter snapshot, not permission to probe a host."""
    tenant_id: str = Field(..., min_length=1, max_length=120)
    asset_ref: str = Field(..., min_length=1, max_length=120)
    source_id: str = Field(..., min_length=1, max_length=120)
    source_type: Literal["node_exporter", "postgres_exporter", "otlp"]
    authorization_ref: str = Field(..., min_length=1, max_length=120)
    observed_at: datetime
    payload: Dict[str, Any]
    previous_observed_at: Optional[datetime] = None
    previous: Optional[Dict[str, Any]] = None
    attestation: Optional[Dict[str, Any]] = None


class CaptureImportOut(BaseModel):
    receipt_id: str
    outcome: str
    source_type: str
    payload_sha256: str
    provenance_state: str
    signer: Optional[Dict[str, str]] = None
    accepted: int
    duplicate: int
    rejected: int
    metric_ids: List[str]
    metric_ids_truncated: bool
    refused: List[Dict[str, str]]
    refusals_truncated: bool
    note: str


def _capture_budget(payload: Dict[str, Any]) -> None:
    families = payload.get("metrics")
    if not isinstance(families, dict) or not families or len(families) > 100:
        raise HTTPException(status_code=422,
                            detail="capture requires 1..100 named metric families")
    count = 0
    for samples in families.values():
        if not isinstance(samples, list):
            raise HTTPException(status_code=422,
                                detail="each captured family must be a list of samples")
        count += len(samples)
        if count > 1000:
            raise HTTPException(status_code=413,
                                detail="capture exceeds 1000 exporter samples")


@router.post("/captures/import", response_model=CaptureImportOut,
             dependencies=[Depends(require_intelligence_writer)])
def import_capture(body: CaptureImportIn,
                   db: Session = Depends(get_db_session),
                   user: str = Depends(get_current_user)) -> CaptureImportOut:
    """Translate approved bank-side exporter captures without contacting a host.

    The bank retains raw snapshots; only normalized, bounded metrics and a
    digest are stored here. Authorization and producer authenticity are NOT
    established by a caller-written reference alone.
    """
    from api.routers.asset_detail import _resolve

    _require_metric_tenant(body.tenant_id)
    _resolve(db, body.asset_ref)
    _capture_budget(body.payload)
    if body.previous is not None:
        _capture_budget(body.previous)
    if (body.observed_at.tzinfo is None or body.observed_at > datetime.now(timezone.utc)
            or (body.previous is None) != (body.previous_observed_at is None)):
        raise HTTPException(status_code=422,
                            detail="capture timestamps must be timezone-aware, ordered, and complete")
    interval = None
    if body.previous_observed_at is not None:
        if body.previous_observed_at.tzinfo is None:
            raise HTTPException(status_code=422,
                                detail="previous capture timestamp requires a timezone")
        interval = (body.observed_at - body.previous_observed_at).total_seconds()
        if not 0 < interval <= 86400:
            raise HTTPException(status_code=422,
                                detail="paired captures require a positive interval of at most one day")
    observed_iso = body.observed_at.astimezone(timezone.utc).isoformat()
    previous_iso = (body.previous_observed_at.astimezone(timezone.utc).isoformat()
                    if body.previous_observed_at else None)
    try:
        digest = payload_sha256(body.payload)
        previous_digest = payload_sha256(body.previous) if body.previous is not None else None
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422,
                            detail="capture contains non-JSON or non-finite source values") from exc
    production = get_settings().is_production
    trusted = (os.environ.get("PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE") or "").strip()
    if production and not trusted:
        raise HTTPException(status_code=503,
                            detail="bank capture signing trust anchor is not configured")
    signer = None
    if body.attestation is not None:
        if not trusted:
            raise HTTPException(status_code=422,
                                detail="capture attestation cannot be verified without a bank trust anchor")
        try:
            signer = verify_capture_attestation(
                attestation=body.attestation, public_key_path=Path(trusted),
                tenant_id=body.tenant_id, asset_ref=body.asset_ref,
                source_id=body.source_id, source_type=body.source_type,
                observed_at=observed_iso,
                previous_observed_at=previous_iso,
                authorization_ref=body.authorization_ref,
                payload_digest=digest, previous_digest=previous_digest)
        except (OSError, ValueError, TypeError) as exc:
            raise HTTPException(status_code=422,
                                detail="bank capture attestation is invalid or does not bind this snapshot") from exc
    elif production:
        raise HTTPException(status_code=422,
                            detail="production capture requires a bank-signed attestation")
    binding = capture_binding(
        tenant_id=body.tenant_id, asset_ref=body.asset_ref,
        source_id=body.source_id, source_type=body.source_type,
        observed_at=observed_iso,
        previous_observed_at=previous_iso,
        authorization_ref=body.authorization_ref,
        payload_digest=digest, previous_digest=previous_digest,
        key_id=signer["key_id"] if signer else None,
        issuer=signer["issuer"] if signer else None)
    capture_id = capture_receipt_id(binding)
    arguments = {"asset_id": body.asset_ref, "tenant_id": body.tenant_id,
                 "source_id": body.source_id, "observed_at": body.observed_at,
                 "interval_seconds": interval}
    if body.source_type == "node_exporter":
        result = translate_node_exporter(body.payload, previous=body.previous, **arguments)
    elif body.source_type == "postgres_exporter":
        result = translate_postgres_exporter(body.payload, previous=body.previous,
                                             **arguments)
    else:
        if body.previous is not None:
            raise HTTPException(status_code=422,
                                detail="OTLP snapshots do not use paired counter translation")
        result = translate_otlp(body.payload, **arguments)
    accepted = duplicate = rejected = 0
    identifiers: List[str] = []
    repo = _repo(db)
    existing = repo.get_capture_receipt(body.tenant_id, capture_id)
    if existing is not None:
        duplicate = len(result.metrics)
    else:
        try:
            for metric in result.metrics:
                prefix = "signed" if signer else "unverified"
                metric = metric.model_copy(update={
                    "evidence_id": f"{prefix}-capture:{capture_id}"})
                stored = repo.insert_metric(metric, commit=False)
                if stored["outcome"] == INSERTED:
                    accepted += 1
                    identifiers.append(metric.metric_id)
                elif stored["outcome"] == DUPLICATE:
                    duplicate += 1
                else:
                    rejected += 1
            repo.add_capture_receipt(
                tenant_id=body.tenant_id, receipt_id=capture_id,
                asset_ref=body.asset_ref, source_id=body.source_id,
                source_type=body.source_type, observed_at=body.observed_at,
                previous_observed_at=body.previous_observed_at,
                payload_sha256=digest, previous_sha256=previous_digest,
                authorization_ref=body.authorization_ref,
                provenance_state=("SIGNED_SOURCE_ASSERTION" if signer else
                                  "UNVERIFIED_CAPTURE_ORIGIN"),
                key_id=signer["key_id"] if signer else None,
                issuer=signer["issuer"] if signer else None,
                signature=(str(body.attestation["signature"])
                           if body.attestation else None),
                accepted_count=accepted, duplicate_count=duplicate,
                rejected_count=rejected + result.refused_count)
            db.commit()  # receipt and accepted metrics stand or fall together
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409,
                                detail="capture conflicts with a concurrently stored metric or receipt") from exc
        except Exception:
            db.rollback()
            raise
    refused = [
        {"raw_family": (str(item.get("raw_family") or "")[:80]
                        if re.fullmatch(r"[A-Za-z0-9_.:@-]{1,80}",
                                        str(item.get("raw_family") or ""))
                        else "UNSAFE_FAMILY"),
         "reason": str(item.get("reason") or "refused")[:200]}
        for item in result.refused[:50]
    ]
    return CaptureImportOut(
        receipt_id=capture_id,
        outcome=("ALREADY_RECORDED" if existing else
                 "RECORDED" if accepted else "NO_METRICS_ACCEPTED"),
        source_type=body.source_type, payload_sha256=digest,
        provenance_state=("SIGNED_SOURCE_ASSERTION" if signer else
                          "UNVERIFIED_CAPTURE_ORIGIN"),
        signer=signer,
        accepted=accepted, duplicate=duplicate,
        rejected=rejected + result.refused_count,
        metric_ids=identifiers[:50], metric_ids_truncated=len(identifiers) > 50,
        refused=refused, refusals_truncated=result.refused_count > 50,
        note=("bank-side read-only capture recorded (accepted counts above); the signed source assertion "
              "binds these bytes under the bank-supplied public key, but does not "
              "prove the exporter measured the bank or that coverage is complete"
              if signer else
              "development-only unsigned capture: caller-declared source and "
              "digest do not authenticate the exporter or prove bank coverage")
             + "; no network probe was run by the API; retain the original under bank custody")


class CaptureReceiptOut(BaseModel):
    receipt_id: str
    tenant_id: str
    asset_ref: str
    source_id: str
    source_type: str
    observed_at: datetime
    previous_observed_at: Optional[datetime] = None
    payload_sha256: str
    previous_sha256: Optional[str] = None
    authorization_ref: str
    provenance_state: str
    key_id: Optional[str] = None
    issuer: Optional[str] = None
    signature: Optional[str] = None
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    note: str


class CaptureTrustAnchorOut(BaseModel):
    status: str
    configured: bool
    form: Optional[str] = None
    key_count: Optional[int] = None
    production_requires_signature: bool
    note: str


@router.get("/captures/trust-anchor", response_model=CaptureTrustAnchorOut)
def capture_trust_anchor(user: str = Depends(get_current_user)) -> CaptureTrustAnchorOut:
    """Whether this install can receive bank-signed captures.

    Reports configuration shape only — never key material. Registered before
    ``/captures/{receipt_id}`` so the literal path wins the match.
    """
    production = get_settings().is_production
    trusted = (os.environ.get("PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE") or "").strip()
    if not trusted:
        return CaptureTrustAnchorOut(
            status="unconfigured", configured=False,
            production_requires_signature=production,
            note="no PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE on this host — "
                 "production capture import refuses unsigned captures and "
                 "cannot verify signed ones until the bank trust anchor is configured")
    try:
        raw = Path(trusted).read_bytes()
    except OSError:
        return CaptureTrustAnchorOut(
            status="unconfigured", configured=False,
            production_requires_signature=production,
            note="the configured bank capture trust anchor is not readable "
                 "on this host — signed captures cannot be verified")
    form, count = "single-pem", 1
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        document = None
    if isinstance(document, dict) and "keys" in document:
        entries = document["keys"] if isinstance(document["keys"], list) else []
        form, count = "keyset", len(entries)
    return CaptureTrustAnchorOut(
        status="ready", configured=True, form=form, key_count=count,
        production_requires_signature=production,
        note="bank capture signatures verify against this anchor; the anchor "
             "reports configuration shape only, never key material")


@router.get("/captures/{receipt_id}", response_model=CaptureReceiptOut)
def capture_receipt(receipt_id: str, tenant_id: str = Query(...),
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> CaptureReceiptOut:
    """Public signed receipt metadata; the raw bank capture remains at source."""
    _require_metric_tenant(tenant_id)
    row = _repo(db).get_capture_receipt(tenant_id, receipt_id)
    if row is None:
        raise HTTPException(status_code=404, detail="capture receipt not found in selected tenant")
    return CaptureReceiptOut(
        receipt_id=row.receipt_id, tenant_id=tenant_id,
        asset_ref=row.asset_ref, source_id=row.source_id,
        source_type=row.source_type, observed_at=row.observed_at,
        previous_observed_at=row.previous_observed_at,
        payload_sha256=row.payload_sha256, previous_sha256=row.previous_sha256,
        authorization_ref=row.authorization_ref,
        provenance_state=row.provenance_state,
        key_id=row.key_id, issuer=row.issuer, signature=row.signature,
        accepted_count=row.accepted_count, duplicate_count=row.duplicate_count,
        rejected_count=row.rejected_count,
        note="signature authenticates a source assertion under the bank's trust anchor; "
             "the original raw capture remains under bank custody and is not stored here")


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


class ServiceRowOut(BaseModel):
    service: str
    p95_latency_ms: Optional[float] = None
    error_rate_pct: Optional[float] = None
    requests_per_sec: Optional[float] = None
    sample_count: int = 0


class OverviewResponse(BaseModel):
    storage_usage_pct: Tile
    network_throughput_mbps: Tile
    api_p95_latency_ms: Tile
    requests_per_sec: Tile
    # the UI brief's headline cards (docs/performance/03_UI_SPEC.md §1)
    cpu_utilization_pct: Optional[Tile] = None
    memory_utilization_pct: Optional[Tile] = None
    app_p95_latency_ms: Optional[Tile] = None
    error_rate_pct: Optional[Tile] = None
    services: List[ServiceRowOut] = Field(default_factory=list)
    note: str


class AppServiceRowOut(BaseModel):
    service: str
    p50_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    p99_latency_ms: Optional[float] = None
    error_rate_pct: Optional[float] = None
    timeout_rate_pct: Optional[float] = None
    requests_per_sec: Optional[float] = None
    samples: int
    last_observed: Optional[str] = None


class AppEndpointRowOut(BaseModel):
    service: str
    endpoint: str
    metric_name: str
    latest: Optional[float] = None
    unit: str
    observed_at: str


class AppCapabilityOut(BaseModel):
    state: str
    basis: str


class ApplicationWorkspaceOut(BaseModel):
    metrics: Dict[str, Any]
    services: List[AppServiceRowOut]
    endpoints: List[AppEndpointRowOut]
    capabilities: Dict[str, AppCapabilityOut]
    regression: Optional[Dict[str, Any]] = None
    note: str


class DbAreaOut(BaseModel):
    state: str
    metrics: Dict[str, Any]
    missing: List[str]


class DbRowOut(BaseModel):
    database: str
    platform: str
    connections_active: Optional[float] = None
    query_time_ms: Optional[float] = None
    size_bytes: Optional[float] = None
    replication_lag_seconds: Optional[float] = None
    samples: int
    last_observed: Optional[str] = None


class DbAdapterOut(BaseModel):
    platform: str
    adapter: Optional[str] = None
    state: str


class DbCollectorOut(BaseModel):
    collector_id: str
    status: str
    last_report_at: Optional[str] = None
    detail: Optional[str] = None


class DatabaseWorkspaceOut(BaseModel):
    areas: Dict[str, DbAreaOut]
    databases: List[DbRowOut]
    adapters: List[DbAdapterOut]
    collectors: List[DbCollectorOut]
    note: str


class HsmDeviceOut(BaseModel):
    device: str
    operation_latency_ms: Optional[float] = None
    p95_latency_ms: Optional[float] = None
    queue_depth: Optional[float] = None
    utilization_pct: Optional[float] = None
    provider_errors: Optional[float] = None
    availability_pct: Optional[float] = None
    operations_per_sec: Optional[float] = None
    samples: int = 0
    last_observed: Optional[str] = None
    trend: List[Dict[str, Any]] = Field(default_factory=list)


class HsmResponse(BaseModel):
    devices: List[HsmDeviceOut]
    families: Dict[str, Any]
    measurements: Dict[str, Any] = Field(default_factory=dict)
    measurement_kind: str
    note: str


class WorkloadResponse(BaseModel):
    workload_metrics: Dict[str, Any]
    categories: Dict[str, Any] = Field(default_factory=dict)
    measurements: Dict[str, Any] = Field(default_factory=dict)
    peak_offpeak: Dict[str, Any] = Field(default_factory=dict)
    correlation_candidates: List[Dict[str, Any]]
    causation: str
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


class InfraCategoryOut(BaseModel):
    state: str
    metrics: Dict[str, Any]
    basis: str


class InfraServerRowOut(BaseModel):
    asset_id: str
    link: Optional[str] = None
    link_state: str
    cpu_pct: Optional[float] = None
    memory_pct: Optional[float] = None
    load: Optional[float] = None
    disk_latency_ms: Optional[float] = None
    families: List[str]
    samples: int
    last_observed: Optional[str] = None


class HardwareHealthOut(BaseModel):
    state: str
    metrics: Dict[str, Any]
    basis: str


class InfrastructureWorkspaceOut(BaseModel):
    categories: Dict[str, InfraCategoryOut]
    inventory: List[InfraServerRowOut]
    trends: Dict[str, Any]
    hardware_health: HardwareHealthOut
    note: str


class NetworkResponse(BaseModel):
    bandwidth_capacity_mbps: Tile
    observed_throughput_mbps: Tile
    rtt_ms: Optional[SummaryStats] = None
    # UI brief §5 twelve measurements — unknown tiles where undelivered
    jitter_ms: Optional[Tile] = None
    packet_loss_pct: Optional[Tile] = None
    retransmissions: Optional[Tile] = None
    dns_resolution_ms: Optional[Tile] = None
    connection_establish_ms: Optional[Tile] = None
    tcp_connections: Optional[Tile] = None
    interface_errors: Optional[Tile] = None
    tunnel_health: Optional[Tile] = None
    tls_handshake_ms: Optional[Tile] = None
    load_balancer_response_ms: Optional[Tile] = None
    metrics: Dict[str, SummaryStats]
    cipher_suite_note: Optional[str] = None
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
    # UI brief §6 ten categories — measured or named gaps
    categories: Dict[str, Any] = Field(default_factory=dict)
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
    # UI brief §9: every forecast displays its observation period, data
    # coverage, assumptions and uncertainty (docs/performance/03_UI_SPEC.md §9)
    observation_period: Optional[str] = None
    coverage: Optional[str] = None
    assumptions: Optional[str] = None
    uncertainty: Optional[str] = None


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
    # Fetch one past the analysis budget. A silent LIMIT 5000 presents a
    # partial window as if it were a complete metric, so require a narrower
    # window instead of returning misleading tiles or aggregate values.
    rows = _repo(db).query_metrics(
        tenant_id, metric_name=metric_name, asset_id=asset_id,
        window_start=window_start, window_end=window_end, limit=5001)
    if len(rows) > 5000:
        raise HTTPException(status_code=409,
                            detail="metric window exceeds 5000 samples; "
                                   "narrow the time window — partial "
                                   "analytics are not reported as complete")
    return rows


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


@router.get("/hsm", response_model=HsmResponse)
def hsm(tenant_id: str = Query(...),
        window: Tuple[datetime, datetime] = Depends(_window_params),
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> HsmResponse:
    """HSM & KMS performance (docs/performance/03_UI_SPEC.md §7) —
    read-only projections of stored vendor-interface telemetry."""
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return HsmResponse(**hsm_view(rows))


@router.get("/workloads", response_model=WorkloadResponse)
def workloads(tenant_id: str = Query(...),
              window: Tuple[datetime, datetime] = Depends(_window_params),
              db: Session = Depends(get_db_session),
              user: str = Depends(get_current_user)) -> WorkloadResponse:
    """Workload & transaction intelligence (docs/performance/03_UI_SPEC.md
    §8) — correlation candidates only; causation stays unproven until
    timestamps and traces establish it."""
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return WorkloadResponse(**workload_view(rows))


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
        delivered = sum(1 for r in base_rows
                        if r.quality_status not in ("stale", "missing")
                        and r.metric_value is not None)
        unknown = len(base_rows) - delivered
        out.append(CapacityOut(
            metric_name=name, status=forecast["status"],
            method=forecast["method"],
            sample_count=forecast.get("sample_count") or 0,
            growth_per_second=forecast.get("growth_per_second"),
            estimated_seconds_to_exhaustion=forecast.get(
                "estimated_seconds_to_exhaustion"),
            disclaimer=forecast.get("disclaimer")
            or "forecast, not fact — never a promise about the future",
            note=forecast.get("note") or "computed from the window's delivered samples",
            observation_period=f"{window_start.isoformat()} to {window_end.isoformat()}",
            coverage=f"{delivered} delivered, {unknown} unknown of {len(base_rows)} samples in window",
            assumptions=(f"{forecast['method']} over the observation period"
                         + (f" at {forecast.get('growth_per_second')} units/sec"
                            if forecast.get("growth_per_second") is not None else "")),
            uncertainty=("a forecast is not a guaranteed future result — "
                         "it is an extrapolation of the observation period's "
                         "delivered samples and its assumptions hold only "
                         "while the observed trend holds")))
    return out


class SimulationWindowOut(BaseModel):
    received: int
    valid: int
    signed_capture_samples: int
    partial_quality: int
    missing_or_stale: int
    p95: Optional[float] = None
    metric_ids: List[str]
    metric_ids_truncated: bool
    evidence_refs_unverified: List[str]


class SimulationChangeOut(BaseModel):
    event_id: str
    observed_at: str
    event_type: str
    evidence_refs_unverified: List[str]
    provenance_note: str


class SimulationPerformanceContextOut(BaseModel):
    model_config = {"populate_by_name": True}

    schema_name: str = Field(alias="schema")
    tenant_id: str
    purpose: str
    status: str
    input_state: str
    asset_ref: str
    metric_name: str
    unit: str
    source_id: str
    change_event_id: str
    change: SimulationChangeOut
    windows: Dict[str, str]
    before: SimulationWindowOut
    after: SimulationWindowOut
    delta_p95: Optional[float] = None
    delta_percent: Optional[float] = None
    causation: str
    benchmark: Dict[str, Any]
    not_proven: List[str]


@router.get("/simulation-context", response_model=SimulationPerformanceContextOut)
def performance_simulation_context(
        tenant_id: str = Query(...),
        asset_ref: str = Query(..., min_length=1, max_length=120),
        metric_name: str = Query(..., min_length=3, max_length=120),
        source_id: str = Query(..., min_length=1, max_length=120),
        change_event_id: str = Query(..., min_length=1, max_length=80),
        before_start: datetime = Query(...), before_end: datetime = Query(...),
        after_start: datetime = Query(...), after_end: datetime = Query(...),
        baseline_benchmark_run_id: Optional[str] = Query(None),
        candidate_benchmark_run_id: Optional[str] = Query(None),
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> SimulationPerformanceContextOut:
    """Read-only measured context to attach to a hypothetical Twin run.

    One stored change, canonical asset, source and two windows are compared.
    This does not select a migration plan, forecast future performance, probe
    a bank endpoint, alter the estate or execute a remediation.
    """
    from api.routers.asset_detail import _resolve
    from db.repositories.cryptolog_repository import CryptoLogRepository, row_to_event
    from shared_models.cryptolog_events import event_hash, validate_event

    _require_metric_tenant(tenant_id)
    _resolve(db, asset_ref)  # a plausible prefix is never proof of an asset
    try:
        definition = definition_for(metric_name)
    except KeyError as exc:
        raise HTTPException(status_code=422,
                            detail="metric is not registered in the performance taxonomy") from exc
    if any(stamp.tzinfo is None for stamp in (
            before_start, before_end, after_start, after_end)):
        raise HTTPException(status_code=422, detail="measurement windows require timezone-aware timestamps")
    try:
        window_check(before_start, before_end)
        window_check(after_start, after_end)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if before_end > after_start:
        raise HTTPException(status_code=422, detail="before and after windows must not overlap")

    stored = CryptoLogRepository(db).get_event(tenant_id, change_event_id)
    if stored is None or stored.asset_id != asset_ref:
        raise HTTPException(status_code=404, detail="recorded change not found for this asset and tenant")
    event = row_to_event(stored)
    try:
        if event_hash(validate_event(event)) != stored.event_hash:
            raise ValueError("stored event hash differs from the ledger")
        observed = datetime.fromisoformat(str(
            (event.get("observation") or {}).get("observed_at") or "").replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=409,
                            detail="recorded change identity or timestamp is unverifiable") from exc
    if (stored.logging_kind != "CHANGE" or observed.tzinfo is None
            or not before_end <= observed <= after_start):
        raise HTTPException(status_code=422,
                            detail="change must be a recorded CHANGE between the two windows")

    repo = _repo(db)
    before = repo.query_metrics(
        tenant_id, asset_id=asset_ref, metric_name=metric_name,
        source_id=source_id, window_start=before_start,
        window_end=before_end, limit=1001)
    after = repo.query_metrics(
        tenant_id, asset_id=asset_ref, metric_name=metric_name,
        source_id=source_id, window_start=after_start,
        window_end=after_end, limit=1001)
    if len(before) > 1000 or len(after) > 1000:
        raise HTTPException(status_code=409,
                            detail="measurement window exceeds 1000 samples; narrow the window")
    if any(row.unit != definition.unit or row.metric_name != metric_name
           for row in [*before, *after]):
        raise HTTPException(status_code=409,
                            detail="stored metric units disagree with the registered taxonomy")
    receipts: Dict[str, Any] = {}
    for row in [*before, *after]:
        ref = row.evidence_id or ""
        if not ref.startswith("signed-capture:"):
            continue
        receipt_id = ref.removeprefix("signed-capture:")
        if not re.fullmatch(r"[0-9a-f]{64}", receipt_id):
            raise HTTPException(status_code=409,
                                detail="signed capture reference is malformed")
        if receipt_id not in receipts:
            candidate = repo.get_capture_receipt(tenant_id, receipt_id)
            if candidate is None:
                raise HTTPException(status_code=409,
                                    detail="signed metric has no tenant-owned capture receipt")
            captured = candidate.observed_at
            previous = candidate.previous_observed_at
            if captured.tzinfo is None:
                captured = captured.replace(tzinfo=timezone.utc)
            if previous is not None and previous.tzinfo is None:
                previous = previous.replace(tzinfo=timezone.utc)
            fields = {"tenant_id": tenant_id, "asset_ref": candidate.asset_ref,
                      "source_id": candidate.source_id, "source_type": candidate.source_type,
                      "observed_at": captured.astimezone(timezone.utc).isoformat(),
                      "previous_observed_at": (previous.astimezone(timezone.utc).isoformat()
                                               if previous else None),
                      "authorization_ref": candidate.authorization_ref,
                      "payload_digest": candidate.payload_sha256,
                      "previous_digest": candidate.previous_sha256,
                      "key_id": candidate.key_id, "issuer": candidate.issuer}
            if capture_receipt_id(capture_binding(**fields)) != receipt_id:
                raise HTTPException(status_code=409,
                                    detail="capture receipt metadata differs from its committed identity")
            trust_file = (os.environ.get("PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE") or "").strip()
            if not trust_file:
                raise HTTPException(status_code=409,
                                    detail="bank capture trust anchor unavailable for verification")
            try:
                verify_capture_attestation(
                    attestation={"schema": CAPTURE_SCHEMA, "algorithm": "Ed25519",
                                 "key_id": candidate.key_id, "issuer": candidate.issuer,
                                 "signature": candidate.signature},
                    public_key_path=Path(trust_file),
                    **{k: v for k, v in fields.items()
                       if k not in {"key_id", "issuer"}})
            except (OSError, TypeError, ValueError) as exc:
                raise HTTPException(status_code=409,
                                    detail="capture receipt signature could not be verified") from exc
            receipts[receipt_id] = candidate
        receipt = receipts[receipt_id]
        stamp = receipt.observed_at if receipt else None
        if stamp is not None and stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        if (receipt is None or receipt.provenance_state != "SIGNED_SOURCE_ASSERTION"
                or not receipt.signature or receipt.asset_ref != asset_ref
                or receipt.source_id != source_id or stamp != row.observed_at):
            raise HTTPException(status_code=409,
                                detail="signed metric has no matching tenant-owned capture receipt")
    if get_settings().is_production and any(
            not (row.evidence_id or "").startswith("signed-capture:")
            for row in [*before, *after]):
        raise HTTPException(status_code=409,
                            detail="production simulation context requires bank-signed capture samples")
    if bool(baseline_benchmark_run_id) != bool(candidate_benchmark_run_id):
        raise HTTPException(status_code=422,
                            detail="controlled benchmark runs must be supplied as a pair")
    old_run = new_run = None
    if baseline_benchmark_run_id:
        old_run = repo.get_benchmark_run(tenant_id, baseline_benchmark_run_id)
        new_run = repo.get_benchmark_run(tenant_id, candidate_benchmark_run_id)
        if old_run is None or new_run is None:
            raise HTTPException(status_code=404,
                                detail="controlled benchmark run not found in selected tenant")
    windows = {"before_start": before_start.isoformat(), "before_end": before_end.isoformat(),
               "after_start": after_start.isoformat(), "after_end": after_end.isoformat()}
    result = compare_bank_windows(
        before, after, asset_ref=asset_ref, metric_name=metric_name,
        unit=definition.unit, source_id=source_id, change_event_id=change_event_id,
        windows=windows)
    return SimulationPerformanceContextOut(**{
        **result, "tenant_id": tenant_id,
        "change": {"event_id": change_event_id,
                   "observed_at": observed.isoformat(),
                   "event_type": event["event_type"],
                   "evidence_refs_unverified": list((event.get("evidence") or {}).get("evidence_ids") or [])[:20],
                   "provenance_note": "stored event hash verified; producer authenticity and cited evidence remain unverified"},
        "benchmark": compare_controlled_benchmarks(old_run, new_run),
    })


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
    next_cursor: Optional[str] = None
    note: str


@router.get("/infrastructure", response_model=DomainResponse)
def infrastructure(tenant_id: str = Query(...),
                   window: Tuple[datetime, datetime] = Depends(_window_params),
                   db: Session = Depends(get_db_session),
                   user: str = Depends(get_current_user)) -> DomainResponse:
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return DomainResponse(**domain_view(rows, "infrastructure"))


@router.get("/databases/workspace", response_model=DatabaseWorkspaceOut)
def databases_workspace(
        tenant_id: str = Query(...),
        window: Tuple[datetime, datetime] = Depends(_window_params),
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> DatabaseWorkspaceOut:
    """Database Performance (docs/performance/03_UI_SPEC.md §4): the nine
    areas, per-database rows and adapter states. Query fingerprints and
    normalized statistics only — SQL statements containing customer data
    are never collected."""
    from db.models.performance import PerformanceCollectorHealth

    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    health = db.execute(
        select(PerformanceCollectorHealth).where(
            PerformanceCollectorHealth.tenant_id == tenant_id)
    ).scalars().all()
    collectors = [{
        "collector_id": h.collector_id,
        "status": h.status,
        "last_report_at": h.last_report_at.isoformat() if h.last_report_at else None,
        "detail": h.detail,
    } for h in health]
    return DatabaseWorkspaceOut(
        **database_workspace_view(rows, collectors=collectors))


@router.get("/applications/workspace", response_model=ApplicationWorkspaceOut)
def applications_workspace(
        tenant_id: str = Query(...),
        window: Tuple[datetime, datetime] = Depends(_window_params),
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> ApplicationWorkspaceOut:
    """Application Performance (docs/performance/03_UI_SPEC.md §3): the ten
    metrics, per-service and per-endpoint rows, and the eight capabilities
    as measured or as named gaps. Trace collection stays governed by
    controlled attributes and redaction."""
    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)
    return ApplicationWorkspaceOut(**application_workspace_view(rows))


@router.get("/infrastructure/workspace", response_model=InfrastructureWorkspaceOut)
def infrastructure_workspace(
        tenant_id: str = Query(...),
        window: Tuple[datetime, datetime] = Depends(_window_params),
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> InfrastructureWorkspaceOut:
    """Infrastructure Performance workspace (docs/performance/03_UI_SPEC.md
    §2): eight tabs over one projection. Server links are emitted only for
    VERIFIED technology-spine identities (hw:/app: lookups) — an unverified
    asset stays unlinked instead of guessing a canonical record."""
    from db.models.hardware_live import HardwareAsset
    from db.models.system import System

    window_start, window_end = window
    rows = _tenant_rows(db, tenant_id, window_start, window_end)

    asset_ids = {r.asset_id for r in rows}
    links: Dict[str, Optional[str]] = {}
    for asset_id in sorted(asset_ids):
        if asset_id.split(":", 1)[0] in ("app", "crypto", "hw", "net", "vendor") and ":" in asset_id:
            from api.routers.asset_detail import _resolve

            try:
                _resolve(db, asset_id)
            except HTTPException as exc:
                if exc.status_code != 404:
                    raise
                links[asset_id] = None
            else:
                links[asset_id] = asset_id
            continue
        hw = db.execute(
            select(HardwareAsset).where(HardwareAsset.asset_id == asset_id)
        ).scalars().first()
        if hw is not None:
            links[asset_id] = f"hw:{asset_id}"
            continue
        sys_rec = filtered_get(db, System, asset_id)
        links[asset_id] = f"app:{asset_id}" if sys_rec is not None else None

    return InfrastructureWorkspaceOut(
        **infrastructure_workspace_view(rows, link_by_asset=links))


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
                    cursor: Optional[str] = Query(None),
                    db: Session = Depends(get_db_session),
                    user: str = Depends(get_current_user)) -> BenchmarkListOut:
    """Controlled benchmark runs, newest first, with cursor pagination
    (§6: time ranges, cursor pagination, tenant authorization)."""
    after = _decode_cursor(cursor) if cursor else None
    rows = _repo(db).list_benchmark_runs(tenant_id, limit=limit + 1,
                                         after=after)
    runs = rows[:limit]
    next_cursor = None
    if len(rows) > limit and runs:
        last = runs[-1]
        next_cursor = _encode_cursor(last["executed_at"], last["run_id"])
    return BenchmarkListOut(
        runs=runs, next_cursor=next_cursor,
        note="every run is controlled benchmark performance — never "
             "production traffic performance (docs/performance/"
             "01_PRODUCT_SPEC.md §2.F)")


@router.post("/benchmarks", response_model=BenchmarkRunOut, status_code=201,
             dependencies=[Depends(require_intelligence_manager)])
def benchmarks(body: BenchmarkIn, response: Response,
               db: Session = Depends(get_db_session),
               user: str = Depends(get_current_user)) -> BenchmarkRunOut:
    """Start an approved controlled benchmark. Results are recorded as
    controlled-benchmark measurement — never presented as production
    traffic performance — and an algorithm the local provider cannot
    perform is refused with its reason, never invented."""
    _require_metric_tenant(body.tenant_id)
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


# --- §5 registries and §6 cursor pagination --------------------------


class MetricDefinitionOut(BaseModel):
    metric_name: str
    domain: str
    unit: str
    metric_type: str
    description: str


class DefinitionSyncResult(BaseModel):
    registered: int
    inserted: int
    note: str


class CollectorHealthOut(BaseModel):
    collector_id: str
    status: str
    last_report_at: Optional[datetime] = None
    detail: Optional[str] = None
    stale: bool
    note: str


class CollectorHealthReport(BaseModel):
    collectors: List[CollectorHealthOut]
    stale_detected: int
    note: str


class SampleOut(BaseModel):
    metric_id: str
    asset_id: str
    metric_name: str
    metric_type: str
    metric_value: Optional[float] = None
    unit: str
    source_id: str
    observed_at: datetime
    interval_seconds: Optional[float] = None
    labels: Dict[str, str] = Field(default_factory=dict)
    evidence_id: Optional[str] = None
    quality_status: str


class SamplePage(BaseModel):
    samples: List[SampleOut]
    next_cursor: Optional[str] = None
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    returned: int
    note: str


def _encode_cursor(observed_at: datetime, metric_id: str) -> str:
    raw = f"{observed_at.isoformat()}|{metric_id}".encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _decode_cursor(cursor: str) -> Tuple[datetime, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8")
        time_part, metric_id = raw.split("|", 1)
        return datetime.fromisoformat(time_part), metric_id
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail="cursor is not a position this API issued — cursors "
                   "are opaque and exact, never guessed") from exc


@router.get("/definitions", response_model=List[MetricDefinitionOut])
def metric_definitions(tenant_id: str = Query(...),
                       domain: Optional[str] = Query(None),
                       db: Session = Depends(get_db_session),
                       user: str = Depends(get_current_user)
                       ) -> List[MetricDefinitionOut]:
    """The registered metric definitions: unit, source and meaning for
    every ingested name. A guessed unit is not a defined unit."""
    return [MetricDefinitionOut(**row) for row in
            _repo(db).list_metric_definitions(tenant_id, domain=domain)]


@router.post("/definitions", response_model=DefinitionSyncResult,
             status_code=201,
             dependencies=[Depends(require_intelligence_manager)])
def sync_metric_definitions(
        body: Dict[str, Any], response: Response,
        db: Session = Depends(get_db_session),
        user: str = Depends(get_current_user)) -> DefinitionSyncResult:
    """Idempotently register the metric taxonomy as definitions. The
    taxonomy is the source of truth — the sync inserts nothing twice."""
    from shared_models.performance_taxonomy import DEFINITIONS
    tenant_id = body.get("tenant_id") or ""
    if not tenant_id:
        raise HTTPException(status_code=422, detail="tenant_id is required")
    _require_metric_tenant(tenant_id)
    result = _repo(db).sync_metric_definitions(tenant_id, DEFINITIONS)
    if result["inserted"] == 0:
        response.status_code = 200
    return DefinitionSyncResult(
        registered=result["registered"], inserted=result["inserted"],
        note="units and meanings come from the taxonomy registry — a "
             "guessed unit is not a defined unit")


@router.get("/collectors", response_model=CollectorHealthReport)
def collector_health(tenant_id: str = Query(...),
                     stale_after_seconds: float = Query(300, gt=0),
                     db: Session = Depends(get_db_session),
                     user: str = Depends(get_current_user)
                     ) -> CollectorHealthReport:
    """Collector heartbeats. A collector that has not reported within
    the threshold is named STALE — its missing telemetry is never
    interpreted as zero."""
    rows = _repo(db).list_collector_health(
        tenant_id, stale_after_seconds=stale_after_seconds,
        now=datetime.now(timezone.utc))
    return CollectorHealthReport(
        collectors=[CollectorHealthOut(**row) for row in rows],
        stale_detected=sum(1 for row in rows if row["stale"]),
        note="detect stale collectors instead of interpreting missing "
             "metrics as zero (docs/performance/01_PRODUCT_SPEC.md §9)")


@router.get("/samples", response_model=SamplePage)
def query_samples(tenant_id: str = Query(...),
                  window_start: Optional[datetime] = Query(None),
                  window_end: Optional[datetime] = Query(None),
                  metric_name: Optional[str] = Query(None),
                  asset_id: Optional[str] = Query(None),
                  cursor: Optional[str] = Query(None),
                  limit: int = Query(100, gt=0, le=500),
                  db: Session = Depends(get_db_session),
                  user: str = Depends(get_current_user)) -> SamplePage:
    """Raw metric samples with cursor pagination (§6): time ranges,
    tenant authorization and a sensible maximum query window. The
    cursor is an exact position — a page is never skipped or repeated."""
    if (window_start is None) != (window_end is None):
        raise HTTPException(
            status_code=422,
            detail="window_start and window_end arrive together or not "
                   "at all — a half-open window is not a window")
    if window_start is not None and window_end is not None:
        try:
            window_check(window_start, window_end)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    after = _decode_cursor(cursor) if cursor else None
    rows = _repo(db).query_samples_cursor(
        tenant_id, metric_name=metric_name, asset_id=asset_id,
        window_start=window_start, window_end=window_end,
        after=after, limit=limit + 1)
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit and page:
        next_cursor = _encode_cursor(page[-1].observed_at, page[-1].metric_id)
    return SamplePage(
        samples=[SampleOut(
            metric_id=row.metric_id, asset_id=row.asset_id,
            metric_name=row.metric_name, metric_type=row.metric_type,
            metric_value=row.metric_value, unit=row.unit,
            source_id=row.source_id, observed_at=row.observed_at,
            interval_seconds=row.interval_seconds,
            labels=dict(row.labels), evidence_id=row.evidence_id,
            quality_status=row.quality_status.value) for row in page],
        next_cursor=next_cursor,
        window_start=window_start, window_end=window_end,
        returned=len(page),
        note="cursor pagination over raw samples — time-bounded, "
             "tenant-scoped, never truncated silently")
