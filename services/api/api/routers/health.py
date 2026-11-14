import logging
import time
from datetime import datetime

from db.connection.engine import check_db_health
from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)

#: Wall-clock budget for the readiness database probe.
#:
#: Chosen to sit inside a typical Kubernetes readinessProbe timeoutSeconds
#: (commonly 5-10 s) so the endpoint answers 503 itself rather than being
#: recorded as a probe timeout. Answering is strictly better: a 503 says
#: "drain me, I am alive"; a timeout is indistinguishable from a wedged
#: process and will eventually be read as a liveness problem too.
READINESS_PROBE_TIMEOUT_SECONDS = 4.0


def _probe(name: str, configured: bool, fn) -> dict:
    """Run one dependency probe with an honest status:
    ok (reachable), down (configured but failing), or skipped (not configured).
    Each probe is timeout-bounded by the underlying client and never raises."""
    if not configured:
        return {"name": name, "status": "skipped", "detail": "not configured"}
    start = time.perf_counter()
    try:
        detail = fn() or "ok"
        return {"name": name, "status": "ok", "detail": detail,
                "latency_ms": round((time.perf_counter() - start) * 1000, 1)}
    except Exception as exc:  # a dependency outage must never 500 the health call
        return {"name": name, "status": "down", "detail": "Dependency probe failed",
                "error_type": type(exc).__name__,
                "latency_ms": round((time.perf_counter() - start) * 1000, 1)}


def dependency_report() -> dict:
    """Status of every backing service the platform can use. Optional
    dependencies report `skipped` when not configured, so the overall
    rollup only goes `degraded` when a configured dependency is down."""
    settings = get_settings()

    def _db():
        health = check_db_health()
        if health.get("status") != "healthy":
            raise RuntimeError(health.get("error", "database unhealthy"))
        return health.get("dialect", "database")

    def _redis():
        from shared_models.redis_connection import connection_settings, verified_redis_client
        client = verified_redis_client(connection_settings(settings, "health"), socket_timeout=1)
        try:
            client.ping()
            return "pong"
        finally:
            try:
                client.close()
            except Exception as close_exc:
                # Closing a failed probe must not mask its original status.
                logger.warning("redis_health_client_close_failed", extra={"error_type": type(close_exc).__name__})

    def _neo4j():
        from graph_engine.connection.neo4j_driver import get_driver

        driver = get_driver()
        if driver is None:
            return "skipped"
        driver.verify_connectivity()
        return "connected"

    from shared_models.redis_connection import connection_settings
    redis_configured = bool(connection_settings(settings, "health").REDIS_URL.strip())
    redis_required = bool(getattr(settings, "is_production", False))
    checks = [
        _probe("database", True, _db),
        _probe("redis", redis_configured or redis_required, _redis),
        _probe("neo4j", bool((settings.NEO4J_URI or "").strip()), _neo4j),
    ]
    if redis_required and not redis_configured:
        checks[1] = {"name": "redis", "status": "down",
                     "detail": "REDIS_URL is required in production"}
    # A reachable Redis server is not enough: production readiness requires the
    # Stream/sequence adapter to have initialized as well.
    operator_profile = getattr(settings, "CRYPTOSCAN_DEPLOYMENT_PROFILE", "") == "kubernetes-external-services/local-source-v1"
    if redis_required and operator_profile:
        checks.append({"name": "realtime_events", "status": "skipped",
                       "detail": "Explicit controlled operator profile disables realtime; decisions reconcile from SQL"})
    if redis_required and not operator_profile:
        try:
            from api.events.bus import get_event_bus

            realtime = (get_event_bus().stats().get("durable_backend") or {})
            if not realtime.get("ready"):
                checks.append({"name": "realtime_events", "status": "down",
                               "detail": "Redis event journal is not ready"})
        except Exception as exc:  # noqa: BLE001
            checks.append({"name": "realtime_events", "status": "down",
                           "detail": type(exc).__name__})
    down = [c["name"] for c in checks if c["status"] == "down"]
    overall = "degraded" if down else "ok"
    return {"status": overall, "down": down, "checks": checks}


@router.get("/healthz")
def healthz():
    """Liveness only: is this process able to serve? No dependency checks.

    This used to return check_db_health() inline, which made the liveness
    probe depend on PostgreSQL answering. The contract stated two lines down
    in readyz -- "Liveness (/healthz) stays 200 through a DB outage" -- was
    therefore not what the code did.

    The existing test did not catch it because it mocks an engine that
    *raises* immediately. A real outage does not raise, it blocks: with the
    database container paused this endpoint hung for the full 20 s probe
    budget, so Kubernetes would record a liveness failure and kill a pod
    whose only problem is that the database is briefly away -- a restart
    storm at precisely the moment the database is already struggling.

    Database state is still reported, by the two endpoints whose job it is:
    /readyz (503 drains the load balancer) and /healthz/dependencies.
    """
    return {"status": "ok"}


@router.get("/healthz/dependencies")
def healthz_dependencies():
    """Component-level dependency health (DB / Redis / Neo4j).

    Read-only and unauthenticated like the other probes; each dependency is
    checked with a short timeout and reported as ok / down / skipped. The
    response is 200 when the API is serving (dependencies that are *optional*
    may be down without taking the process out), and the `status`/`down`
    fields tell dashboards and operators what actually needs attention.
    """
    return dependency_report()


@router.get("/readyz")
def readyz():
    """Readiness for LB drain: 503 until the database answers again.

    Liveness (/healthz) stays 200 through a DB outage — the process is fine
    and keeps retrying; readiness tells nginx/kubernetes to stop routing to
    this replica until the failover completes.

    A draining process (begin_drain at shutdown) answers 503 immediately:
    the load balancer stops routing while in-flight requests finish, so a
    rolling restart is a drain, never a reset.
    """
    from api import drain

    if drain.is_draining():
        return JSONResponse(status_code=503, content={
            "status": "draining",
            "detail": ("this replica is draining: in-flight requests are "
                       "finishing and no new traffic should be routed here"),
            **drain.as_dict(),
        })
    import concurrent.futures

    from db.connection.engine import get_engine
    from sqlalchemy import text

    def _probe() -> None:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))

    # Bounded on wall clock, not just on the driver's own timeouts.
    #
    # Unreachable is not the same as refused. A paused or partitioned
    # database accepts the TCP connection and never answers, so pool
    # pre-ping and pool checkout each wait out their own timeout and stack:
    # measured at over 25 s here, well past any sane probe budget. The
    # endpoint then fails by *timing out* rather than by answering 503,
    # which looks identical to the API being wedged and ties up a worker
    # thread for the whole duration on every probe interval.
    #
    # A readiness probe that cannot answer inside its budget is not a
    # readiness probe, so the slow path is turned into an explicit 503.
    # Deliberately not a `with` block: ThreadPoolExecutor.__exit__ calls
    # shutdown(wait=True), which blocks until the probe thread finishes and
    # so waits out the very stall the timeout exists to escape. On timeout
    # the executor is released without waiting and the orphaned thread ends
    # on its own when the driver's own timeout expires.
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1,
                                                 thread_name_prefix="readyz-probe")
    try:
        pool.submit(_probe).result(timeout=READINESS_PROBE_TIMEOUT_SECONDS)
        pool.shutdown(wait=False)
    except concurrent.futures.TimeoutError:
        pool.shutdown(wait=False, cancel_futures=True)
        return JSONResponse(status_code=503, content={
            "status": "not_ready",
            "database": (f"no answer within {READINESS_PROBE_TIMEOUT_SECONDS}s "
                         "(unreachable, not refused)"),
        })
    except Exception as exc:
        pool.shutdown(wait=False)
        logger.warning("readiness_database_probe_failed", extra={"error_type": type(exc).__name__})
        return JSONResponse(status_code=503, content={"status": "not_ready", "database": "Database probe failed",
                                                     "error_type": type(exc).__name__})
    settings = get_settings()
    migration = None
    if getattr(settings, "is_production", False):
        from db.connection.session import migration_status

        migration = migration_status(get_engine())
        if migration.get("status") != "current":
            return JSONResponse(status_code=503, content={
                "status": "not_ready", "database": "ok", "migrations": migration,
            })
        report = dependency_report()
        if report.get("down"):
            return JSONResponse(status_code=503, content={
                "status": "not_ready", "dependencies": report, "migrations": migration,
            })
    return {"status": "ready", "database": "ok", **({"migrations": migration} if migration else {})}


@router.get("/healthz/schema")
def healthz_schema():
    """Schema drift report: models vs the live database."""
    from db.connection.engine import get_engine
    from db.connection.schema_ensure import schema_drift_report

    return schema_drift_report(get_engine())


@router.get("/meta")
def meta():
    settings = get_settings()
    return {
        "name": "CryptoScan",
        "version": settings.API_VERSION,
        "environment": settings.ENVIRONMENT,
        "docs_enabled": settings.docs_enabled,
    }


@router.get("/discovery/plugins")
def discovery_plugins():
    try:
        from scanner.core.plugin import plugin_catalog

        return {"plugins": plugin_catalog()}
    except Exception:
        return {"plugins": []}


# ----------------------------------------------- worker-fleet independent probe
#: A RUNNING scan job with no update for this long is STUCK — surfaced as
#: stuck, not failed, so operators can tell a wedged worker from a bad scan
#: (product vision §5: distinguish RUNNING, stuck, partial, refused, failed).
STUCK_RUNNING_AFTER_S = 15 * 60
#: An event leased but not completed for this long is a STALE LEASE — the
#: consumer died mid-lease; the row never completes on its own.
STALE_LEASE_AFTER_S = 10 * 60
#: Work waiting longer than this with no drain evidence is a backlog.
BACKLOG_AFTER_S = 15 * 60


def _as_dt(value):
    """Coerce a row value to an aware datetime (SQLite text() rows come
    back as ISO strings; ORM datetimes may be naive). None passes through."""
    if value is None or isinstance(value, datetime):
        return value
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed


def _age_s(value, now) -> int | None:
    """Age in seconds of a possibly-naive datetime (assumed UTC)."""
    if value is None:
        return None
    from datetime import timezone as _tz

    stamp = value if value.tzinfo else value.replace(tzinfo=_tz.utc)
    return max(0, int((now - stamp).total_seconds()))


def worker_fleet(db: Session) -> dict:
    """Independent queue / worker-pool health (§5, round 78).

    The console used to report "Not measured" for the worker fleet because
    the only signal was API liveness — which is not evidence that anything
    consumes the queues. This probe measures the real observed state
    instead, from the durable records themselves:

    - scan jobs: per-status counts, oldest queued age, STUCK running jobs
      (no update within the threshold), completions/failures in the last
      hour;
    - the control-plane event queue: depth, oldest waiting age, in-flight
      leases, STALE leases, dead letters, completions in the last hour;
    - the worker tier's monitor lease (``monitor_leases``): holder,
      heartbeat age and liveness — the only true independent worker
      heartbeat in the platform.

    Drain evidence = completions in the last hour OR a live monitor lease:
    proof that something is consuming, independent of this API. Status is
    never derived from API liveness and never fabricated: an idle system
    with no live heartbeat and no recent completions reports "Not
    measured" (nothing current to measure), not Operational.
    """
    from datetime import timedelta, timezone

    from sqlalchemy import func, text

    from db.models.control_plane import QueuedEvent
    from db.models.scan_job import ScanJob

    now = datetime.now(timezone.utc)

    # ---- scan jobs (durable job pipeline) ---------------------------------
    job_status = dict(
        db.query(ScanJob.status, func.count(ScanJob.id)).group_by(ScanJob.status).all()
    )
    oldest_queued = db.query(func.min(ScanJob.created_at)).filter(
        ScanJob.status == "QUEUED").scalar()
    stuck_running = db.query(func.count(ScanJob.id)).filter(
        ScanJob.status == "RUNNING",
        ScanJob.updated_at < now - timedelta(seconds=STUCK_RUNNING_AFTER_S),
    ).scalar()
    hour_ago = now - timedelta(hours=1)
    jobs_completed_1h = db.query(func.count(ScanJob.id)).filter(
        ScanJob.status == "COMPLETED", ScanJob.completed_at >= hour_ago).scalar()
    jobs_failed_1h = db.query(func.count(ScanJob.id)).filter(
        ScanJob.status == "FAILED", ScanJob.completed_at >= hour_ago).scalar()

    # ---- control-plane event queue (outbox/inbox) ------------------------
    event_status = dict(
        db.query(QueuedEvent.status, func.count(QueuedEvent.id))
        .group_by(QueuedEvent.status).all()
    )
    oldest_event = db.query(func.min(QueuedEvent.available_at)).filter(
        QueuedEvent.status == "queued").scalar()
    stale_leases = db.query(func.count(QueuedEvent.id)).filter(
        QueuedEvent.status == "leased",
        QueuedEvent.leased_at < now - timedelta(seconds=STALE_LEASE_AFTER_S),
    ).scalar()
    events_completed_1h = db.query(func.count(QueuedEvent.id)).filter(
        QueuedEvent.status == "completed",
        QueuedEvent.completed_at >= hour_ago).scalar()

    # ---- worker tier heartbeat (monitor leader lease) --------------------
    heartbeat: dict = {"measured": False}
    try:
        row = db.execute(text(
            "SELECT holder, expires_at, updated_at FROM monitor_leases "
            "WHERE name = 'monitor'")).first()
    except Exception:  # table absent in this deployment — honest absence
        row = None
        db.rollback()  # a failed statement poisons the transaction
        heartbeat["reason"] = "monitor_leases table absent — no worker heartbeat source"
    if row is not None:
        holder, expires_at, updated_at = row
        heartbeat = {
            "measured": True,
            "holder": holder,
            "heartbeat_age_s": _age_s(_as_dt(updated_at), now),
            "lease_live": bool(_as_dt(expires_at) is not None
                               and _as_dt(expires_at) > now),
        }

    oldest_queued_s = _age_s(_as_dt(oldest_queued), now)
    oldest_event_s = _age_s(_as_dt(oldest_event), now)
    completions_1h = int(jobs_completed_1h or 0) + int(events_completed_1h or 0)
    drain_evidence = completions_1h > 0 or heartbeat.get("lease_live")

    total_jobs = sum(job_status.values())
    total_events = sum(event_status.values())

    reasons: list[str] = []
    if int(stuck_running or 0) > 0:
        reasons.append(f"{stuck_running} running job(s) stuck "
                       f"(no update in {STUCK_RUNNING_AFTER_S // 60} min)")
    if int(stale_leases or 0) > 0:
        reasons.append(f"{stale_leases} stale event lease(s) "
                       f"(no completion in {STALE_LEASE_AFTER_S // 60} min)")
    backlog = ((oldest_queued_s is not None and oldest_queued_s > BACKLOG_AFTER_S)
               or (oldest_event_s is not None and oldest_event_s > BACKLOG_AFTER_S))
    if backlog and not drain_evidence:
        reasons.append("work waiting beyond threshold with no drain observed "
                       "in the last hour")

    if total_jobs == 0 and total_events == 0 and not heartbeat.get("measured"):
        status = "Not measured"
        detail = ("no scan jobs, no queued events and no worker heartbeat "
                  "source observed — nothing to measure the fleet from")
    elif reasons:
        status = "Degraded"
        detail = "; ".join(reasons)
    elif drain_evidence:
        status = "Operational"
        detail = (f"drain observed: {completions_1h} completion(s) in the last hour"
                  + (f", live monitor lease ({heartbeat.get('holder')})"
                     if heartbeat.get("lease_live") else ""))
    else:
        status = "Not measured"
        detail = ("idle — no work waiting and no live worker heartbeat; "
                  "current fleet state is not measurable from records")

    return {
        "status": status,
        "detail": detail,
        "jobs": {
            "by_status": job_status,
            "total": total_jobs,
            "oldest_queued_s": oldest_queued_s,
            "stuck_running": int(stuck_running or 0),
            "completed_last_hour": int(jobs_completed_1h or 0),
            "failed_last_hour": int(jobs_failed_1h or 0),
        },
        "event_queue": {
            "by_status": event_status,
            "total": total_events,
            "oldest_queued_s": oldest_event_s,
            "stale_leases": int(stale_leases or 0),
            "completed_last_hour": int(events_completed_1h or 0),
        },
        "worker_heartbeat": heartbeat,
        "thresholds": {
            "stuck_running_after_s": STUCK_RUNNING_AFTER_S,
            "stale_lease_after_s": STALE_LEASE_AFTER_S,
            "backlog_after_s": BACKLOG_AFTER_S,
        },
        "drain_evidence": {
            "completions_last_hour": completions_1h,
            "lease_live": bool(heartbeat.get("lease_live")),
        },
        "note": (
            "Measured from the durable records themselves (scan jobs, the "
            "control-plane event queue, the worker monitor lease) — never "
            "from API liveness. Stuck running jobs and stale leases are "
            "surfaced as such, not as failures; an idle fleet with no live "
            "heartbeat reports Not measured, not Operational."
        ),
    }


@router.get("/health/worker-fleet")
def worker_fleet_health(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """The console's view of the fleet: the measurement plus its evidence.

    Same function as the probe below, so a console and an orchestrator cannot
    disagree about whether anything is consuming.
    """
    return worker_fleet(db)


class WorkerLivenessOut(BaseModel):
    """The probe's answer: what the fleet is doing, and the evidence for it."""

    schema_: str = Field(default="cryptoscan.worker-liveness/1", alias="schema")
    status: str
    detail: str
    drain_evidence: dict
    jobs_queued_oldest_s: int | None = None
    jobs_stuck_running: int
    event_leases_stale: int
    worker_heartbeat: dict
    meaning: str

    model_config = {"populate_by_name": True}


@router.get("/healthz/workers", response_model=WorkerLivenessOut)
def workers_liveness(
    request: Request,
    response: Response,
    db: Session = Depends(get_db_session),
):
    """A worker probe an orchestrator can call (guide 117, second pass).

    Liveness of the *API* process is ``/healthz``; readiness of its dependencies
    is ``/readyz``. Neither of them answers the question a bank actually pages
    on: **is anything consuming the queue?** The fleet probe existed for the
    console, behind a session — which a Kubernetes liveness/readiness probe
    cannot present. This is the same measurement, unauthenticated the way
    ``/metrics`` is (and gated by the same token in production), with the one
    status that deserves a non-200 mapped to it:

    * ``Operational`` / ``Not measured`` → 200: the fleet is draining, or there
      is nothing to drain and no evidence either way (an idle system is not an
      outage);
    * ``Degraded`` → 503: work is waiting past the threshold with no drain
      observed, or jobs/leases are stuck. That is the condition a probe exists
      to catch.
    """
    from api.security.machine_tokens import require_metrics_token

    # The metric scrape's token, not the session: a probe has no cookie jar.
    require_metrics_token(request)
    report = worker_fleet(db)
    # The status is the answer, not an error: 503 says "drain me / page someone".
    response.status_code = 503 if report["status"] == "Degraded" else 200
    return {
        "schema": "cryptoscan.worker-liveness/1",
        "status": report["status"],
        "detail": report["detail"],
        "drain_evidence": report["drain_evidence"],
        "jobs_queued_oldest_s": report["jobs"]["oldest_queued_s"],
        "jobs_stuck_running": report["jobs"]["stuck_running"],
        "event_leases_stale": report["event_queue"]["stale_leases"],
        "worker_heartbeat": report["worker_heartbeat"],
        "meaning": (
            "liveness answers 'is the process up', readiness answers 'can it serve', "
            "this answers 'is anything consuming' — measured from the durable job and "
            "lease records, never from API liveness"
        ),
    }


# ------------------------------------------------- connector health probe
#: How many recent delivery attempts per integration the probe considers
#: (the audit window — recent outcomes, not all history).
CONNECTOR_WINDOW = 50


@router.get("/health/connectors")
def connectors_health(
    user: str = Depends(get_current_user),
    db: Session = Depends(get_db_session),
):
    """Independent connector health (§4.8, round 79) — measured, never
    inferred from registration.

    A registered integration with the ``enabled`` flag set is NOT evidence
    that the external system is reachable or accepting events. The only
    independent measurement the platform keeps is the outbound delivery
    audit (``cp_delivery_logs`` — one row per REAL signed HTTP attempt, or
    per air-gap skip). This probe reports, per registered connector:

    - the last delivery outcome and its age (delivered / failed / skipped);
    - recent-window attempt counts by status;
    - an honest verdict: Operational (last attempt delivered), Degraded
      (last attempt failed), Outbox/air-gap (no endpoint configured —
      events are retained, delivery is not claimed), Disabled, or
      **Not measured** when the connector has never produced a delivery
      attempt — registration alone is not health, and no synthetic
      "connected" status is derived.
    """
    from datetime import timezone

    from db.models.control_plane import DeliveryLog
    from db.repositories.enterprise_repository import EnterpriseRepository

    now = datetime.now(timezone.utc)

    integrations = EnterpriseRepository(db).list_integrations()

    # newest-first window per integration (bounded scan of the audit trail)
    logs = (
        db.query(DeliveryLog)
        .order_by(DeliveryLog.created_at.desc(), DeliveryLog.id.desc())
        .limit(CONNECTOR_WINDOW * max(1, len(integrations)))
        .all()
    )
    by_integration: dict[str, list[DeliveryLog]] = {}
    for log in logs:
        if log.integration_id:
            by_integration.setdefault(str(log.integration_id), []).append(log)

    def _age(iso_or_dt) -> int | None:
        stamp = _as_dt(iso_or_dt)
        if stamp is None:
            return None
        return _age_s(stamp, now)

    rows = []
    for integ in integrations:
        attempts = by_integration.get(str(integ.id), [])
        counts: dict[str, int] = {}
        for a in attempts:
            counts[a.status] = counts.get(a.status, 0) + 1
        last = attempts[0] if attempts else None

        if not integ.enabled:
            status = "Disabled"
            detail = "disabled by an operator — not delivering by configuration"
        elif not integ.endpoint:
            status = "Outbox (air-gap)"
            detail = ("no endpoint configured — events retained in the durable "
                      "outbox; delivery is not claimed"
                      + (f"; last attempt {last.status}" if last else ""))
        elif last is None:
            status = "Not measured"
            detail = ("registered but no delivery attempt recorded — "
                      "registration is not health evidence")
        elif last.status == "delivered":
            status = "Operational"
            detail = ("last delivery delivered"
                      + (f" (HTTP {last.http_status})" if last.http_status else "")
                      + f" {last.attempts} attempt(s)")
        elif last.status == "failed":
            status = "Degraded"
            detail = ("last delivery failed"
                      + (f" (HTTP {last.http_status})" if last.http_status else "")
                      + (f": {last.error}" if last.error else ""))
        else:  # skipped with an endpoint configured (e.g. SSRF-blocked)
            status = "Degraded"
            detail = (f"last attempt {last.status}"
                      + (f": {last.error}" if last.error else ""))

        rows.append({
            "integration_id": integ.id,
            "name": integ.name,
            "kind": integ.kind,
            "provider": integ.provider,
            "enabled": bool(integ.enabled),
            "endpoint_configured": bool(integ.endpoint),
            "status": status,
            "detail": detail,
            "last_delivery": ({
                "status": last.status,
                "http_status": last.http_status,
                "attempts": last.attempts,
                "age_s": _age(last.created_at),
                "event_type": last.event_type,
            } if last else None),
            "recent_counts": counts,
        })

    measured = [r for r in rows if r["status"] in ("Operational", "Degraded")]
    degraded = [r for r in rows if r["status"] == "Degraded"]
    if not rows:
        overall = "Not measured"
        overall_detail = "no integrations registered — nothing to measure"
    elif degraded:
        overall = "Degraded"
        overall_detail = f"{len(degraded)} of {len(rows)} connector(s) failing"
    elif measured:
        overall = "Operational"
        overall_detail = (f"{len(measured)} of {len(rows)} connector(s) measured healthy")
    else:
        overall = "Not measured"
        overall_detail = ("no connector has a delivery attempt on record — "
                          "registration is not health evidence")

    return {
        "status": overall,
        "detail": overall_detail,
        "connectors": rows,
        "count": len(rows),
        "note": (
            "Measured from the outbound delivery audit (cp_delivery_logs): "
            "one row per real signed HTTP attempt or air-gap skip. "
            "Registration and the enabled flag are configuration, not "
            "health — a connector with no delivery history reports Not "
            "measured, never a derived 'connected'."
        ),
    }
