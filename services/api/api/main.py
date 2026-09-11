"""CryptoScan API + dashboard host."""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from api.config.settings import APISettings, get_settings, validate_runtime_settings
from fastapi.middleware.gzip import GZipMiddleware
from api.middleware.auth_middleware import AuthMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.logging_middleware import LoggingMiddleware
from api.middleware.request_id_middleware import RequestIDMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.routers import (
    agility,
    analytics,
    assets,
    inventory,
    scope,
    risk,
    connectors,
    live,
    auth,
    banking,
    baselines,
    business,
    business_context,
    cbom,
    certificates,
    cloud,
    cloud_scans,
    container,
    container_scans,
    crypto,
    drift,
    estate,
    events,
    techbom,
    exceptions,
    notifications,
    export,
    findings,
    graph,
    hardware,
    health,
    intelligence,
    jobs,
    live_scan,
    network,
    network_scans,
    ot,
    ot_safety,
    policy,
    quantum,
    reachability,
    remediation,
    report_schedules,
    monitor,
    payment_crypto,
    telecom,
    audit_export,
    repo_configs,
    runtime,
    scans,
    stats,
    systems,
    sla,
    automation,
    automation_ops,
    trigger,
    vulnerability,
    vulns,
    webhooks,
    api_keys,
    algorithms,
    platform,
    sectors,
    sso,
    scim,
    workload,
    crypto_assurance,
    devsecops,
    onboarding,
    control_plane,
    enterprise,
    marketplace as marketplace_router,
    datalake as datalake_router,
    anomaly as anomaly_router,
    governance as governance_router,
    security as security_router,
    resilience,
)
from api.routers import metrics as metrics_router
from api.security.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)


def _under_test() -> bool:
    """True when running under pytest.

    Several test fixtures set ``ENVIRONMENT=development`` (closer to real
    runtime than ``test``), which would otherwise start the async event tailer /
    telemetry heartbeat in the app lifespan. Those background asyncio tasks and
    their threads keep the process alive after the suite finishes, causing
    hangs. Detecting pytest directly lets us suppress them regardless of the
    ENVIRONMENT value a fixture sets.
    """
    return "pytest" in sys.modules


def _shared_rate_limit_backend():
    """Redis client for cluster-wide rate limits; None (in-process) when unset/down."""
    url = os.environ.get("REDIS_URL", "")
    if not url:
        return None
    try:
        import redis

        return redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
    except Exception:
        return None


def create_app(settings: APISettings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from db.connection.session import init_db
        from shared_config.env_loader import load_env
        from shared_logging.logger_factory import configure_logging

        load_env()
        configure_logging(settings.LOG_LEVEL, json_output=settings.is_production)
        validate_runtime_settings(settings)
        if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
            init_db()
            try:
                from graph_engine.connection.neo4j_driver import get_driver
                from graph_engine.core.store import Neo4jGraphStore

                driver = get_driver()
                if driver is not None:
                    Neo4jGraphStore(driver).apply_schema()
            except Exception:
                logger.debug("neo4j_schema_skipped", exc_info=True)
            try:
                from db.connection.session import SessionLocal
                from api.security.auth import AuthService

                with SessionLocal() as session:
                    AuthService(session=session).bootstrap_admin()
            except Exception:
                logger.warning("admin_bootstrap_skipped", exc_info=True)
        logger.info("cryptoscan_api_started", extra={"env": settings.ENVIRONMENT})
        tailer_task = None
        telemetry_task = None
        redis_sync = None
        if (
            settings.EVENT_TAILER_SECONDS > 0
            and settings.ENVIRONMENT.lower() not in {"test", "testing"}
            and not _under_test()
        ):
            from api.routers.events import start_event_tailer, start_telemetry_heartbeat

            tailer_task = start_event_tailer(settings.EVENT_TAILER_SECONDS)
            if tailer_task is not None:
                logger.info("event_tailer_started", extra={"interval": settings.EVENT_TAILER_SECONDS})
            try:
                from api.events.automation_bridge import start_automation_bridge

                if start_automation_bridge():
                    logger.info("automation_bridge_started")
            except Exception:  # noqa: BLE001
                logger.debug("automation_bridge_start_skipped", exc_info=True)
            telemetry_task = start_telemetry_heartbeat()
            if telemetry_task is not None:
                logger.info("telemetry_heartbeat_started")
            # Cross-instance realtime: when REDIS_URL is set, federate events so
            # SSE clients on ANY replica receive events published on another
            # replica. Without Redis the bus stays on the local node (and the
            # durable DB tailer still federates cross-process events).
            redis_sync = None
            try:
                if settings.REDIS_URL:
                    import redis as _redis
                    from api.events.bus import get_event_bus
                    from api.events.redis_sync import start_redis_federation

                    rclient = _redis.Redis.from_url(
                        settings.REDIS_URL, socket_timeout=2, socket_connect_timeout=2
                    )
                    redis_sync = start_redis_federation(rclient, get_event_bus())
                    if redis_sync is not None:
                        logger.info("redis_event_federation_started")
                    # Share the live scan status across replicas so any node can
                    # answer /orchestrator/status even if it did not run the scan.
                    from api.live_scan.current_run import get_current_run_store
                    from api.live_scan.orchestrator import get_scan_orchestrator

                    get_scan_orchestrator().set_status_store(
                        get_current_run_store(settings.REDIS_URL)
                    )
            except Exception:  # noqa: BLE001 — Redis must never break startup
                logger.debug("redis_event_federation_skipped", exc_info=True)
        # Restore the latest live-scanner snapshot so consoles see the most
        # recent real scan immediately after a restart (best-effort; runs
        # independent of the event tailer).
        try:
            from api.live_scan.runner import get_live_scan_runner

            if get_live_scan_runner().load_persisted_snapshot():
                logger.info("live_scan_snapshot_restored")
        except Exception:  # noqa: BLE001
            logger.debug("live_scan_snapshot_restore_skipped", exc_info=True)
        yield
        if tailer_task is not None:
            tailer_task.cancel()
        if telemetry_task is not None:
            telemetry_task.cancel()
        if redis_sync is not None:
            try:
                redis_sync.stop()
            except Exception:  # noqa: BLE001
                pass
        logger.info("cryptoscan_api_stopped")

    app = FastAPI(
        title="CryptoScan Intelligence Platform",
        description="Deterministic cryptographic discovery, inventory, and compliance.",
        version=settings.API_VERSION,
        docs_url="/api/docs" if settings.docs_enabled else None,
        redoc_url="/api/redoc" if settings.docs_enabled else None,
        openapi_url="/api/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    origins = settings.cors_origin_list
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=origins != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Request-Duration-ms", "X-Trace-Id", "X-Total-Count"],
    )
    if settings.trusted_host_list and settings.trusted_host_list != ["*"]:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_host_list)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=1024)  # W59-60: compress bulky JSON payloads
    app.add_middleware(RequestIDMiddleware)
    if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
        app.add_middleware(AuthMiddleware, settings=settings)
        app.add_middleware(RateLimitMiddleware, redis_client=_shared_rate_limit_backend())
    # ABAC scope enforcement runs just inside the auth gate on EVERY route.
    # It is a no-op unless ABAC_ENFORCED is set (and grants are provisioned),
    # so test/dev installs keep working while large-bank deployments get
    # fail-closed Region→BU→Environment→Asset isolation.
    from api.middleware.abac_middleware import AbacMiddleware

    app.add_middleware(AbacMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Innermost: runs right after the route so every successful mutating call
    # across all services lands on the real-time bus (api.<segment>.<verb>).
    from api.middleware.control_events import ControlEventMiddleware

    app.add_middleware(ControlEventMiddleware)

    @app.exception_handler(AuthenticationError)
    async def auth_exception_handler(request: Request, exc: AuthenticationError):
        return JSONResponse(status_code=401, content={"detail": exc.message})

    @app.exception_handler(ValidationError)
    async def validation_exception_handler(request: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content={"detail": exc.message, "errors": exc.errors})

    @app.get("/health")
    def health_check():
        return {"status": "healthy", "version": settings.API_VERSION, "environment": settings.ENVIRONMENT}

    @app.get("/ready")
    def ready_check():
        from db.connection.engine import check_db_health

        db = check_db_health()
        ready = db.get("status") == "healthy"
        return {
            "ready": ready,
            "status": "ok" if ready else "degraded",
            "database": db,
            "environment": settings.ENVIRONMENT,
            "version": settings.API_VERSION,
        }

    # Root-level LB/K8s probe aliases of /api/v1/healthz + /api/v1/readyz.
    # smoke_test.sh and the hardening guide probe these at the edge; /readyz
    # carries the drain semantics (503 while the database is down) that the
    # legacy /ready above intentionally does not have.
    @app.get("/healthz")
    def healthz_root_alias():
        from api.routers.health import healthz as _healthz

        return _healthz()

    @app.get("/readyz")
    def readyz_root_alias():
        from api.routers.health import readyz as _readyz

        return _readyz()

    prefix = "/api/v1"
    app.include_router(auth.router, prefix=prefix)
    app.include_router(banking.router, prefix=prefix)
    # Runtime findings MUST be registered before scans.router: scans exposes a
    # catch-all GET /scans/{scan_id} which would otherwise shadow the static
    # path /scans/runtime-findings (FastAPI matches routes in include order).
    app.include_router(runtime.router, prefix=prefix)
    app.include_router(scans.router, prefix=prefix)
    app.include_router(findings.router, prefix=prefix)
    app.include_router(drift.router, prefix=prefix)
    app.include_router(jobs.router, prefix=prefix)
    app.include_router(stats.router, prefix=prefix)
    app.include_router(baselines.router, prefix=prefix)
    app.include_router(trigger.router, prefix=prefix)
    app.include_router(webhooks.router, prefix=prefix)
    app.include_router(repo_configs.router, prefix=prefix)
    app.include_router(hardware.router, prefix=prefix)
    app.include_router(crypto.router, prefix=prefix)
    app.include_router(health.router, prefix=prefix)
    app.include_router(export.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(inventory.router, prefix=prefix)
    app.include_router(scope.router, prefix=prefix)
    app.include_router(risk.router, prefix=prefix)
    app.include_router(connectors.router, prefix=prefix)
    app.include_router(live.router, prefix=prefix)
    app.include_router(algorithms.router, prefix=prefix)
    app.include_router(systems.router, prefix=prefix)
    app.include_router(cbom.router, prefix=prefix)
    app.include_router(container.router, prefix=prefix)
    app.include_router(container_scans.router, prefix=prefix)
    app.include_router(vulns.router, prefix=prefix)
    app.include_router(vulnerability.router, prefix=prefix)
    app.include_router(policy.router, prefix=prefix)
    app.include_router(quantum.router, prefix=prefix)
    app.include_router(intelligence.router, prefix=prefix)
    app.include_router(network.router, prefix=prefix)
    app.include_router(network_scans.router, prefix=prefix)
    app.include_router(certificates.router, prefix=prefix)
    app.include_router(cloud.router, prefix=prefix)
    app.include_router(cloud_scans.router, prefix=prefix)
    app.include_router(estate.router, prefix=prefix)
    app.include_router(techbom.router, prefix=prefix)
    app.include_router(graph.router, prefix=prefix)
    app.include_router(reachability.router, prefix=prefix)
    app.include_router(remediation.router, prefix=prefix)
    app.include_router(report_schedules.router, prefix=prefix)
    app.include_router(monitor.router, prefix=prefix)
    app.include_router(payment_crypto.router, prefix=prefix)
    app.include_router(telecom.router, prefix=prefix)
    app.include_router(audit_export.router, prefix=prefix)
    app.include_router(events.router, prefix=prefix)
    app.include_router(notifications.router, prefix=prefix)
    app.include_router(live_scan.router, prefix=prefix)
    app.include_router(api_keys.router, prefix=prefix)
    app.include_router(business.router, prefix=prefix)
    app.include_router(business_context.router, prefix=prefix)
    app.include_router(agility.router, prefix=prefix)
    app.include_router(exceptions.router, prefix=prefix)
    app.include_router(ot.router, prefix=prefix)
    app.include_router(ot_safety.router, prefix=prefix)
    app.include_router(sla.router, prefix=prefix)
    app.include_router(automation.router, prefix=prefix)
    app.include_router(automation_ops.router, prefix=prefix)
    app.include_router(analytics.router, prefix=prefix)
    app.include_router(platform.router, prefix=prefix)
    app.include_router(sectors.router, prefix=prefix)
    app.include_router(sso.router, prefix=prefix)
    app.include_router(scim.router, prefix=prefix)
    app.include_router(workload.router, prefix=prefix)
    app.include_router(devsecops.router, prefix=prefix)
    app.include_router(resilience.router, prefix=prefix)
    app.include_router(crypto_assurance.router, prefix=prefix)
    app.include_router(onboarding.router, prefix=prefix)
    app.include_router(control_plane.router, prefix=prefix)
    app.include_router(security_router.router, prefix=prefix)
    app.include_router(enterprise.router, prefix=prefix)
    app.include_router(marketplace_router.router, prefix=prefix)
    app.include_router(datalake_router.router, prefix=prefix)
    app.include_router(anomaly_router.router, prefix=prefix)
    app.include_router(governance_router.router, prefix=prefix)
    app.include_router(metrics_router.router)  # /metrics (no /api prefix)

    dashboard_dist = Path(__file__).resolve().parents[2] / "dashboard" / "dist"
    dashboard_html = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
    if dashboard_dist.is_dir() and (dashboard_dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dashboard_dist / "assets"), name="assets")

        @app.get("/")
        def spa_root():
            return FileResponse(dashboard_dist / "index.html")
    elif dashboard_html.is_file():

        @app.get("/")
        def home():
            return HTMLResponse(dashboard_html.read_text(encoding="utf-8"))

    return app


settings = get_settings()
app = create_app(settings)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST or "0.0.0.0",
        port=int(settings.API_PORT or 8010),
        reload=False,
    )


if __name__ == "__main__":
    run()
