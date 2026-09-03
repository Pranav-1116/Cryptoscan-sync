"""CryptoScan API + dashboard host."""

from __future__ import annotations

import logging
import os
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
    auth,
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
    exceptions,
    export,
    findings,
    graph,
    hardware,
    health,
    intelligence,
    jobs,
    network,
    network_scans,
    ot,
    policy,
    quantum,
    reachability,
    remediation,
    report_schedules,
    monitor,
    payment_crypto,
    audit_export,
    repo_configs,
    runtime,
    scans,
    stats,
    systems,
    trigger,
    vulnerability,
    vulns,
    webhooks,
    api_keys,
    algorithms,
    platform,
    sectors,
    onboarding,
    control_plane,
    enterprise,
    marketplace as marketplace_router,
    datalake as datalake_router,
    anomaly as anomaly_router,
    governance as governance_router,
)
from api.routers import metrics as metrics_router
from api.security.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)


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
        if settings.EVENT_TAILER_SECONDS > 0 and settings.ENVIRONMENT.lower() not in {"test", "testing"}:
            from api.routers.events import start_event_tailer, start_telemetry_heartbeat

            tailer_task = start_event_tailer(settings.EVENT_TAILER_SECONDS)
            if tailer_task is not None:
                logger.info("event_tailer_started", extra={"interval": settings.EVENT_TAILER_SECONDS})
            telemetry_task = start_telemetry_heartbeat()
            if telemetry_task is not None:
                logger.info("telemetry_heartbeat_started")
        yield
        if tailer_task is not None:
            tailer_task.cancel()
        if telemetry_task is not None:
            telemetry_task.cancel()
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
        expose_headers=["X-Request-ID", "X-Total-Count"],
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

    prefix = "/api/v1"
    app.include_router(auth.router, prefix=prefix)
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
    app.include_router(graph.router, prefix=prefix)
    app.include_router(reachability.router, prefix=prefix)
    app.include_router(remediation.router, prefix=prefix)
    app.include_router(report_schedules.router, prefix=prefix)
    app.include_router(monitor.router, prefix=prefix)
    app.include_router(payment_crypto.router, prefix=prefix)
    app.include_router(audit_export.router, prefix=prefix)
    app.include_router(events.router, prefix=prefix)
    app.include_router(api_keys.router, prefix=prefix)
    app.include_router(runtime.router, prefix=prefix)
    app.include_router(business.router, prefix=prefix)
    app.include_router(business_context.router, prefix=prefix)
    app.include_router(agility.router, prefix=prefix)
    app.include_router(exceptions.router, prefix=prefix)
    app.include_router(ot.router, prefix=prefix)
    app.include_router(analytics.router, prefix=prefix)
    app.include_router(platform.router, prefix=prefix)
    app.include_router(sectors.router, prefix=prefix)
    app.include_router(onboarding.router, prefix=prefix)
    app.include_router(control_plane.router, prefix=prefix)
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
