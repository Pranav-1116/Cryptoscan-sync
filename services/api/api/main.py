"""CryptoScan API + dashboard host."""

from __future__ import annotations

import logging
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
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.logging_middleware import LoggingMiddleware
from api.middleware.request_id_middleware import RequestIDMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.routers import (
    accuracy,
    collector_authority,
    collector_depth,
    failure_matrix,
    scale_validation,
    software_supply_chain,
    execution_controls,
    assurance,
    relationship_lifecycle,
    agility,
    analytics,
    digital_twin,
    graphql,
    billing,
    compliance,
    ops,
    priority,
    saas,
    stream,
    realtime as realtime_router,
    assets,
    inventory,
    inventory_cloud,
    scope,
    risk,
    connectors,
    live,
    auth,
    banking,
    baselines,
    business,
    business_context,
    site_security,
    chatops,
    evidence_disposition,
    facts,
    topology,
    threat_intel,
    cbom,
    certificates,
    cloud,
    cloud_scans,
    container,
    container_scans,
    crypto,
    ct_scans,
    drift,
    estate,
    estate_graph,
    ingestion,
    events,
    exposure,
    trust_model,
    techbom,
    exceptions,
    notifications,
    export,
    findings,
    graph,
    hardware,
    hbom,
    health,
    hsm_scans,
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
    retirement,
    monitor,
    payment_crypto,
    telecom,
    audit_export,
    pentest,
    repo_configs,
    runtime,
    runtime_crypto,
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
    readiness,
)
from api.routers import metrics as metrics_router
from api.routers import ws
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
    try:
        from api.config.settings import get_settings
        from shared_models.redis_connection import connection_settings, verified_redis_client
        config = connection_settings(get_settings(), "rate_limit")
        if not config.REDIS_URL:
            return None
        return verified_redis_client(config, socket_timeout=1)
    except Exception as exc:
        logger.exception("shared_rate_limit_backend_unavailable", extra={"error_type": type(exc).__name__})
        return None  # production middleware fails closed, never local quotas


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
        # Runtime egress guard (audit 81, round 35): under enforce, every
        # outbound TCP connection must match the explicit allowlist —
        # fail-closed, fail-loud. Off by default (community installs).
        if str(getattr(settings, "EGRESS_GUARD", "off") or "off").lower() == "enforce":
            from api.security.egress_guard import install_egress_guard

            allowlist = [
                entry.strip()
                for entry in str(getattr(settings, "EGRESS_ALLOWLIST", "") or "").split(",")
                if entry.strip()
            ]
            install_egress_guard(allowlist)
        # External secret references (advanced/75 P0#1, round 31): resolve
        # vault:// file: env: references in credential settings at startup.
        # Fail-loud: a half-resolved credential set must not boot.
        try:
            from api.security.vault import resolve_settings_secrets

            report = resolve_settings_secrets(strict=True)
            if report.get("resolved"):
                logger.info(
                    "secrets_resolved", extra={"count": report["resolved"], "fields": report["resolved_fields"]}
                )
        except Exception as exc:
            logger.error("secret_resolution_failed", extra={"error": str(exc)})
            raise
        if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
            init_db()
            if settings.CRYPTOSCAN_DEPLOYMENT_PROFILE != "kubernetes-external-services/local-source-v1":
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
        # Pay the lazy-import bill on the boot path: the first request to a route
        # that imports its engine inside the handler would otherwise pay it, and
        # two such requests racing can trip CPython's import-lock deadlock. Skipped
        # under pytest: an in-process test client would pay for it per app, and the
        # live smoke server (which is not a TestClient) still warms properly.
        if not _under_test():
            from api.startup_imports import warm as warm_imports

            warm_imports()
        from api.security.breach_corpus import production_gap

        # A control that is silently absent is worse than one that is missing
        # loudly: name the gap at startup so an operator sees it in the first
        # hundred lines of the log rather than never.
        gap = production_gap(settings)
        if gap:
            logger.warning("password_breach_corpus_missing", extra={"detail": gap})
        logger.info("cryptoscan_api_started", extra={"env": settings.ENVIRONMENT})
        tailer_task = None
        telemetry_task = None
        redis_sync = None
        if (
            settings.EVENT_TAILER_SECONDS > 0
            and not (settings.is_production or required())
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
                    from api.events.redis_backend import realtime_redis_client
                    from api.events.bus import get_event_bus
                    from api.events.redis_sync import start_redis_federation

                    from shared_models.redis_connection import connection_settings, verified_redis_client, connection_fingerprint
                    realtime_config = connection_settings(settings, "realtime")
                    rclient = realtime_redis_client(realtime_config)
                    redis_sync = start_redis_federation(rclient, get_event_bus(), required=settings.is_production)
                    if redis_sync is None or not getattr(redis_sync, "ready", False):
                        if settings.is_production:
                            raise RuntimeError("Redis realtime federation did not become ready")
                        logger.warning("redis_event_federation_unavailable")
                    else:
                        logger.info("redis_event_federation_started")
                    # Share the live scan status across replicas so any node can
                    # answer /orchestrator/status even if it did not run the scan.
                    from api.live_scan.current_run import get_current_run_store
                    from api.live_scan.orchestrator import get_scan_orchestrator

                    current_config = connection_settings(settings, "current_run")
                    current_client = rclient if connection_fingerprint(current_config) == connection_fingerprint(realtime_config) else verified_redis_client(current_config)
                    get_scan_orchestrator().set_status_store(
                        get_current_run_store(current_config.REDIS_URL, required=settings.is_production, client=current_client)
                    )
            except Exception as exc:  # noqa: BLE001 — production must not run realtime-degraded
                if settings.is_production:
                    raise RuntimeError("production realtime dependencies are unavailable") from exc
                logger.debug("redis_event_federation_skipped", exc_info=True)
        # 24/7 estate loop (spec 93 §18). Off unless ESTATE_REALTIME is set: the
        # daemon is safe on every replica because each run is claimed with a
        # database lease, but an operator should still opt in rather than find a
        # scheduler they did not start. The thread is stopped in the shutdown
        # half of this lifespan, after the run in flight finishes.
        estate_daemon = None
        estate_thread = None
        if (
            bool(getattr(settings, "ESTATE_REALTIME", False))
            and settings.ENVIRONMENT.lower() not in {"test", "testing"}
            and not _under_test()
        ):
            try:
                import threading

                from api.estate_daemon import EstateDaemon
                from api.estate_events import bus_publisher
                from db.connection.session import SessionLocal
                from db.tenancy import current_tenant

                def publish_estate_event(event_type, payload):
                    bus_publisher(tenant_id=current_tenant())(event_type, payload)

                estate_daemon = EstateDaemon(
                    SessionLocal,
                    worker=f"api-{settings.API_VERSION or '1.0'}",
                    poll_seconds=float(getattr(settings, "ESTATE_REALTIME_POLL_SECONDS", 30.0) or 30.0),
                    publisher=publish_estate_event,
                )
                estate_thread = threading.Thread(
                    target=estate_daemon.run_forever, name="estate-daemon", daemon=True
                )
                estate_thread.start()
                logger.info("estate_realtime_started",
                            extra={"poll_seconds": estate_daemon.poll_seconds})
            except Exception as exc:  # noqa: BLE001 — an unstartable loop is logged, not fatal
                logger.error("estate_realtime_start_failed", extra={"error": str(exc)})
                estate_daemon = None
                estate_thread = None

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
        if estate_daemon is not None:
            estate_daemon.stop()
            if estate_thread is not None:
                estate_thread.join(timeout=30)
                if estate_thread.is_alive():
                    logger.warning("estate_realtime_stop_timeout",
                                   extra={"detail": "a run was still in flight at shutdown"})
                else:
                    logger.info("estate_realtime_stopped")
        if redis_sync is not None:
            try:
                redis_sync.stop()
            except Exception as exc:  # noqa: BLE001
                logger.exception("redis_sync_stop_failed", extra={"error_type": type(exc).__name__})
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
    from db.repositories.execution_control import ExecutionDenied, required
    from api.middleware.controlled_surface import ControlledSurfaceMiddleware

    @app.exception_handler(ExecutionDenied)
    async def execution_denied(_request, exc):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    app.add_middleware(ControlledSurfaceMiddleware, production=settings.is_production)
    from api.middleware.assurance_body_limit import AssuranceBodyLimit
    app.add_middleware(AssuranceBodyLimit, prefix="/api/v1/assurance/")

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
    # Machine identity for the ingest surface. Inert unless
    # CRYPTOSCAN_REQUIRE_AGENT_IDENTITY is set, and scoped to /api/v1/ingestion.
    from api.middleware.agent_identity_middleware import AgentIdentityMiddleware

    app.add_middleware(AgentIdentityMiddleware)
    if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
        # Added before AuthMiddleware, so it runs *after* it: Starlette applies
        # middleware outermost-last, and the tenant can only be resolved once
        # the request is known to be authenticated.
        app.add_middleware(TenantScopeMiddleware)
        app.add_middleware(AuthMiddleware, settings=settings)
        app.add_middleware(
            RateLimitMiddleware,
            redis_client=_shared_rate_limit_backend(),
            fail_closed=settings.is_production,
        )
    # Platform self-observability: W3C trace-context + Prometheus metrics on
    # every request (works in all environments; cheap single pass).
    from observability.metrics import MetricsRegistry
    from observability.metrics import TraceStore as _TraceStore
    import os as _os

    app.state.metrics = MetricsRegistry()
    app.state.evidence_pack = None
    _sink = _os.environ.get("CRYPTOSCAN_SNAPSHOT_DIR", "data")
    app.state.traces = _TraceStore(
        sink_path=None
        if settings.ENVIRONMENT.lower() in {"test", "testing"}
        else Path(_sink) / "traces" / "spans.jsonl",
        otlp_endpoint=_os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"),
    )
    from api.middleware.observability_middleware import ObservabilityMiddleware

    app.add_middleware(ObservabilityMiddleware, registry=app.state.metrics, traces=app.state.traces)
    # ABAC scope enforcement runs just inside the auth gate on EVERY route.
    # It is a no-op unless ABAC_ENFORCED is set (and grants are provisioned),
    # so test/dev installs keep working while large-bank deployments get
    # fail-closed Region→BU→Environment→Asset isolation.
    from api.middleware.abac_middleware import AbacMiddleware

    app.add_middleware(AbacMiddleware)
    # Zero-trust PDP overlay (advanced/82, round 31): external policy-as-code
    # that can only RESTRICT — deny-wins over RBAC allow, never a bypass.
    # No-op unless ZERO_TRUST_ENFORCED is set (same deployment gate as ABAC).
    from api.middleware.zero_trust_middleware import ZeroTrustMiddleware

    app.add_middleware(ZeroTrustMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Innermost: runs right after the route so every successful mutating call
    # across all services lands on the real-time bus (api.<segment>.<verb>).
    from api.middleware.control_events import ControlEventMiddleware

    app.add_middleware(ControlEventMiddleware)
    # Before ABAC and FastAPI can buffer/parse uploaded CBOMs. Reuse the
    # existing bounded evidence JSON reader, including chunked requests.
    app.add_middleware(AssuranceBodyLimit, prefix="/api/v1/cbom/", label="CBOM")
    app.add_middleware(AssuranceBodyLimit, prefix="/api/v1/host-evidence/", label="Host evidence")
    app.add_middleware(AssuranceBodyLimit, prefix="/api/v1/collection/", label="Collection")

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
        from db.connection.engine import check_db_health, get_engine

        db = check_db_health()
        migration = None
        if settings.is_production:
            from db.connection.session import migration_status

            migration = migration_status(get_engine())
        ready = db.get("status") == "healthy" and (
            not settings.is_production or (migration is not None and migration.get("status") == "current")
        )
        return {
            "ready": ready,
            "status": "ok" if ready else "degraded",
            "database": db,
            "migrations": migration,
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
    app.include_router(execution_controls.router, prefix=prefix)
    app.include_router(assurance.router, prefix=prefix)
    app.include_router(site_security.router, prefix=prefix)
    app.include_router(chatops.router, prefix=prefix)
    app.include_router(facts.router, prefix=prefix)
    app.include_router(evidence_disposition.router, prefix=prefix)
    app.include_router(topology.router, prefix=prefix)
    app.include_router(threat_intel.router, prefix=prefix)
    app.include_router(banking.router, prefix=prefix)
    # Runtime findings MUST be registered before scans.router: scans exposes a
    # catch-all GET /scans/{scan_id} which would otherwise shadow the static
    # path /scans/runtime-findings (FastAPI matches routes in include order).
    app.include_router(runtime.router, prefix=prefix)
    app.include_router(runtime_crypto.router, prefix=prefix)
    app.include_router(estate_graph.router, prefix=prefix)
    app.include_router(collector_authority.router, prefix=prefix)
    app.include_router(collector_depth.router, prefix=prefix)
    app.include_router(scale_validation.router, prefix=prefix)
    app.include_router(failure_matrix.router, prefix=prefix)
    app.include_router(ingestion.router, prefix=prefix)
    app.include_router(scans.router, prefix=prefix)
    app.include_router(accuracy.router, prefix=prefix)
    app.include_router(findings.router, prefix=prefix)
    app.include_router(pentest.router, prefix=prefix)
    app.include_router(drift.router, prefix=prefix)
    app.include_router(jobs.router, prefix=prefix)
    app.include_router(stats.router, prefix=prefix)
    app.include_router(baselines.router, prefix=prefix)
    app.include_router(trigger.router, prefix=prefix)
    app.include_router(webhooks.router, prefix=prefix)
    app.include_router(repo_configs.router, prefix=prefix)
    app.include_router(hardware.router, prefix=prefix)
    app.include_router(hbom.router, prefix=prefix)
    app.include_router(crypto.router, prefix=prefix)
    app.include_router(health.router, prefix=prefix)
    app.include_router(export.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(inventory.router, prefix=prefix)
    app.include_router(inventory_cloud.router, prefix=prefix)
    app.include_router(scope.router, prefix=prefix)
    app.include_router(risk.router, prefix=prefix)
    app.include_router(connectors.router, prefix=prefix)
    app.include_router(live.router, prefix=prefix)
    app.include_router(algorithms.router, prefix=prefix)
    app.include_router(systems.router, prefix=prefix)
    app.include_router(cbom.router, prefix=prefix)
    from api.routers import host_evidence, collection
    app.include_router(collection.router, prefix=prefix)
    # Three routers existed with routes, tests and console callers but were never
    # mounted, so `POST /collection/snapshots`, `/resource-monitoring` and
    # `/traffic-control` answered 404 in the running API while their tests failed
    # against the same client. Mounting them is the fix; the routes are read/propose
    # only and keep their own dependencies.
    from api.routers import collection_views, resource_monitoring, traffic_control
    app.include_router(collection_views.router, prefix=prefix)
    app.include_router(resource_monitoring.router, prefix=prefix)
    app.include_router(traffic_control.router, prefix=prefix)
    from api.routers import oci_collection
    app.include_router(oci_collection.router, prefix=prefix)
    app.include_router(host_evidence.router, prefix=prefix)
    app.include_router(container.router, prefix=prefix)
    app.include_router(container_scans.router, prefix=prefix)
    app.include_router(hsm_scans.router, prefix=prefix)
    app.include_router(ct_scans.router, prefix=prefix)
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
    app.include_router(exposure.router, prefix=prefix)
    app.include_router(trust_model.router, prefix=prefix)
    app.include_router(techbom.router, prefix=prefix)
    app.include_router(graph.router, prefix=prefix)
    app.include_router(reachability.router, prefix=prefix)
    app.include_router(remediation.router, prefix=prefix)
    app.include_router(retirement.router, prefix=prefix)
    app.include_router(report_schedules.router, prefix=prefix)
    app.include_router(monitor.router, prefix=prefix)
    app.include_router(payment_crypto.router, prefix=prefix)
    app.include_router(telecom.router, prefix=prefix)
    app.include_router(audit_export.router, prefix=prefix)
    app.include_router(events.router, prefix=prefix)
    app.include_router(realtime_router.router, prefix=prefix)
    app.include_router(notifications.router, prefix=prefix)
    app.include_router(live_scan.router, prefix=prefix)
    app.include_router(api_keys.router, prefix=prefix)
    app.include_router(saas.router, prefix=prefix)
    app.include_router(stream.router, prefix=prefix)
    app.include_router(priority.router, prefix=prefix)
    app.include_router(billing.router, prefix=prefix)
    app.include_router(ops.router, prefix=prefix)
    app.include_router(compliance.router, prefix=prefix)
    app.include_router(business.router, prefix=prefix)
    app.include_router(business_context.router, prefix=prefix)
    app.include_router(agility.router, prefix=prefix)
    app.include_router(digital_twin.router, prefix=prefix)
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
    app.include_router(software_supply_chain.router, prefix=prefix)
    app.include_router(relationship_lifecycle.router, prefix=prefix)
    app.include_router(resilience.router, prefix=prefix)
    app.include_router(readiness.router, prefix=prefix)
    app.include_router(crypto_assurance.router, prefix=prefix)
    app.include_router(onboarding.router, prefix=prefix)
    app.include_router(control_plane.router, prefix=prefix)
    app.include_router(security_router.router, prefix=prefix)
    app.include_router(enterprise.router, prefix=prefix)
    app.include_router(marketplace_router.router, prefix=prefix)
    app.include_router(datalake_router.router, prefix=prefix)
    app.include_router(anomaly_router.router, prefix=prefix)
    app.include_router(governance_router.router, prefix=prefix)
    app.include_router(graphql.router, prefix=prefix)  # POST/GET /graphql (read-only)
    app.include_router(ws.router, prefix=prefix)  # /ws/binary/jobs/{id}, /ws/events
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
