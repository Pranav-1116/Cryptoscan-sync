import logging
import time

from db.connection.engine import check_db_health
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.config.settings import get_settings

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


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
        return {"name": name, "status": "down", "detail": str(exc)[:200],
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
        import redis

        client = redis.Redis.from_url(
            settings.REDIS_URL, socket_timeout=1, socket_connect_timeout=1
        )
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

    checks = [
        _probe("database", True, _db),
        _probe("redis", bool((settings.REDIS_URL or "").strip()), _redis),
        _probe("neo4j", bool((settings.NEO4J_URI or "").strip()), _neo4j),
    ]
    down = [c["name"] for c in checks if c["status"] == "down"]
    overall = "degraded" if down else "ok"
    return {"status": overall, "down": down, "checks": checks}


@router.get("/healthz")
def healthz():
    return {"status": "ok", "database": check_db_health()}


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
    """
    from db.connection.engine import get_engine
    from sqlalchemy import text

    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "not_ready", "database": str(exc)[:200]})
    return {"status": "ready", "database": "ok"}


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
