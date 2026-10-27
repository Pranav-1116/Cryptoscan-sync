from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.config.settings import get_settings
from db.connection.engine import check_db_health

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz():
    return {"status": "ok", "database": check_db_health()}


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
    from db.connection.engine import engine
    from db.connection.schema_ensure import schema_drift_report

    return schema_drift_report(engine)


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
