from fastapi import APIRouter

from api.config.settings import get_settings
from db.connection.engine import check_db_health

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz():
    return {"status": "ok", "database": check_db_health()}


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
