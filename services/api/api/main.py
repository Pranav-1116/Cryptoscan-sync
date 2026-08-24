"""CryptoScan API + dashboard host."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.config.settings import APISettings, get_settings
from api.middleware.auth_middleware import AuthMiddleware
from api.middleware.logging_middleware import LoggingMiddleware
from api.middleware.request_id_middleware import RequestIDMiddleware
from api.routers import (
    assets,
    auth,
    baselines,
    cbom,
    container,
    drift,
    export,
    findings,
    health,
    intelligence,
    jobs,
    policy,
    repo_configs,
    scans,
    stats,
    systems,
    trigger,
    vulns,
    webhooks,
)
from api.security.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)


def create_app(settings: APISettings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from db.connection.session import init_db
        from shared_config.env_loader import load_env
        from shared_logging.logger_factory import configure_logging

        load_env()
        configure_logging(settings.LOG_LEVEL, json_output=settings.is_production)
        if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
            init_db()
        logger.info("cryptoscan_api_started", extra={"env": settings.ENVIRONMENT})
        yield
        logger.info("cryptoscan_api_stopped")

    app = FastAPI(
        title="CryptoScan Intelligence Platform",
        description="Deterministic cryptographic discovery, inventory, and compliance.",
        version=settings.API_VERSION,
        docs_url="/api/docs" if settings.DOCS_ENABLED else None,
        redoc_url="/api/redoc" if settings.DOCS_ENABLED else None,
        openapi_url="/api/openapi.json" if settings.DOCS_ENABLED else None,
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
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)
    if settings.ENVIRONMENT.lower() not in {"test", "testing"}:
        app.add_middleware(AuthMiddleware, settings=settings)

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
        return {"ready": db.get("status") == "healthy", "database": db}

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
    app.include_router(health.router, prefix=prefix)
    app.include_router(export.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(systems.router, prefix=prefix)
    app.include_router(cbom.router, prefix=prefix)
    app.include_router(container.router, prefix=prefix)
    app.include_router(vulns.router, prefix=prefix)
    app.include_router(policy.router, prefix=prefix)
    app.include_router(intelligence.router, prefix=prefix)

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
        port=int(settings.API_PORT or 8000),
        reload=False,
    )


if __name__ == "__main__":
    run()
