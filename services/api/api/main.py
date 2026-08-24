"""
FastAPI Application Factory - Main entry point for REST API.

Sets up FastAPI app, middleware, exception handlers, and routes.
"""

import logging
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from api.config.settings import APISettings
from api.middleware.auth_middleware import AuthMiddleware
from api.middleware.request_id_middleware import RequestIDMiddleware
from api.middleware.logging_middleware import LoggingMiddleware
from api.routers import scans, findings, drift, jobs, stats, webhooks, baselines, trigger
from api.security.exceptions import AuthenticationError, ValidationError

logger = logging.getLogger(__name__)


def create_app(settings: Optional[APISettings] = None) -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Args:
        settings: APISettings instance (loads from env if None)
    
    Returns:
        Configured FastAPI application
    """
    if settings is None:
        settings = APISettings()
    
    # Lifespan context manager for startup/shutdown
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """
        Handle app startup and shutdown.
        
        Yields at startup point, resumes at shutdown.
        """
        # STARTUP
        logger.info(
            "CryptoScan API starting up",
            extra={
                "environment": settings.ENVIRONMENT,
                "version": settings.API_VERSION
            }
        )
        
        # Initialize database connections, caches, etc.
        # (would add here when integrated)
        
        yield
        
        # SHUTDOWN
        logger.info("CryptoScan API shutting down")
        # Cleanup: close DB connections, flush caches, etc.
    
    # Create FastAPI app
    app = FastAPI(
        title="CryptoScan Intelligence Platform",
        description="Universal Cryptographic Discovery, Inventory & Dependency Engine",
        version=settings.API_VERSION,
        docs_url="/api/docs" if settings.DOCS_ENABLED else None,
        redoc_url="/api/redoc" if settings.DOCS_ENABLED else None,
        openapi_url="/api/openapi.json" if settings.DOCS_ENABLED else None,
        lifespan=lifespan
    )
    
    # Store settings in app state
    app.state.settings = settings
    
    # Add middleware (order matters - first added is last to execute)
    
    # 1. CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-Total-Count", "X-Page"],
        max_age=3600
    )
    
    # 2. Trusted hosts middleware
    if settings.ENVIRONMENT == "production":
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.TRUSTED_HOSTS
        )
    
    # 3. Custom middleware (executed in reverse order of addition)
    app.add_middleware(LoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(AuthMiddleware, settings=settings)
    
    # Exception handlers
    @app.exception_handler(AuthenticationError)
    async def auth_exception_handler(request: Request, exc: AuthenticationError):
        return JSONResponse(
            status_code=401,
            content={
                "detail": exc.message,
                "error_code": "AUTHENTICATION_FAILED",
                "request_id": request.state.request_id
            }
        )
    
    @app.exception_handler(ValidationError)
    async def validation_exception_handler(request: Request, exc: ValidationError):
        return JSONResponse(
            status_code=400,
            content={
                "detail": exc.message,
                "error_code": "VALIDATION_FAILED",
                "errors": exc.errors,
                "request_id": request.state.request_id
            }
        )
    
    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Request validation failed",
                "errors": exc.errors(),
                "request_id": getattr(request.state, "request_id", None)
            }
        )
    
    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        logger.error(
            "Unhandled exception",
            extra={
                "exception_type": type(exc).__name__,
                "error": str(exc),
                "request_id": getattr(request.state, "request_id", None)
            },
            exc_info=True
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "error_code": "INTERNAL_ERROR",
                "request_id": getattr(request.state, "request_id", None)
            }
        )
    
    # Health check endpoint
    @app.get("/health", tags=["health"])
    async def health_check():
        """
        Health check endpoint.
        
        Returns:
            Health status
        """
        return {
            "status": "healthy",
            "version": settings.API_VERSION,
            "environment": settings.ENVIRONMENT
        }
    
    # Ready check endpoint
    @app.get("/ready", tags=["health"])
    async def readiness_check():
        """
        Readiness check endpoint.
        
        Returns:
            Readiness status
        """
        # In production, would check DB connectivity, cache, etc.
        return {
            "ready": True,
            "version": settings.API_VERSION
        }
    
    # Include routers (API v1)
    app.include_router(
        scans.router,
        prefix="/api/v1",
        tags=["scans"]
    )
    app.include_router(
        findings.router,
        prefix="/api/v1",
        tags=["findings"]
    )
    app.include_router(
        drift.router,
        prefix="/api/v1",
        tags=["drift"]
    )
    app.include_router(
        jobs.router,
        prefix="/api/v1",
        tags=["jobs"]
    )
    app.include_router(
        stats.router,
        prefix="/api/v1",
        tags=["stats"]
    )
    app.include_router(
        baselines.router,
        prefix="/api/v1",
        tags=["baselines"]
    )
    app.include_router(
        trigger.router,
        prefix="/api/v1",
        tags=["trigger"]
    )
    app.include_router(
        webhooks.router,
        prefix="/api/v1",
        tags=["webhooks"]
    )
    
    logger.info(
        "FastAPI application created successfully",
        extra={
            "routes": len(app.routes),
            "middleware_count": len(app.user_middleware)
        }
    )
    
    return app


# Create default app instance
settings = APISettings()
app = create_app(settings)