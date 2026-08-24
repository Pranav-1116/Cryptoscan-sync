"""
Health check endpoints for the API service.

Provides:
- /health/live: Liveness probe (is process alive?)
- /health/ready: Readiness probe (can serve traffic?)
- /health/detailed: Full component health (internal use)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from api.dependencies import get_db_session

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

# Track service start time for uptime calculation
_SERVICE_START_TIME = time.monotonic()
_SERVICE_START_WALL = datetime.now(timezone.utc)


class ComponentHealth(BaseModel):
    status: str  # "ok", "degraded", "down"
    latency_ms: float | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str  # "healthy", "degraded", "unhealthy"
    version: str = "1.0.0"
    timestamp: datetime
    uptime_seconds: float
    components: dict[str, ComponentHealth] | None = None


@router.get(
    "/live",
    summary="Liveness probe",
    description="Returns 200 if the process is alive. Used by Kubernetes liveness probe.",
    response_model=HealthResponse,
)
async def liveness() -> HealthResponse:
    """
    Liveness check — just confirms the process is running.

    Always returns 200 unless the process is completely dead.
    Does NOT check DB or external dependencies.
    """
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        uptime_seconds=time.monotonic() - _SERVICE_START_TIME,
    )


@router.get(
    "/ready",
    summary="Readiness probe",
    description="Returns 200 if ready to serve traffic (DB connected).",
)
async def readiness(
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Readiness check — confirms service can handle requests.

    Checks:
    1. Database connectivity
    2. Database query response time

    Returns 200 if ready, 503 if not ready.
    """
    db_health = await _check_database(session)

    overall_status = "healthy" if db_health.status == "ok" else "unhealthy"
    http_status = (
        status.HTTP_200_OK
        if overall_status == "healthy"
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    body: dict[str, Any] = {
        "status": overall_status,
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": time.monotonic() - _SERVICE_START_TIME,
        "components": {
            "database": db_health.model_dump(),
        },
    }

    if overall_status != "healthy":
        logger.warning(
            "readiness_check_failed",
            db_status=db_health.status,
            db_detail=db_health.detail,
        )

    return JSONResponse(content=body, status_code=http_status)


@router.get(
    "/detailed",
    summary="Detailed health check",
    description="Full component health status. For internal/monitoring use.",
    include_in_schema=False,  # Don't expose in public OpenAPI docs
)
async def detailed_health(
    session: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Detailed health including all component checks.
    Use for monitoring dashboards, not for load balancer probes.
    """
    start = time.monotonic()

    db_health = await _check_database(session)

    components = {
        "database": db_health,
    }

    # Determine overall status
    statuses = [c.status for c in components.values()]
    if all(s == "ok" for s in statuses):
        overall = "healthy"
    elif any(s == "down" for s in statuses):
        overall = "unhealthy"
    else:
        overall = "degraded"

    total_check_time = (time.monotonic() - start) * 1000

    body: dict[str, Any] = {
        "status": overall,
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": time.monotonic() - _SERVICE_START_TIME,
        "service_start": _SERVICE_START_WALL.isoformat(),
        "total_check_ms": round(total_check_time, 2),
        "components": {
            name: comp.model_dump()
            for name, comp in components.items()
        },
    }

    http_status = (
        status.HTTP_200_OK
        if overall == "healthy"
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )

    return JSONResponse(content=body, status_code=http_status)


async def _check_database(session: AsyncSession) -> ComponentHealth:
    """Check database connectivity and query response time."""
    start = time.monotonic()
    try:
        result = await session.execute(text("SELECT 1"))
        result.scalar()
        latency_ms = (time.monotonic() - start) * 1000

        if latency_ms > 1000:
            return ComponentHealth(
                status="degraded",
                latency_ms=round(latency_ms, 2),
                detail=f"High latency: {latency_ms:.0f}ms",
            )

        return ComponentHealth(
            status="ok",
            latency_ms=round(latency_ms, 2),
        )

    except Exception as exc:
        latency_ms = (time.monotonic() - start) * 1000
        logger.error("database_health_check_failed", error=str(exc))
        return ComponentHealth(
            status="down",
            latency_ms=round(latency_ms, 2),
            detail=str(exc)[:200],
        )