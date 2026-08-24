# services/api/api/config/settings.py

"""
Production API service configuration.
Loads from environment variables with validation.
"""

from typing import Optional, Set
import os
from pydantic import Field, validator, AnyUrl
from shared_config.base_settings import BaseSettings


class APISettings(BaseSettings):
    """
    API service configuration.
    
    Environment variables:
    - API_HOST: Listen host (default: 0.0.0.0)
    - API_PORT: Listen port (default: 8000)
    - API_DEBUG: Debug mode (default: false)
    - API_WORKERS: Uvicorn workers (default: 4)
    - API_LOG_LEVEL: Logging level (default: INFO)
    - API_CORS_ORIGINS: Comma-separated CORS origins
    - API_HMAC_SECRET: Secret for webhook HMAC verification (REQUIRED)
    - DATABASE_URL: PostgreSQL connection string (REQUIRED)
    - REDIS_URL: Redis connection string (default: redis://localhost:6379/0)
    """
    
    # Server Configuration
    host: str = Field(
        default="0.0.0.0",
        description="Listen host address"
    )
    
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Listen port"
    )
    
    debug: bool = Field(
        default=False,
        description="Debug mode (disable in production)"
    )
    
    workers: int = Field(
        default=4,
        ge=1,
        le=16,
        description="Uvicorn worker count"
    )
    
    # Logging
    log_level: str = Field(
        default="INFO",
        description="Python logging level"
    )
    
    log_file: Optional[str] = Field(
        default=None,
        description="Log file path (stdout if null)"
    )
    
    # CORS Configuration
    cors_origins: Set[str] = Field(
        default=set(),
        description="Allowed CORS origins"
    )
    
    cors_credentials: bool = Field(
        default=True,
        description="Allow CORS credentials"
    )
    
    cors_methods: Set[str] = Field(
        default={"GET", "POST", "PUT", "DELETE", "OPTIONS"},
        description="Allowed CORS methods"
    )
    
    cors_headers: Set[str] = Field(
        default={"Content-Type", "Authorization", "X-Request-ID"},
        description="Allowed CORS headers"
    )
    
    # Security
    hmac_secret: str = Field(
        description="Secret key for webhook HMAC verification (REQUIRED)"
    )
    
    session_secret: str = Field(
        description="Secret key for session management (REQUIRED)"
    )
    
    session_ttl_hours: int = Field(
        default=24,
        ge=1,
        le=720,
        description="Session time-to-live (hours)"
    )
    
    # Database
    database_url: str = Field(
        description="PostgreSQL connection string (REQUIRED)"
    )
    
    database_pool_size: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Database connection pool size"
    )
    
    database_max_overflow: int = Field(
        default=20,
        ge=0,
        le=100,
        description="Max overflow connections"
    )
    
    # Redis
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    
    redis_timeout_seconds: int = Field(
        default=30,
        ge=1,
        description="Redis operation timeout"
    )
    
    # Rate Limiting
    rate_limit_enabled: bool = Field(
        default=True,
        description="Enable rate limiting"
    )
    
    rate_limit_requests: int = Field(
        default=1000,
        ge=1,
        description="Requests per time window"
    )
    
    rate_limit_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Rate limit window (seconds)"
    )
    
    # API Configuration
    api_title: str = Field(
        default="CryptoScan Platform",
        description="OpenAPI title"
    )
    
    api_version: str = Field(
        default="0.1.0",
        description="API version"
    )
    
    api_docs_enabled: bool = Field(
        default=True,
        description="Enable /docs endpoint"
    )
    
    # Pagination
    default_page_size: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Default pagination size"
    )
    
    max_page_size: int = Field(
        default=500,
        ge=1,
        description="Maximum pagination size"
    )
    
    # Timeouts
    request_timeout_seconds: int = Field(
        default=30,
        ge=1,
        description="HTTP request timeout"
    )
    
    background_job_timeout_seconds: int = Field(
        default=3600,
        ge=60,
        description="Background job timeout (seconds)"
    )
    
    class Config:
        env_prefix = "API_"
        case_sensitive = False
    
    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        """Parse comma-separated CORS origins from env var."""
        if isinstance(v, str):
            return {origin.strip() for origin in v.split(",") if origin.strip()}
        return v if v else set()
    
    @validator("database_url")
    def validate_database_url(cls, v):
        """Validate PostgreSQL connection string."""
        if not v.startswith("postgresql://"):
            raise ValueError("Only PostgreSQL is supported")
        return v
    
    @validator("redis_url")
    def validate_redis_url(cls, v):
        """Validate Redis URL."""
        if not v.startswith("redis://"):
            raise ValueError("Invalid Redis URL format")
        return v
    
    @validator("hmac_secret")
    def validate_hmac_secret(cls, v):
        """Ensure HMAC secret is sufficiently long."""
        if len(v) < 32:
            raise ValueError("HMAC secret must be at least 32 characters")
        return v
    
    @validator("session_secret")
    def validate_session_secret(cls, v):
        """Ensure session secret is sufficiently long."""
        if len(v) < 32:
            raise ValueError("Session secret must be at least 32 characters")
        return v
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.debug is True
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.debug is False


def get_api_settings() -> APISettings:
    """
    Get API settings singleton (lazy-loaded).
    Use this function throughout API service.
    """
    return APISettings()