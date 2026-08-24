"""
Base Settings
Common Pydantic Settings base class
"""
from pydantic_settings import BaseSettings as PydanticBaseSettings
from typing import Optional


class BaseSettings(PydanticBaseSettings):
    """
    Base settings class with common configuration
    All service settings should inherit from this
    """
    
    # Database
    DATABASE_URL: str = "postgresql://cryptoscan:cryptoscan@localhost:5432/cryptoscan"
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 10
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = True
    
    # Environment
    ENVIRONMENT: str = "development"  # development, staging, production
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "allow"  # Allow extra fields from env


def get_database_url(settings: BaseSettings) -> str:
    """
    Get database URL with proper formatting
    """
    return settings.DATABASE_URL


def is_production(settings: BaseSettings) -> bool:
    """
    Check if running in production
    """
    return settings.ENVIRONMENT.lower() == "production"