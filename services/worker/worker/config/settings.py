"""
Worker Configuration
Loads from environment variables
"""
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Worker settings"""
    
    # Redis configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    QUEUE_NAME: str = "scan-jobs"
    
    # Database configuration
    DATABASE_URL: str = "postgresql://cryptoscan:cryptoscan@localhost:5432/cryptoscan"
    
    # Workspace configuration
    WORKSPACE_BASE: str = "/tmp/cryptoscan"
    
    # Scanner configuration
    SCANNER_TIMEOUT: int = 300  # 5 minutes
    
    # Logging
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


def get_settings() -> Settings:
    """Factory function"""
    return Settings()