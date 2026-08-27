"""
Policy Engine Settings - Configuration management.

Loads settings from environment variables with validation.
"""

import logging
from pathlib import Path
from pydantic import BaseSettings, Field, validator

logger = logging.getLogger(__name__)


class PolicySettings(BaseSettings):
    """Policy engine configuration."""

    # Core settings
    ENVIRONMENT: str = Field(
        default="development",
        env="ENVIRONMENT"
    )
    
    DEBUG: bool = Field(
        default=False,
        env="DEBUG"
    )
    
    # Rules configuration
    RULES_DIRECTORY: str = Field(
        default="./rule_definitions",
        env="POLICY_RULES_DIRECTORY"
    )
    
    RULES_CACHE_ENABLED: bool = Field(
        default=True,
        env="POLICY_RULES_CACHE_ENABLED"
    )
    
    RULES_RELOAD_ON_CHANGE: bool = Field(
        default=False,
        env="POLICY_RULES_RELOAD_ON_CHANGE"
    )
    
    # Evaluation settings
    EVALUATION_TIMEOUT_SECONDS: int = Field(
        default=30,
        env="POLICY_EVALUATION_TIMEOUT_SECONDS"
    )
    
    MAX_BATCH_SIZE: int = Field(
        default=1000,
        env="POLICY_MAX_BATCH_SIZE"
    )
    
    # Logging
    LOG_LEVEL: str = Field(
        default="INFO",
        env="POLICY_LOG_LEVEL"
    )
    
    LOG_FORMAT: str = Field(
        default="json",
        env="POLICY_LOG_FORMAT"
    )

    @validator("RULES_DIRECTORY")
    def validate_rules_directory(cls, v):
        """Ensure rules directory exists."""
        path = Path(v)
        if not path.exists():
            logger.warning(
                f"Rules directory does not exist: {v}. "
                "It will be created if rules are loaded."
            )
        return v

    @validator("EVALUATION_TIMEOUT_SECONDS")
    def validate_timeout(cls, v):
        """Ensure timeout is positive."""
        if v <= 0:
            raise ValueError("EVALUATION_TIMEOUT_SECONDS must be positive")
        return v

    @validator("MAX_BATCH_SIZE")
    def validate_batch_size(cls, v):
        """Ensure batch size is reasonable."""
        if v <= 0:
            raise ValueError("MAX_BATCH_SIZE must be positive")
        if v > 10000:
            logger.warning(
                f"MAX_BATCH_SIZE of {v} is very large, "
                "consider reducing for better performance"
            )
        return v

    class Config:
        env_file = ".env"
        case_sensitive = True

    def __init__(self, **data):
        """Initialize settings and log configuration."""
        super().__init__(**data)
        logger.info(
            "Policy engine settings loaded",
            extra={
                "environment": self.ENVIRONMENT,
                "debug": self.DEBUG,
                "rules_directory": self.RULES_DIRECTORY,
                "log_level": self.LOG_LEVEL
            }
        )