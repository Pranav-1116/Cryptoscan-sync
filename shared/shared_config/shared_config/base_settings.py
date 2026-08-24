"""Shared Pydantic settings base used by every CryptoScan service."""

from __future__ import annotations

from pydantic_settings import BaseSettings as PydanticBaseSettings, SettingsConfigDict


class BaseSettings(PydanticBaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="allow",
        case_sensitive=False,
    )

    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    REDIS_URL: str = ""
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: str = "development"
    SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_development(self) -> bool:
        return not self.is_production
