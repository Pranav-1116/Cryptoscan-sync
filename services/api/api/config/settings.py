"""API settings — one schema used everywhere."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class APISettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    HOST: str = "0.0.0.0"
    API_HOST: str = "0.0.0.0"
    PORT: int = 8000
    API_PORT: int = 8000
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    API_VERSION: str = "0.1.0"
    DOCS_ENABLED: bool = True

    SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"
    SESSION_EXPIRE_HOURS: int = 24
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "cryptoscan"

    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    REDIS_URL: str = ""
    SCAN_JOB_QUEUE_KEY: str = "cryptoscan:jobs:queue"

    CORS_ORIGINS: str = "*"
    TRUSTED_HOSTS: list[str] = Field(default_factory=lambda: ["*"])

    GITHUB_WEBHOOK_SECRET: str = "dev-webhook-secret-change-me-32chars!!"
    GITHUB_TOKEN: str = ""

    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_FROM: str = "alerts@cryptoscan.local"
    ALERT_EMAIL_TO: str = "security@example.com"

    @property
    def cors_origin_list(self) -> list[str]:
        if not self.CORS_ORIGINS or self.CORS_ORIGINS.strip() == "*":
            return ["*"]
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"


@lru_cache
def get_settings() -> APISettings:
    return APISettings()


# Back-compat alias
Settings = APISettings
