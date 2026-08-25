"""API settings — one schema used everywhere."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

WEAK_SECRET_KEYS = {
    "dev-cryptoscan-secret-key-change-in-production-32",
    "change-me-to-a-random-64-character-secret-key-please",
    "change-this-secret-in-production-32chars",
}
WEAK_PASSWORDS = {"", "cryptoscan", "admin", "password", "changeme", "secret"}
WEAK_WEBHOOK_SECRETS = {
    "dev-webhook-secret-change-me-32chars!!",
    "change-me-to-a-random-webhook-secret-32ch",
}


class APISettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    HOST: str = "0.0.0.0"
    API_HOST: str = "0.0.0.0"
    PORT: int = 8000
    API_PORT: int = 8000
    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    API_VERSION: str = "1.0.0"
    DOCS_ENABLED: bool | None = None

    SECRET_KEY: str = "dev-cryptoscan-secret-key-change-in-production-32"
    SESSION_EXPIRE_HOURS: int = 24
    COOKIE_SECURE: bool | None = None
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "cryptoscan"
    ADMIN_PASSWORD_HASH: str = ""
    LOGIN_MAX_FAILURES: int = 8
    LOGIN_LOCKOUT_SECONDS: int = 900

    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    REDIS_URL: str = ""
    SCAN_JOB_QUEUE_KEY: str = "cryptoscan:jobs:queue"
    ALLOW_SQLITE: bool = False

    CORS_ORIGINS: str = "*"
    ALLOW_INSECURE_CORS: bool = False
    TRUSTED_HOSTS: list[str] = Field(default_factory=lambda: ["*"])

    GITHUB_WEBHOOK_SECRET: str = "dev-webhook-secret-change-me-32chars!!"
    GITHUB_TOKEN: str = ""

    NEO4J_URI: str = ""
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cryptoscan"
    NEO4J_DATABASE: str = "neo4j"
    ISTIO_PROMETHEUS_URL: str = ""

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

    @property
    def is_test(self) -> bool:
        return self.ENVIRONMENT.lower() in {"test", "testing"}

    @property
    def docs_enabled(self) -> bool:
        if self.DOCS_ENABLED is not None:
            return bool(self.DOCS_ENABLED)
        return not self.is_production

    @property
    def cookie_secure(self) -> bool:
        if self.COOKIE_SECURE is not None:
            return bool(self.COOKIE_SECURE)
        return self.is_production

    @property
    def trusted_host_list(self) -> list[str]:
        return [str(item).strip() for item in (self.TRUSTED_HOSTS or []) if str(item).strip()]


def validate_runtime_settings(settings: APISettings | None = None) -> None:
    """Fail closed when ENVIRONMENT=production still has demo defaults."""
    settings = settings or get_settings()
    if not settings.is_production:
        return
    errors: list[str] = []
    secret = (settings.SECRET_KEY or "").strip()
    if len(secret) < 32 or secret in WEAK_SECRET_KEYS:
        errors.append("SECRET_KEY must be a unique value of at least 32 characters")
    if not settings.ADMIN_PASSWORD_HASH:
        password = settings.ADMIN_PASSWORD or ""
        if password.lower() in WEAK_PASSWORDS or len(password) < 12:
            errors.append("ADMIN_PASSWORD must be strong, or set ADMIN_PASSWORD_HASH")
    webhook = (settings.GITHUB_WEBHOOK_SECRET or "").strip()
    if webhook in WEAK_WEBHOOK_SECRETS or len(webhook) < 24:
        errors.append("GITHUB_WEBHOOK_SECRET must be a unique value of at least 24 characters")
    if settings.DATABASE_URL.startswith("sqlite") and not settings.ALLOW_SQLITE:
        errors.append("DATABASE_URL must be PostgreSQL in production (or set ALLOW_SQLITE=true)")
    if settings.cors_origin_list == ["*"] and not settings.ALLOW_INSECURE_CORS:
        errors.append("CORS_ORIGINS must be an explicit origin list (or set ALLOW_INSECURE_CORS=true)")
    if errors:
        raise RuntimeError("production configuration rejected: " + "; ".join(errors))


@lru_cache
def get_settings() -> APISettings:
    return APISettings()


# Back-compat alias
Settings = APISettings
