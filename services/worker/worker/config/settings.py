"""Worker settings."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    REDIS_URL: str = ""
    QUEUE_NAME: str = "cryptoscan:jobs:queue"
    SCAN_JOB_QUEUE_KEY: str = "cryptoscan:jobs:queue"
    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    WORKSPACE_BASE: str = "./data/workspaces"
    WORKSPACE_BASE_PATH: str = "./data/workspaces"
    SCANNER_TIMEOUT: int = 300
    LOG_LEVEL: str = "INFO"
    CLEANUP_WORKSPACE: bool = True
    POLICY_RULES_DIR: str = ""
    NORMALIZATION_RULES_DIR: str = ""
    ALERT_EMAIL_TO: str = ""
    SMTP_HOST: str = ""
    NEO4J_URI: str = ""
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "cryptoscan"
    NEO4J_DATABASE: str = "neo4j"
    ISTIO_PROMETHEUS_URL: str = ""
    GITHUB_TOKEN: str = ""
    DASHBOARD_URL: str = ""

    @property
    def queue_key(self) -> str:
        return self.SCAN_JOB_QUEUE_KEY or self.QUEUE_NAME

    @property
    def workspace_dir(self) -> str:
        return self.WORKSPACE_BASE_PATH or self.WORKSPACE_BASE


def get_settings() -> Settings:
    return Settings()
