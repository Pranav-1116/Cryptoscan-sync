"""Worker settings — one schema used everywhere."""

from __future__ import annotations

from pydantic_settings import SettingsConfigDict

from shared_config.base_settings import BaseSettings


class WorkerSettings(BaseSettings):
    """Worker settings — inherits env/log-level validation and secret
    redaction from shared_config.BaseSettings (enterprise base)."""

    model_config = SettingsConfigDict(env_file=".env", extra="allow", case_sensitive=False)

    ENVIRONMENT: str = "development"
    LOG_LEVEL: str = "INFO"
    REDIS_URL: str = ""
    QUEUE_NAME: str = "cryptoscan:jobs:queue"
    SCAN_JOB_QUEUE_KEY: str = "cryptoscan:jobs:queue"
    DATABASE_URL: str = "sqlite:///./data/cryptoscan.db"
    WORKSPACE_BASE: str = "./data/workspaces"
    WORKSPACE_BASE_PATH: str = "./data/workspaces"
    SCANNER_TIMEOUT: int = 300
    CLONE_TIMEOUT_SECONDS: int = 300
    SCAN_TIMEOUT_SECONDS: int = 600
    MAX_CONCURRENT_JOBS: int = 2
    # job-path hardening (see worker/core/job_consumer.py, job_reaper.py)
    JOB_LEASE_TTL_SECONDS: int = 60
    JOB_MAX_REDELIVERIES: int = 3
    JOB_RUNNING_TIMEOUT_MINUTES: int = 90
    JOB_QUEUED_TIMEOUT_MINUTES: int = 10
    CLEANUP_WORKSPACE: bool = True
    ALLOW_SQLITE: bool = False
    POLICY_RULES_DIR: str = ""
    NORMALIZATION_RULES_DIR: str = ""
    ALERT_EMAIL_TO: str = ""
    SMTP_HOST: str = ""
    # 24/7 live-monitor daemon (scripts/run_monitor.py)
    MONITOR_TICK_SECONDS: float = 30.0          # daemon tick cadence
    MONITOR_LEASE_TTL_SECONDS: float = 60.0     # leader-lease TTL (multi-AZ HA)
    MONITOR_JITTER_FRACTION: float = 0.1        # next_scan_at random spread (0 = off)
    MONITOR_WATCH_ENABLED: bool = True          # change-watch probes on every tick
    MONITOR_WATCH_PROBE_TIMEOUT_SECONDS: float = 10.0
    MONITOR_CONCURRENCY: int = 2                # parallel scans per tick (1 = serial)
    MONITOR_RUN_REPORTS: bool = True            # execute due compliance report schedules each tick
    MONITOR_RUN_NETWORK: bool = True            # execute persisted /network/targets schedules each tick
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

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    def validate_runtime(self) -> None:
        if not self.is_production:
            return
        errors: list[str] = []
        if self.DATABASE_URL.startswith("sqlite") and not self.ALLOW_SQLITE:
            errors.append("DATABASE_URL must be PostgreSQL in production (or set ALLOW_SQLITE=true)")
        if not (self.REDIS_URL or "").strip():
            errors.append("REDIS_URL is required in production")
        if errors:
            raise RuntimeError("production worker configuration rejected: " + "; ".join(errors))


def get_settings() -> WorkerSettings:
    return WorkerSettings()


# Back-compat alias
Settings = WorkerSettings
