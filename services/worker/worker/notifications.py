"""Opt-in notification scheduler, deliberately separate from scanning/monitoring.

Only explicitly selected estates are visited. A fresh session per estate avoids
identity-map reuse across tenants. Receipt leases, not process leadership,
protect concurrent daemon/manual drains. No exactly-once or hard-deadline claim.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from uuid import UUID

from pydantic import Field, FiniteFloat, field_validator, model_validator
from pydantic_settings import SettingsConfigDict
from sqlalchemy import select
from sqlalchemy.engine import make_url

from shared_config.base_settings import BaseSettings

logger = logging.getLogger(__name__)


class NotificationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    DATABASE_URL: str = Field(default="sqlite:///./data/cryptoscan.db", repr=False)
    NOTIFICATION_DISPATCH_ENABLED: bool = False
    NOTIFICATION_DISPATCH_PLATFORM: bool = False
    NOTIFICATION_DISPATCH_TENANTS: list[UUID] = Field(default_factory=list, max_length=1000)
    NOTIFICATION_DISPATCH_REGION: str = ""
    NOTIFICATION_DISPATCH_INTERVAL_SECONDS: FiniteFloat = Field(default=30, ge=1, le=3600)
    NOTIFICATION_DISPATCH_BUDGET_SECONDS: FiniteFloat = Field(default=20, ge=0.1, le=120)
    NOTIFICATION_DISPATCH_SCOPE_BUDGET_SECONDS: FiniteFloat = Field(default=5, ge=0.1, le=30)
    NOTIFICATION_DISPATCH_MAX_SCOPES: int = Field(default=10, ge=1, le=100)
    NOTIFICATION_DISPATCH_LIMIT: int = Field(default=50, ge=1, le=200)

    @field_validator("NOTIFICATION_DISPATCH_REGION")
    @classmethod
    def normalize_region(cls, value):
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_selection(self):
        tenants = self.NOTIFICATION_DISPATCH_TENANTS
        if len(set(tenants)) != len(tenants):
            raise ValueError("duplicate notification tenant selection")
        if self.NOTIFICATION_DISPATCH_SCOPE_BUDGET_SECONDS > self.NOTIFICATION_DISPATCH_BUDGET_SECONDS:
            raise ValueError("notification scope budget exceeds tick budget")
        if self.NOTIFICATION_DISPATCH_ENABLED:
            if not tenants and not self.NOTIFICATION_DISPATCH_PLATFORM:
                raise ValueError("notification dispatch requires an explicit estate selection")
            if tenants and not self.NOTIFICATION_DISPATCH_REGION:
                raise ValueError("notification tenant dispatch requires a declared processing region")
        return self

    def validate_runtime(self):
        try:
            url = make_url(self.DATABASE_URL)
            backend = url.get_backend_name()
        except Exception:
            raise RuntimeError("invalid notification database configuration") from None
        if backend not in {"postgresql", "sqlite"} or (self.is_production and backend != "postgresql"):
            raise RuntimeError("notification dispatch requires PostgreSQL in production; SQLite is development/test only")

        if backend == "sqlite" and (url.database in {None, "", ":memory:"} or url.query.get("mode") == "memory"):
            raise RuntimeError("notification scheduler requires a durable file database")

    def sensitive_fields(self):
        return sorted(set(super().sensitive_fields()) | {"DATABASE_URL", "REDIS_URL"})

    @property
    def scopes(self):
        return ([None] if self.NOTIFICATION_DISPATCH_PLATFORM else []) + [
            str(owner) for owner in self.NOTIFICATION_DISPATCH_TENANTS]


class NotificationLoop:
    def __init__(self, settings, *, session_factory, drain=None, monotonic=time.monotonic, stop_event=None):
        from control_plane.notification_dispatch import drain_notifications

        self.settings = settings
        self.session_factory = session_factory
        self.drain = drain or drain_notifications
        self.monotonic = monotonic
        self.stop = stop_event if stop_event is not None else threading.Event()
        self.cursor = 0

    def request_stop(self, *_args):
        self.stop.set()

    def run_once(self):
        from db.models.control_plane import Tenant
        from db.tenancy import TenantScopeViolation, current_tenant, tenant_scope

        if current_tenant() is not None:
            raise TenantScopeViolation("notification scheduler requires a platform entry point")
        counts = Counter({name: 0 for name in (
            "scopes_attempted", "scopes_completed", "scopes_blocked", "scopes_failed", "scopes_unconfirmed",
            "delivered", "failed", "skipped", "lease_lost", "destination_attempts", "enqueued",
            "observed_pending_receipts", "observed_legacy_unknown",
        )})
        if not self.settings.NOTIFICATION_DISPATCH_ENABLED:
            return {"enabled": False, "ok": False, "scopes_attempted": 0}
        scopes = self.settings.scopes
        deadline = self.monotonic() + self.settings.NOTIFICATION_DISPATCH_BUDGET_SECONDS
        for _ in range(min(len(scopes), self.settings.NOTIFICATION_DISPATCH_MAX_SCOPES)):
            remaining = deadline - self.monotonic()
            if self.stop.is_set() or remaining <= 0:
                break
            owner = scopes[self.cursor % len(scopes)]
            # Advance even on a poison scope/error/budget overrun. A hot first
            # estate must not permanently starve the remaining selected estates.
            self.cursor = (self.cursor + 1) % len(scopes)
            counts["scopes_attempted"] += 1
            try:
                with tenant_scope(owner), self.session_factory() as session:
                    if owner is not None:
                        tenant = session.scalar(select(Tenant).where(Tenant.id == owner))
                        if tenant is None or not tenant.is_active:
                            counts["scopes_blocked"] += 1
                            continue
                        regions = tenant.processing_regions
                        if regions is None:
                            regions = [tenant.data_residency_region]
                        if not isinstance(regions, list) or not regions or any(
                            not isinstance(region, str) or not region.strip() for region in regions
                        ) or self.settings.NOTIFICATION_DISPATCH_REGION not in {
                            region.strip().lower() for region in regions
                        }:
                            counts["scopes_blocked"] += 1
                            continue
                    remaining = deadline - self.monotonic()
                    if self.stop.is_set() or remaining <= 0:
                        break
                    result = self.drain(
                        session, limit=self.settings.NOTIFICATION_DISPATCH_LIMIT,
                        budget_s=min(remaining, self.settings.NOTIFICATION_DISPATCH_SCOPE_BUDGET_SECONDS),
                        should_stop=self.stop.is_set,
                    )
                    counts["scopes_completed"] += 1
                    for name in ("delivered", "failed", "skipped", "lease_lost", "destination_attempts", "enqueued"):
                        counts[name] += result.get(name, 0)
                    statuses = result.get("receipts", {})
                    counts["observed_pending_receipts"] += sum(statuses.get(status, 0) for status in (
                        "pending", "inflight", "failed", "skipped"))
                    counts["observed_legacy_unknown"] += statuses.get("legacy_unknown", 0)
                    if not result.get("ok", False):
                        counts["scopes_unconfirmed"] += 1
            except Exception as exc:
                counts["scopes_failed"] += 1
                # Never log endpoints, credentials, event details or exception text.
                logger.error("notification_scope_failed error_type=%s", type(exc).__name__)
        ok = counts["scopes_completed"] > 0 and not self.stop.is_set() and not any(counts[name] for name in (
            "scopes_failed", "scopes_blocked", "scopes_unconfirmed", "failed", "skipped", "lease_lost"))
        return {"enabled": True, "ok": ok, "stopped": self.stop.is_set(), **dict(counts)}

    def run_forever(self):
        while not self.stop.is_set():
            outcome = self.run_once()
            logger.info("notification_tick %s", outcome)
            if not outcome["enabled"]:
                return 2
            self.stop.wait(self.settings.NOTIFICATION_DISPATCH_INTERVAL_SECONDS)
        return 0


def _initialize(settings):
    import os

    from db.connection.engine import create_db_engine
    from db.connection.session import init_db

    # init_db's production migration gate reads the process environment. Honor
    # settings loaded from .env too; never bootstrap production metadata as dev.
    os.environ["ENVIRONMENT"] = settings.ENVIRONMENT
    engine = create_db_engine(settings.DATABASE_URL, application_name="cryptoscan-notifications")
    try:
        init_db(engine)
    except Exception:
        engine.dispose()
        raise
    return engine


def main(argv=None):
    import argparse
    import json
    import signal

    from sqlalchemy.orm import sessionmaker

    parser = argparse.ArgumentParser(description="Opt-in durable webhook/SIEM notification scheduler (no SMTP).")
    parser.add_argument("--once", action="store_true", help="one bounded tick for exactly one selected estate; not a complete backlog drain")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    # HTTP client INFO/DEBUG logs may contain full receiver URLs/query tokens.
    # Keep these quiet in this dedicated process, independently of root logging.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        settings = NotificationSettings()
        if not settings.NOTIFICATION_DISPATCH_ENABLED:
            logger.warning("notification_scheduler_disabled; explicitly enable and select estates before running")
            return 2
        settings.validate_runtime()
        if args.once and len(settings.scopes) != 1:
            raise RuntimeError("one-shot dispatch requires exactly one estate; use the daemon for fair multi-estate rotation")
        engine = _initialize(settings)
    except Exception as exc:
        logger.error("notification_scheduler_startup_failed error_type=%s; see docs/dev/notification-scheduler.md", type(exc).__name__)
        return 2
    try:
        loop = NotificationLoop(settings, session_factory=sessionmaker(bind=engine, expire_on_commit=False, autoflush=False))
        previous = {}
        try:
            for sig in (signal.SIGINT, signal.SIGTERM):
                previous[sig] = signal.signal(sig, loop.request_stop)
            if args.once:
                outcome = loop.run_once()
                print(json.dumps(outcome, sort_keys=True))
                return 0 if outcome["ok"] else 1
            return loop.run_forever()
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
    finally:
        engine.dispose()
