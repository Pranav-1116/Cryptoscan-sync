"""Database-backed leader lease: run N monitor daemons, exactly one scans.

Multi-AZ monitoring without double-scanning. Every daemon heartbeats a single
lease row; only the lease holder runs ticks, the others stand by. If the
holder dies (host, AZ, network), the lease expires and a standby takes over
within ``ttl`` seconds — no human promotion step for the monitor tier.

Portability: a normal table + conditional UPDATE, so it works identically on
sqlite (single-host HA) and Postgres (multi-AZ). The renewal is a single
atomic statement — no read-modify-write race::

    UPDATE monitor_leases SET holder = :me, expires_at = :now + ttl
    WHERE name = 'monitor' AND (holder = :me OR expires_at < :now)

A daemon that loses the lease (network partition, slow tick) steps down on
the next heartbeat and logs it — two leaders can only coexist for the
partition duration, and the engine is idempotent (due-target selection +
fresh sessions) so a brief overlap is safe, not corrupting.
"""

from __future__ import annotations

import logging
import os
import socket
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import text

logger = logging.getLogger(__name__)

LEASE_NAME = "monitor"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def instance_id() -> str:
    """Stable-per-process identity: host:pid (readable in logs and the lease row)."""
    return f"{socket.gethostname()}:{os.getpid()}"


class LeaderLease:
    def __init__(self, session_factory: Callable[[], Any], *, ttl_seconds: float = 60.0,
                 name: str = LEASE_NAME, holder: str | None = None, clock=None):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.session_factory = session_factory
        self.ttl_seconds = ttl_seconds
        self.name = name
        self.holder = holder or instance_id()
        self._clock = clock or _utcnow
        self._leader = False

    @property
    def is_leader(self) -> bool:
        return self._leader

    def heartbeat(self) -> bool:
        """Acquire or renew the lease. True when this instance may tick."""
        now = self._clock()
        session = None
        try:
            session = self.session_factory()
            row = session.execute(
                text(
                    "UPDATE monitor_leases SET holder = :holder, expires_at = :expires, "
                "updated_at = :now WHERE name = :name "
                "AND (holder = :holder OR expires_at < :now OR expires_at IS NULL)"
                ),
                {"holder": self.holder, "expires": now + timedelta(seconds=self.ttl_seconds),
                 "now": now, "name": self.name},
            )
            if row.rowcount == 0:  # someone else holds a live lease
                session.rollback()
                if self._leader:
                    logger.warning("lease_lost", extra={"lease": self.name, "holder": self.holder})
                self._leader = False
                return False
            session.commit()
            if not self._leader:
                logger.info("lease_acquired", extra={"lease": self.name, "holder": self.holder,
                                                     "ttl_s": self.ttl_seconds})
            self._leader = True
            return True
        except Exception:
            if session is not None:
                try:
                    session.rollback()
                except Exception as _handler_exc:
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    pass
            self._leader = False  # cannot verify leadership -> assume standby, never double-run
            raise
        finally:
            if session is not None:
                session.close()

    def release(self) -> None:
        """Give the lease up immediately (graceful shutdown -> instant failover)."""
        session = self.session_factory()
        try:
            session.execute(
                text("UPDATE monitor_leases SET holder = NULL, expires_at = NULL, "
                     "updated_at = :now WHERE name = :name AND holder = :holder"),
                {"now": self._clock(), "name": self.name, "holder": self.holder},
            )
            session.commit()
        finally:
            session.close()
        if self._leader:
            logger.info("lease_released", extra={"lease": self.name, "holder": self.holder})
        self._leader = False


def ensure_lease_table(session: Any) -> None:
    """Idempotent DDL so a fresh install (or a pre-0031 schema) can still run HA."""
    session.execute(text(
        "CREATE TABLE IF NOT EXISTS monitor_leases ("
        "id VARCHAR(36) PRIMARY KEY, name VARCHAR(50) UNIQUE NOT NULL, holder VARCHAR(200), "
        "expires_at TIMESTAMP, created_at TIMESTAMP, updated_at TIMESTAMP)"
    ))
    existing = session.execute(
        text("SELECT name FROM monitor_leases WHERE name = :name"), {"name": LEASE_NAME}
    ).first()
    if existing is None:
        try:
            session.execute(
                text("INSERT INTO monitor_leases (id, name, updated_at) VALUES (:id, :name, :now)"),
                {"id": str(uuid.uuid4()), "name": LEASE_NAME, "now": _utcnow()},
            )
        except Exception:  # IntegrityError on a concurrent create — the row exists, that's enough
            session.rollback()
    session.commit()
