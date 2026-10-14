"""DB-backed API-key quota windows (§4.8, round 59).

``apikeys.policy.FixedWindowQuota`` counts in a process-local dict: with
more than one API replica, each process enforces its own window and a
"60/min" key gets 60×replicas. ``DbQuotaWindow`` is the drop-in
replacement that counts in ONE durable row per (key, window), shared by
every replica, via a single atomic upsert:

    INSERT INTO api_key_quota_windows (key_id, window_start, hit_count)
    VALUES (:key, :window, 1)
    ON CONFLICT (key_id, window_start)
    DO UPDATE SET hit_count = hit_count + 1
    RETURNING hit_count

One statement — no read-modify-write race, no advisory locks; two
replicas incrementing the same key serialize on the row. The window is
aligned to the epoch minute (floor(now/60)*60), identical semantics to
the in-memory counter. Old rows are pruned opportunistically (bounded
growth; a window row is only meaningful for 60s).

Failure posture: exceptions propagate — the DB is already a hard
dependency of API-key auth (the key row is read from it), so quota
failing together with auth is consistent, never silent fail-open.
"""

from __future__ import annotations

import math
import time

from apikeys.policy import QuotaBackend  # noqa: F401 — re-exported contract
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

WINDOW_SECONDS = 60.0
#: keep a couple of closed windows before pruning (observability slack)
_PRUNE_AFTER_SECONDS = 3 * WINDOW_SECONDS


def window_start_for(moment: float) -> float:
    """Epoch-aligned 60s window start for a moment."""
    return math.floor(moment / WINDOW_SECONDS) * WINDOW_SECONDS


class DbQuotaWindow:
    """Fixed-window counter backed by the shared ``api_key_quota_windows``
    table — one count across every replica."""

    def __init__(self, session: Session):
        self.session = session

    def check_and_consume(self, key_id: str, limit: int, *,
                          now: float | None = None) -> tuple[bool, int, float]:
        moment = time.time() if now is None else now
        if limit <= 0:
            return True, 10**9, moment + WINDOW_SECONDS  # unlimited
        start = window_start_for(moment)

        count = self._upsert_hit(key_id, start)
        self._prune(moment)
        remaining = max(0, limit - count)
        return (count <= limit, remaining, start + WINDOW_SECONDS)

    def _upsert_hit(self, key_id: str, start: float) -> int:
        """Atomically +1 the (key, window) row and return its new count."""
        from sqlalchemy import insert, select, update

        from db.models.api_key_quota_window import ApiKeyQuotaWindow

        dialect = self.session.bind.dialect.name if self.session.bind else ""
        if dialect in {"postgresql", "sqlite"}:
            stmt = self._dialect_insert(key_id, start)
            if stmt is not None:
                row = self.session.execute(stmt).scalar_one_or_none()
                if row is not None:
                    self.session.commit()
                    return int(row)
        # portable fallback (or dialects without upsert): UPDATE, then
        # INSERT on miss with the PK race caught
        updated = self.session.execute(
            update(ApiKeyQuotaWindow)
            .where(ApiKeyQuotaWindow.key_id == key_id,
                   ApiKeyQuotaWindow.window_start == start)
            .values(hit_count=ApiKeyQuotaWindow.hit_count + 1)
        )
        if updated.rowcount:
            count = self.session.execute(
                select(ApiKeyQuotaWindow.hit_count)
                .where(ApiKeyQuotaWindow.key_id == key_id,
                       ApiKeyQuotaWindow.window_start == start)
            ).scalar_one()
            self.session.commit()
            return int(count)
        try:
            self.session.execute(
                insert(ApiKeyQuotaWindow)
                .values(key_id=key_id, window_start=start, hit_count=1)
            )
            self.session.commit()
            return 1
        except IntegrityError:
            # a concurrent replica inserted first: take the UPDATE path
            self.session.rollback()
            return self._upsert_hit(key_id, start)

    def _dialect_insert(self, key_id: str, start: float):
        """Single-statement upsert for PG/SQLite, or None if unavailable."""
        import logging

        from db.models.api_key_quota_window import ApiKeyQuotaWindow

        logger = logging.getLogger(__name__)
        try:
            if self.session.bind is None:
                return None
            if self.session.bind.dialect.name == "postgresql":
                from sqlalchemy.dialects.postgresql import insert as pg_insert

                stmt = pg_insert(ApiKeyQuotaWindow)
                return stmt.values(
                    key_id=key_id, window_start=start, hit_count=1,
                ).on_conflict_do_update(
                    index_elements=["key_id", "window_start"],
                    set_={"hit_count": ApiKeyQuotaWindow.hit_count + 1},
                ).returning(ApiKeyQuotaWindow.hit_count)
            if self.session.bind.dialect.name == "sqlite":
                from sqlalchemy.dialects.sqlite import insert as sqlite_insert

                stmt = sqlite_insert(ApiKeyQuotaWindow)
                return stmt.values(
                    key_id=key_id, window_start=start, hit_count=1,
                ).on_conflict_do_update(
                    index_elements=["key_id", "window_start"],
                    set_={"hit_count": ApiKeyQuotaWindow.hit_count + 1},
                ).returning(ApiKeyQuotaWindow.hit_count)
        except Exception:  # pragma: no cover — fall back to portable path
            # logged, never silent: a broken upsert builder must be visible
            # while the portable UPDATE/INSERT path keeps quota correct
            logger.warning("quota_upsert_builder_unavailable", exc_info=True)
            return None
        return None

    def _prune(self, moment: float) -> None:
        """Opportunistic cleanup of closed windows (bounded growth)."""
        from sqlalchemy import delete

        from db.models.api_key_quota_window import ApiKeyQuotaWindow

        self.session.execute(
            delete(ApiKeyQuotaWindow).where(
                ApiKeyQuotaWindow.window_start < moment - _PRUNE_AFTER_SECONDS
            )
        )
        self.session.commit()

    def reset(self, key_id: str | None = None) -> None:

        from db.models.api_key_quota_window import ApiKeyQuotaWindow

        if key_id is None:
            self.session.query(ApiKeyQuotaWindow).delete()
        else:
            self.session.query(ApiKeyQuotaWindow).filter(
                ApiKeyQuotaWindow.key_id == key_id).delete()
        self.session.commit()
