"""Idle-versus-absolute session limits.

Two independent clocks govern a session:

* the **absolute** expiry stamped into the token and the ``user_sessions``
  row (``SESSION_EXPIRE_HOURS``). Nothing extends it. A token carried off a
  machine and never used dies here.
* the **idle** window (``SESSION_IDLE_MINUTES``). A session that has not been
  used for this long is refused even though the absolute expiry is still in
  the future. A stolen token is therefore useful only while the real user is
  also active — the window in which both parties are racing is the window an
  operator sees in the audit trail.

Keeping both matters: an idle window alone lets a continuously-used token live
forever, and an absolute expiry alone leaves an unused token valid for its full
lifetime after a laptop is stolen.

The functions here are pure so the qualification drill can pin the boundaries
without a database or a wall clock.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

#: How often a used session refreshes its idle clock. Writing on every request
#: would turn each read into a write; a minute of granularity is far finer than
#: any sane idle window.
TOUCH_INTERVAL_SECONDS = 60


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; treat them as UTC, never as local."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def session_anchor(
    last_seen_at: datetime | None,
    created_at_ts: datetime | None,
) -> datetime | None:
    """When the idle clock started: last use, else creation."""
    return _aware(last_seen_at) or _aware(created_at_ts)


def idle_deadline(anchor: datetime | None, *, idle_minutes: int) -> datetime | None:
    """The moment an idle session dies, or ``None`` when idling is disabled."""
    if anchor is None or idle_minutes <= 0:
        return None
    return anchor + timedelta(minutes=int(idle_minutes))


def session_refusal(
    *,
    now: datetime,
    expires_at: datetime | None,
    created_at_ts: datetime | None,
    last_seen_at: datetime | None,
    idle_minutes: int,
) -> str | None:
    """``None`` when the session may be used, else why it may not.

    The absolute expiry is checked first: a session past it is dead regardless
    of activity, so idle freshness cannot resurrect it.
    """
    expires = _aware(expires_at)
    if expires is not None and expires < now:
        return "expired"
    deadline = idle_deadline(
        session_anchor(last_seen_at, created_at_ts), idle_minutes=idle_minutes
    )
    if deadline is not None and deadline < now:
        return "idle"
    return None


def touch_due(last_seen_at: datetime | None, *, now: datetime,
              interval_seconds: int = TOUCH_INTERVAL_SECONDS) -> bool:
    """Whether this use should move the idle clock forward."""
    seen = _aware(last_seen_at)
    if seen is None:
        return True
    return (now - seen) >= timedelta(seconds=int(interval_seconds))
