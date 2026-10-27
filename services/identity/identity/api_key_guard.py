"""Deterministic API-key network guard and rotation reminders.

Two pure functions with no DB/IO so they are trivially testable:

- ``ip_allowed`` — per-key IP allowlist (exact IP or CIDR) for machine keys.
- ``rotation_status`` — deterministic key-age / expiry reminders for the
  rotation dashboard (no mail/ML; just a rule-based state).

Everything fails closed: an unparseable allowlist or client address denies.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Iterable, Any

DEFAULT_ROTATION_DAYS = 90


def _now(now: datetime | None) -> datetime:
    ref = now or datetime.now(timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    return ref.astimezone(timezone.utc)


def normalize_allowlist(raw: Iterable[str] | str | None) -> list[str]:
    """Validate and normalize an IP/CIDR allowlist. Raises ValueError on junk."""
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = raw.replace(";", ",").replace(" ", ",").split(",")
    else:
        parts = list(raw)
    out: list[str] = []
    for item in parts:
        token = str(item or "").strip()
        if not token:
            continue
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
            else:
                net = ipaddress.ip_network(f"{token}/32" if ":" not in token else f"{token}/128",
                                           strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid IP/CIDR in allowlist: {token!r}") from exc
        out.append(str(net))
    # de-dup preserving order
    seen: set[str] = set()
    deduped = [x for x in out if not (x in seen or seen.add(x))]
    return deduped


def ip_allowed(client_ip: str | None, allowlist: Iterable[str] | str | None) -> bool:
    """Return True when the client IP is in the key's allowlist.

    Empty/None allowlist => no network restriction (True). A present but
    unparseable client IP or a non-empty allowlist that cannot match => False
    (fail closed).
    """
    rules = normalize_allowlist(allowlist)
    if not rules:
        return True
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False
    for rule in rules:
        try:
            net = ipaddress.ip_network(rule, strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False


def rotation_status(
    *,
    created_at: datetime | None,
    expires_at: datetime | None = None,
    rotate_after_days: int | None = DEFAULT_ROTATION_DAYS,
    revoked_at: datetime | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Deterministic key-rotation state for the admin dashboard.

    States: ``REVOKED``, ``EXPIRED``, ``EXPIRING_SOON`` (≤14d to expiry),
    ``ROTATION_DUE`` (older than rotate_after_days), ``ROTATION_SOON``
    (within 14 days of the rotation age), ``OK``.
    """
    ref = _now(now)
    age_days: int | None = None
    if created_at is not None:
        age_days = max(0, int((ref - _now(created_at)).total_seconds() // 86_400))

    if revoked_at is not None:
        return {"state": "REVOKED", "age_days": age_days, "days_until_expiry": None,
                "recommended_action": "none (revoked)"}

    days_until_expiry: int | None = None
    if expires_at is not None:
        days_until_expiry = int((_now(expires_at) - ref).total_seconds() // 86_400)
        if days_until_expiry < 0:
            return {"state": "EXPIRED", "age_days": age_days, "days_until_expiry": days_until_expiry,
                    "recommended_action": "rotate immediately — key is expired"}
        if days_until_expiry <= 14:
            return {"state": "EXPIRING_SOON", "age_days": age_days,
                    "days_until_expiry": days_until_expiry,
                    "recommended_action": f"rotate within {max(days_until_expiry,0)} days"}

    if rotate_after_days and age_days is not None:
        if age_days >= rotate_after_days:
            return {"state": "ROTATION_DUE", "age_days": age_days, "days_until_expiry": days_until_expiry,
                    "recommended_action": f"rotate — key is {age_days}d old (policy {rotate_after_days}d)"}
        due_in = rotate_after_days - age_days
        if due_in <= 14:
            return {"state": "ROTATION_SOON", "age_days": age_days, "days_until_expiry": days_until_expiry,
                    "recommended_action": f"schedule rotation in ~{due_in} days"}

    return {"state": "OK", "age_days": age_days, "days_until_expiry": days_until_expiry,
            "recommended_action": "none"}
