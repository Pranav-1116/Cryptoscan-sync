"""Expiry forecasting and the rotation calendar.

Two inventories age in production: payment keys (``expiry_at``) and TLS
certificates (``not_after``). This module turns both into one forward-looking
calendar so operations can staff ceremonies and certificate renewals instead
of discovering expiries on incident calls.

- horizon buckets: EXPIRED / CRITICAL_7D / WARNING_30D / NOTICE_90D / OK;
- per-week rotation load for the next N weeks (ceremonies are staffed work);
- items expiring soon that have **no ceremony record covering the window**
  (PAY-015 — a rotation without dual control planned is a finding, not a
  surprise).

Honesty: keys/certs with no expiry date land in ``undated`` — counted, never
guessed. A ceremony "covers" the window if one is scheduled (held_at in the
future) for that key.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

HORIZONS = (
    ("EXPIRED", 0),
    ("CRITICAL_7D", 7),
    ("WARNING_30D", 30),
    ("NOTICE_90D", 90),
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_datetime(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def bucket(days_left: float) -> str:
    for name, window in HORIZONS:
        if days_left <= window:
            return name
    return "OK"


@dataclass
class ExpiryItem:
    kind: str            # PAYMENT_KEY | CERTIFICATE
    reference: str       # key_id or subject
    expires_at: datetime
    days_left: int
    status: str
    meta: dict

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "reference": self.reference,
            "expires_at": self.expires_at.isoformat(),
            "days_left": self.days_left,
            "status": self.status,
            **({"meta": self.meta} if self.meta else {}),
        }


class ExpiryForecaster:
    def __init__(self, *, horizon_days: int = 90, now: datetime | None = None):
        self.horizon_days = horizon_days
        self._now = now or _utcnow()

    def forecast(
        self,
        keys: Iterable[dict],
        certificates: Iterable[dict] | None = None,
        *,
        ceremonies: Iterable[dict] | None = None,
    ) -> dict:
        items: list[ExpiryItem] = []
        undated = 0

        for key in keys:
            expires = _as_datetime(key.get("expiry_at"))
            if expires is None:
                undated += 1
                continue
            items.append(ExpiryItem(
                "PAYMENT_KEY", str(key.get("key_id") or "?"), expires,
                days_left=int((expires - self._now).total_seconds() // 86_400),
                status=bucket((expires - self._now).total_seconds() / 86_400),
                meta={"algorithm": key.get("algorithm"), "usage": key.get("key_usage"),
                      "device": key.get("hsm_device")},
            ))

        for cert in certificates or []:
            expires = _as_datetime(cert.get("not_after"))
            if expires is None:
                undated += 1
                continue
            items.append(ExpiryItem(
                "CERTIFICATE", str(cert.get("subject") or cert.get("fingerprint", "?"))[:80], expires,
                days_left=int((expires - self._now).total_seconds() // 86_400),
                status=bucket((expires - self._now).total_seconds() / 86_400),
                meta={"issuer": (cert.get("issuer") or "")[:60],
                      "key_algorithm": cert.get("public_key_algorithm")},
            ))

        items.sort(key=lambda item: item.expires_at)
        upcoming = [item for item in items if 0 <= item.days_left <= self.horizon_days]

        # PAY-015: a payment key rotating inside the window with no ceremony
        # scheduled for it (future-dated ceremony record) — dual control must
        # be planned before the rotation, not improvised during it.
        scheduled = {
            str(ceremony.get("key_id") or "")
            for ceremony in (ceremonies or [])
            if (_as_datetime(ceremony.get("held_at")) or self._now) >= self._now
            and str(ceremony.get("status") or "PLANNED") != "ABANDONED"
        }
        findings = [
            {
                "rule_id": "PAY-015", "severity": 3, "blocking": False,
                "key_id": item.reference,
                "message": f"{item.kind.lower().replace('_', ' ')} '{item.reference}' rotates in "
                           f"{item.days_left}d with no ceremony scheduled (dual control unplanned)",
                "evidence": {"days_left": item.days_left, "expires_at": item.expires_at.isoformat()},
            }
            for item in upcoming
            if item.kind == "PAYMENT_KEY" and item.reference not in scheduled
        ]

        return {
            "as_of": self._now.isoformat(),
            "horizon_days": self.horizon_days,
            "by_status": _counts(items),
            "upcoming": [item.to_dict() for item in upcoming],
            "upcoming_count": len(upcoming),
            "undated_items": undated,
            "rotation_calendar": self._calendar(items),
            "findings": findings,
        }

    def _calendar(self, items: list[ExpiryItem]) -> dict[str, dict[str, int]]:
        """Per-ISO-week load for the horizon: how many keys/certs rotate when."""
        weeks: dict[str, dict[str, int]] = {}
        for item in items:
            if not 0 <= item.days_left <= self.horizon_days * 2:
                continue
            week_start = (self._now + timedelta(days=item.days_left))
            monday = week_start - timedelta(days=week_start.weekday())
            key = monday.date().isoformat()
            weeks.setdefault(key, {"payment_keys": 0, "certificates": 0})
            if item.kind == "PAYMENT_KEY":
                weeks[key]["payment_keys"] += 1
            else:
                weeks[key]["certificates"] += 1
        return dict(sorted(weeks.items()))


def _counts(items: list[ExpiryItem]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.status] = counts.get(item.status, 0) + 1
    return counts
