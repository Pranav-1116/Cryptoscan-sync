"""Alertmanager's door into the platform: one route, one counter, no session.

Guide 117's alerting row was a PARTIAL with a plain reason: fifteen rules named
metrics that exist, evaluated on a scraped endpoint, and then went **nowhere** —
the bundled Prometheus had no ``alerting:`` stanza, so a paging alert was a line
in a file. Shipping rules without a receiver is the observability equivalent of
logging to a file nobody opens.

This module is the receiving end:

* ``POST /ops/alerts/alertmanager`` accepts an Alertmanager **webhook v4**
  notification (the shape Alertmanager posts, not a shape invented here) and
  answers with what it accepted.
* It is authenticated as an infrastructure principal — the shared
  ``ALERTMANAGER_WEBHOOK_TOKEN`` in ``Authorization: Bearer`` or
  ``X-Alertmanager-Token`` — because Alertmanager has no session and a rule that
  fires must not fail with 401. In production the token is required; a missing
  one is a startup error rather than an open door.
* Every notification is counted by ``alertname``, ``severity`` and ``status``,
  and the age of the last one is a gauge. That is what makes "is anything
  paging, and are we still receiving?" answerable from ``/metrics`` alone — a
  receiver that silently stops receiving is itself an outage, and now it is a
  series that goes stale instead of a silence.

Delivery to a human (email, chat, ticket) stays the bank's Alertmanager
configuration: this route is the platform's acknowledgement that the pager fired,
and the drill proves the path end to end from a rule in ``alerts.yml`` to a
scraped counter.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.security.machine_tokens import require_alertmanager_token

router = APIRouter(tags=["ops"])

#: Counters live in-process: a notification is a fact about this API instance,
#: and a restart resetting the count is honest (the age gauge carries the rest).
_LOCK = threading.Lock()
_RECEIVED: dict[tuple[str, str, str], int] = {}
_LAST_AT: float | None = None
_LAST_STATUS: str | None = None
_REJECTED: dict[str, int] = {}

_TERMINAL_STATUSES = {"firing", "resolved"}
_MAX_ALERTS_PER_NOTIFICATION = 200


class AlertLabelSet(BaseModel):
    alertname: str = Field(min_length=1, max_length=200)
    severity: str = Field(default="none", max_length=40)


class AlertIn(BaseModel):
    """One alert. Alertmanager sends many fields; these are the ones used."""

    status: str = Field(default="firing", max_length=20)
    labels: AlertLabelSet
    annotations: dict[str, Any] = Field(default_factory=dict)
    startsAt: str | None = None
    endsAt: str | None = None
    generatorURL: str | None = None
    fingerprint: str | None = None


class NotificationIn(BaseModel):
    """The Alertmanager webhook v4 payload."""

    version: str = Field(default="4", max_length=8)
    status: str = Field(default="firing", max_length=20)
    receiver: str | None = Field(default=None, max_length=200)
    groupKey: str | None = Field(default=None, max_length=400)
    alerts: list[AlertIn] = Field(default_factory=list,
                                  max_length=_MAX_ALERTS_PER_NOTIFICATION)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    externalURL: str | None = None


def reset() -> None:
    """Clear the counters (tests and drills only)."""
    global _LAST_AT, _LAST_STATUS
    with _LOCK:
        _RECEIVED.clear()
        _REJECTED.clear()
        _LAST_AT = None
        _LAST_STATUS = None


def counters() -> dict[str, Any]:
    with _LOCK:
        received = {f"{name}|{severity}|{state}": count
                    for (name, severity, state), count in _RECEIVED.items()}
        return {
            "received": received,
            "rejected": dict(_REJECTED),
            "last_at": _LAST_AT,
            "last_status": _LAST_STATUS,
        }


def metric_lines(now: float | None = None) -> list[str]:
    """Prometheus text for the receiver, emitted by ``/metrics``.

    ``cryptoscan_alertmanager_notifications_total`` counts what arrived;
    ``cryptoscan_alertmanager_last_notification_age_seconds`` is the one that
    catches a receiver that stopped receiving — an alerting pipeline that goes
    quiet is indistinguishable from a quiet estate until you measure the silence.
    """
    moment = time.time() if now is None else now
    with _LOCK:
        received = dict(_RECEIVED)
        last_at = _LAST_AT
        rejected = dict(_REJECTED)
    lines = [
        "# HELP cryptoscan_alertmanager_notifications_total Alerts accepted from "
        "Alertmanager, by alertname, severity and status",
        "# TYPE cryptoscan_alertmanager_notifications_total counter",
    ]
    for (name, severity, state), count in sorted(received.items()):
        lines.append(
            "cryptoscan_alertmanager_notifications_total"
            f'{{alertname="{name}",severity="{severity}",status="{state}"}} {count}'
        )
    if not received:
        # A counter family with no samples is invisible to Prometheus, and an
        # alert on "we stopped receiving" could never fire at zero.
        lines.append(
            'cryptoscan_alertmanager_notifications_total'
            '{alertname="",severity="",status=""} 0'
        )
    lines.extend([
        "# HELP cryptoscan_alertmanager_rejected_total Notifications refused as "
        "malformed",
        "# TYPE cryptoscan_alertmanager_rejected_total counter",
        "cryptoscan_alertmanager_rejected_total "
        f"{sum(rejected.values())}",
        "# HELP cryptoscan_alertmanager_last_notification_age_seconds Seconds since "
        "the last accepted notification (-1 when none has arrived)",
        "# TYPE cryptoscan_alertmanager_last_notification_age_seconds gauge",
        "cryptoscan_alertmanager_last_notification_age_seconds "
        f"{(round(max(0.0, moment - last_at), 1) if last_at else -1)}",
    ])
    return lines


class ReceiptOut(BaseModel):
    """What the receiver did with the notification it was handed."""

    schema_: str = Field(default="cryptoscan.alertmanager-receipt/1", alias="schema")
    accepted: int
    dropped: int
    alerts: list[dict[str, str]]
    receiver: str | None = None
    group_key: str | None = None
    received_at: str
    meaning: str

    model_config = {"populate_by_name": True}


@router.post(
    "/ops/alerts/alertmanager",
    response_model=ReceiptOut,
    # Declared as a dependency, not called inline: the route-auth inventory
    # resolves seams by module, and a machine principal is a seam.
    dependencies=[Depends(require_alertmanager_token)],
)
def alertmanager_webhook(
    body: NotificationIn,
    request: Request,
) -> dict[str, Any]:
    """Accept one Alertmanager notification and count it.

    A malformed *notification* is refused with 422 (Alertmanager retries, which
    is correct for a transient receiver bug); an individual alert with no
    ``alertname`` is dropped and counted, because one bad rule must not make the
    whole page disappear.
    """
    global _LAST_AT, _LAST_STATUS

    if body.status not in _TERMINAL_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"notification status must be one of {sorted(_TERMINAL_STATUSES)}",
        )

    accepted: list[dict[str, str]] = []
    dropped: list[str] = []
    with _LOCK:
        for alert in body.alerts:
            state = alert.status if alert.status in _TERMINAL_STATUSES else body.status
            name = (alert.labels.alertname or "").strip()
            if not name:
                dropped.append(alert.fingerprint or "unnamed")
                _REJECTED["unnamed_alert"] = _REJECTED.get("unnamed_alert", 0) + 1
                continue
            severity = (alert.labels.severity or "none").strip() or "none"
            key = (name, severity, state)
            _RECEIVED[key] = _RECEIVED.get(key, 0) + 1
            accepted.append({"alertname": name, "severity": severity, "status": state})
        _LAST_AT = time.time()
        _LAST_STATUS = body.status

    return {
        "schema": "cryptoscan.alertmanager-receipt/1",
        "accepted": len(accepted),
        "dropped": len(dropped),
        "alerts": accepted,
        "receiver": body.receiver,
        "group_key": body.groupKey,
        "received_at": datetime.now(timezone.utc).isoformat(),
        "meaning": (
            "the rules evaluated outside the process they watch and the resulting "
            "notification reached the platform: an alert that fires is now a counted "
            "event and a scraped series, not a line in a config file"
        ),
    }
