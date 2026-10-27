"""Authentication lifecycle events for the real-time stream.

Every account lifecycle transition (login, logout, register, password change,
profile update, failed login) publishes a deterministic ``auth.*`` event on
the in-process bus so SSE subscribers — the console's live feed, a SIEM tail,
an audit screen — see security-relevant activity the instant it happens.

These events carry **identity and role metadata only — never tokens, password
material, or secrets**. Publication is best-effort: a bus hiccup must never
break an authentication flow, so every call swallows its own errors.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_SENSITIVE_RE = re.compile(r"(token|password|secret|cookie|recovery|hash)", re.IGNORECASE)


def publish_auth(event_type: str, payload: dict[str, Any] | None = None) -> None:
    """Publish an ``auth.*`` event to the real-time bus (never raises).

    `event_type` is normalized to start with ``auth.`` so subscribers can
    filter the whole security lifecycle with a single prefix match.
    """
    name = event_type if event_type.startswith("auth.") else f"auth.{event_type}"
    try:
        from api.events.bus import get_event_bus

        # Defensive copy + strip anything that looks sensitive before it can
        # ever reach a subscriber.
        safe = {
            k: v for k, v in (payload or {}).items() if not _SENSITIVE_RE.search(str(k))
        }
        get_event_bus().publish(name, safe, source="auth")
    except Exception:  # pragma: no cover - the bus is best-effort
        logger.debug("auth_event_publish_failed", exc_info=True)
