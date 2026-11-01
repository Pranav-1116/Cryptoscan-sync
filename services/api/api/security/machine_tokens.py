"""Machine principals: the credentials infrastructure presents instead of a session.

Three surfaces in this product are called by something that has no cookie jar and
no user role: Prometheus scraping ``/metrics``, an orchestrator probing
``/healthz/workers``, and Alertmanager posting a notification. Each authenticates
with a shared secret over a header, and each of those checks used to be — or was
about to be — a slightly different copy of the same comparison.

The properties that matter, in one place:

* **constant-time comparison**, so a low-volume endpoint cannot be turned into a
  token oracle by timing;
* **open in development, closed in production**, because a scrape config that
  needs a secret in a developer's checkout is a scrape config people disable;
* **fail closed at request time** when production has no token configured, even
  though ``validate_runtime_settings`` already refuses to boot — an ASGI probe
  does not necessarily run lifespan hooks;
* **two accepted presentations** (``Authorization: Bearer`` and the header the
  component's own docs use), so the caller does not have to be configured twice.

Refusals are :class:`fastapi.HTTPException`: 401 for a wrong or missing token,
503 for a production deployment with no token at all. Both are "not you" rather
than "not now", which is what a machine caller needs to know.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

#: The surface each token protects, for error messages that name the caller.
METRICS = "metrics"
WORKERS = "worker probe"
ALERTMANAGER = "alertmanager"


def _compare(presented: str, expected: str) -> bool:
    return bool(presented) and hmac.compare_digest(presented, expected)


def _presented(request: Request, header: str) -> str:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.headers.get(header, "").strip()


def require_token(request: Request, *, surface: str, expected: str,
                  header: str) -> None:
    """Check a machine token, or raise the refusal that fits."""
    from api.config.settings import get_settings

    if not get_settings().is_production:
        return
    value = (expected or "").strip()
    if len(value) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{surface} authentication is not configured",
        )
    if not _compare(_presented(request, header), value):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"{surface} authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_metrics_token(request: Request) -> None:
    """Prometheus's credential. Also gates the worker probe, which is a scrape."""
    from api.config.settings import get_settings

    require_token(request, surface=METRICS,
                  expected=get_settings().METRICS_TOKEN, header="x-metrics-token")


def require_alertmanager_token(request: Request) -> None:
    """Alertmanager's credential: a rule that fires must never be refused 401."""
    from api.config.settings import get_settings

    require_token(request, surface=ALERTMANAGER,
                  expected=get_settings().ALERTMANAGER_WEBHOOK_TOKEN,
                  header="x-alertmanager-token")
