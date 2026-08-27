"""Reliability layer for live cloud scans.

Enterprise rules implemented here:

- **Throttle-aware retry** — transient AWS errors (Throttling, 429, ...) are
  retried with exponential backoff + jitter instead of silently dropping a
  service's findings.
- **Real pagination** — list calls walk every page (NextToken/Marker); a
  hard ``[:80]`` cap no longer hides the rest of the estate.
- **Telemetry, not silence** — every error, truncation and resource count is
  recorded per (provider, service, region) so a scan report says exactly
  what was scanned and what failed. Fail-open stays for *unconfigured*
  providers; *configured but failing* scans surface their errors.
"""

from __future__ import annotations

import random
import time
from typing import Any, Callable

#: Error codes/messages that indicate throttling — safe to retry.
THROTTLE_MARKERS = (
    "throttling",
    "throttlingexception",
    "requestlimitexceeded",
    "toomanyrequests",
    "rateexceeded",
    "slowdown",
    "429",
)

RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}

MAX_RETRIES = 2
BASE_BACKOFF_SECONDS = 0.4


def is_throttle_error(exc: Exception) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    compact = "".join(ch for ch in text if ch.isalnum())
    if any(marker in compact for marker in THROTTLE_MARKERS):
        return True
    status = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    return status in RETRYABLE_STATUS_CODES


def call_with_retry(call: Callable[[], Any], *, retries: int = MAX_RETRIES, sleep: Callable[[float], None] = time.sleep) -> tuple[bool, Any, Exception | None]:
    """Run ``call`` retrying transient failures. Returns (ok, value, error)."""
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return True, call(), None
        except Exception as exc:  # noqa: BLE001 — boundary: classify then retry
            last_error = exc
            if not is_throttle_error(exc) or attempt == retries:
                return False, None, exc
            delay = BASE_BACKOFF_SECONDS * (2**attempt) + random.uniform(0, 0.2)
            sleep(delay)
    return False, None, last_error


def paginate(
    list_call: Callable[..., Any],
    *,
    items_key: str,
    next_token_keys: tuple[str, ...] = ("NextToken", "NextMarker", "Marker"),
    request_token_keys: tuple[str, ...] = ("NextToken", "Marker"),
    max_items: int = 500,
) -> tuple[list[dict[str, Any]], bool]:
    """Walk every page of an AWS-style list API.

    Returns (items, truncated) where ``truncated`` is True when the cap was
    reached before the API ran out of pages.
    """
    collected: list[dict[str, Any]] = []
    truncated = False
    request_token: str | None = None
    while True:
        kwargs: dict[str, Any] = {}
        if request_token:
            for key in request_token_keys:
                kwargs[key] = request_token
                break
        response = list_call(**kwargs) or {}
        page = response.get(items_key) or []
        if not isinstance(page, list):
            page = []
        for item in page:
            if len(collected) >= max_items:
                truncated = True
                return collected, truncated
            if isinstance(item, dict):
                collected.append(item)
        request_token = next(
            (str(response[key]) for key in next_token_keys if response.get(key)),
            None,
        )
        if not request_token:
            return collected, truncated


def cap_items(
    items: list,
    *,
    telemetry: "ScanTelemetry | None",
    provider: str,
    service: str,
    region: str,
    default: int = 500,
) -> list:
    """Apply the resource cap to a record list, recording a truncation when
    items are actually dropped — a cap may never silently shrink an estate."""
    cap = telemetry.max_resources if telemetry else default
    if len(items) <= cap:
        return items
    if telemetry:
        telemetry.record_truncation(provider, service, region, cap)
    return items[:cap]


class ScanTelemetry:
    """Aggregated live-scan telemetry across providers/services/regions."""

    def __init__(self, *, max_resources: int = 500) -> None:
        self.max_resources = max_resources
        self.resources_scanned = 0
        self.errors: list[dict[str, str]] = []
        self.truncations: list[dict[str, str]] = []
        self.providers_attempted: set[str] = set()

    def record_error(self, provider: str, service: str, region: str, exc: Exception) -> None:
        code = str(getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__) if hasattr(exc, "response") else type(exc).__name__
        self.errors.append(
            {"provider": provider, "service": service, "region": region, "code": str(code), "error": str(exc)[:300]}
        )

    def record_truncation(self, provider: str, service: str, region: str, cap: int) -> None:
        self.truncations.append(
            {"provider": provider, "service": service, "region": region, "cap": str(cap)}
        )

    def record_resources(self, count: int) -> None:
        self.resources_scanned += count

    # -- verdicts -------------------------------------------------------- #

    @property
    def configured(self) -> bool:
        """True when at least one provider was attempted."""
        return bool(self.providers_attempted)

    @property
    def total_failure(self) -> bool:
        """Every attempted call errored and nothing was found — the scan
        must not be reported as an empty success."""
        return self.configured and not self.resources_scanned and bool(self.errors)

    def status(self) -> str:
        if self.total_failure:
            return "FAILED"
        if self.errors or self.truncations:
            return "PARTIAL"
        if self.configured:
            return "OK"
        return "SKIPPED"

    def summary(self, *, enabled: bool) -> dict[str, Any]:
        return {
            "enabled": enabled,
            "status": self.status(),
            "resources_scanned": self.resources_scanned,
            "errors": self.errors[:50],
            "truncations": self.truncations[:50],
            "error_count": len(self.errors),
            "truncation_count": len(self.truncations),
        }
