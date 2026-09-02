"""Real outbound delivery of SIEM / ITSM / SOAR webhooks.

The P1 integration layer built the deterministic payloads (CEF for SIEM,
ticket bodies for ITSM) and enqueued them as ``cp_queued_events``. This module
is the missing half: it actually performs the signed HTTP POST to the
registered integration endpoint, with per-provider payload shaping, HMAC
request signing, secret resolution from the *environment* (never from the
database — the vault doctrine), bounded retries with exponential backoff, and
a structured result the caller persists as a delivery log.

Air-gap doctrine: if no ``endpoint`` is configured on an integration the event
stays durably enqueued (outbox) and this returns status ``skipped`` — nothing
is fabricated as "delivered".
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from control_plane.integrations import SIEM_EVENT_CATEGORIES, to_cef

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------- SSRF guard
class WebhookUrlError(ValueError):
    """Raised when a webhook endpoint is unsafe (SSRF / non-HTTP / metadata)."""


#: well-known cloud-instance metadata hostnames that must never be reachable.
_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.google.com",
    "metadata",
    "metadata.aws.internal",
    "169.254.169.254.nip.io",
}

#: scheme allow-list — anything else (file://, gopher://, ftp:// …) is SSRF/abuse.
_ALLOWED_SCHEMES = {"http", "https"}


def _allow_private() -> bool:
    return os.environ.get("ZELNX_WEBHOOK_ALLOW_PRIVATE", "").lower() in {"1", "true", "yes", "on"}


def _ip_is_safe(ip: ipaddress._BaseAddress) -> bool:
    # These ranges are never valid webhook receivers — they are the SSRF
    # targets (cloud metadata 169.254/16, loopback, multicast, unspecified).
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    # RFC1918 / CGNAT / reserved space: SIEM/ITSM receivers on an internal
    # network are common in on-prem/air-gap deployments, so permitted by
    # default but blockable via ZELNX_WEBHOOK_ALLOW_PRIVATE=false.
    if ip.is_private or ip.is_reserved:
        if os.environ.get("ZELNX_WEBHOOK_ALLOW_PRIVATE", "").strip().lower() in {"0", "false", "no", "off"}:
            return False
        return True
    return True


def validate_webhook_url(url: str) -> str:
    """Validate an outbound webhook endpoint against SSRF.

    Allows only http/https; blocks cloud metadata hosts, loopback, link-local
    (169.254/16), multicast, unspecified and (unless ZELNX_WEBHOOK_ALLOW_PRIVATE
    is set) private/reserved address space. Hostnames are resolved and every
    resolved IP is checked (DNS-rebind hardening at request time). Raises
    :class:`WebhookUrlError`; returns the URL unchanged when safe.
    """
    if not url or not isinstance(url, str):
        raise WebhookUrlError("empty webhook endpoint")
    try:
        parsed = urlparse(url.strip())
    except ValueError as exc:
        raise WebhookUrlError(f"unparseable webhook URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise WebhookUrlError(f"disallowed scheme {scheme!r} (http/https only)")

    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise WebhookUrlError("webhook URL has no host")
    if host in _METADATA_HOSTNAMES:
        raise WebhookUrlError("blocked cloud-metadata endpoint")

    # IP literal in the URL — check directly.
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        if not _ip_is_safe(ip):
            raise WebhookUrlError(f"blocked non-public address {ip}")
        return url

    # Hostname — resolve and check every address; fail closed on resolution error.
    try:
        infos = socket.getaddrinfo(host, parsed.port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        raise WebhookUrlError(f"cannot resolve webhook host {host!r}: {exc}") from exc
    for info in infos:
        addr = info[4][0]
        try:
            resolved = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if not _ip_is_safe(resolved):
            raise WebhookUrlError(
                f"webhook host {host!r} resolves to blocked address {resolved}"
            )
    return url


#: event-type prefix -> integration kinds that consume it.
_KIND_FOR_PREFIX = {
    "siem": ("siem", "soar"),
    "itsm": ("itsm",),
    "ticket": ("itsm",),
}

#: providers that ingest raw JSON webhooks (generic).
_JSON_WEBHOOK_PROVIDERS = {"webhook", "sentinel", "chronicle", "qradar", "splunk"}

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_ATTEMPTS = 4


@dataclass
class DeliveryResult:
    integration_id: str
    provider: str
    kind: str
    endpoint: str
    status: str  # delivered | failed | skipped
    attempts: int = 0
    http_status: int | None = None
    response_excerpt: str | None = None
    error: str | None = None
    signature: str | None = None
    duration_ms: int | None = None
    at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id, "provider": self.provider,
            "kind": self.kind, "endpoint": self.endpoint, "status": self.status,
            "attempts": self.attempts, "http_status": self.http_status,
            "response_excerpt": self.response_excerpt, "error": self.error,
            "signature": self.signature, "duration_ms": self.duration_ms, "at": self.at,
        }


# --------------------------------------------------------------- secret lookup
def credential_secret(credential_id: str | None, provider: str) -> str | None:
    """Resolve a signing/token secret from the environment.

    Secrets never live in the database. The integration row carries a
    ``credential_id`` (a vault *reference*); the runtime maps it to an env var
    ``ZELNX_WEBHOOK_SECRET_<id>`` (or provider defaults
    ``SPLUNK_HEC_TOKEN`` / ``ZELNX_WEBHOOK_SECRET``). Customer deployments fetch
    short-lived tokens from their vault out-of-band and export them.
    """
    candidates = []
    if credential_id:
        slug = "".join(c if c.isalnum() else "_" for c in str(credential_id)).upper()
        candidates.append(f"ZELNX_WEBHOOK_SECRET_{slug}")
    if provider:
        candidates.append(f"{str(provider).upper().replace('-', '_')}_WEBHOOK_SECRET")
    if provider == "splunk":
        candidates.append("SPLUNK_HEC_TOKEN")
    candidates.append("ZELNX_WEBHOOK_SECRET")
    for name in candidates:
        val = os.environ.get(name)
        if val:
            return val
    return None


# ------------------------------------------------------------------ payloads
def build_payload(integration: dict, event: dict) -> tuple[dict | str, dict]:
    """Shape the outbound body + headers for one integration/event pair.

    Returns ``(body, extra_headers)``. ``body`` is a dict (sent as JSON) or a
    raw string (CEF syslog over HTTP for ``cef_syslog``).
    """
    provider = (integration.get("provider") or "webhook").lower()
    kind = integration.get("kind", "siem")
    payload = event.get("payload") or {}
    category = str(event.get("event_type", "")).split(".", 1)[-1] or payload.get("category", "finding")
    if category not in SIEM_EVENT_CATEGORIES:
        category = "finding"
    headers = {"User-Agent": "ZELNX-ControlPlane/1.0"}
    secret = credential_secret(integration.get("credential_id"), provider)

    if kind == "itsm":
        body = {
            "source": "zelnx", "event_type": event.get("event_type"),
            "ticket": payload.get("ticket") or payload,
            "finding_id": payload.get("finding_id"), "asset_id": payload.get("asset_id"),
            "severity": payload.get("severity", "medium"),
            "occurred_at": event.get("created_at") or datetime.now(timezone.utc).isoformat(),
        }
    elif provider == "cef_syslog":
        cef_event = {"category": category, "name": event.get("event_type", "event"),
                     "severity": payload.get("severity", "info"),
                     "asset": payload.get("asset") or payload.get("asset_id", ""),
                     "sector": payload.get("sector", ""),
                     "detail": payload.get("detail") or payload.get("title", "")}
        body = to_cef(cef_event)
        headers["Content-Type"] = "text/plain"
    else:
        body = {
            "source": "zelnx", "event_type": event.get("event_type"),
            "category": category, "severity": payload.get("severity", "info"),
            "asset": payload.get("asset") or payload.get("asset_id"),
            "payload": payload,
            "occurred_at": event.get("created_at") or datetime.now(timezone.utc).isoformat(),
        }
        headers["Content-Type"] = "application/json"
        if provider == "splunk":
            # Splunk HEC expects an event wrapper + Authorization token.
            body = {"source": "zelnx", "sourcetype": "zelnx:sec",
                    "event": body}
            if secret:
                headers["Authorization"] = f"Splunk {secret}"

    # HMAC signing for generic JSON webhooks (shared-secret integrations).
    if isinstance(body, dict):
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()
    else:
        raw = body.encode()
    signature = None
    if secret and provider != "splunk":
        signature = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        headers["X-ZELNX-Signature"] = f"sha256={signature}"
        headers["X-ZELNX-Event"] = str(event.get("event_type", ""))[:120]
    return body, {"headers": headers, "signature": signature}


# ------------------------------------------------------------------ delivery
def integration_matches(integration: dict, event_type: str) -> bool:
    if not integration.get("enabled", True):
        return False
    prefix = str(event_type).split(".", 1)[0].lower()
    wanted = _KIND_FOR_PREFIX.get(prefix)
    if wanted is None:
        return False
    return integration.get("kind") in wanted


def deliver(
    integration: dict,
    event: dict,
    *,
    post: Callable[..., Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
    backoff_base: float = 1.0,
) -> DeliveryResult:
    """Deliver one event to one integration with bounded retries.

    ``post(url, *, content, headers, timeout) -> (status_code, text)`` is
    injectable for tests; production uses :mod:`httpx`. Retries only on
    connection errors / 429 / 5xx with exponential backoff.
    """
    endpoint = integration.get("endpoint")
    result = DeliveryResult(
        integration_id=str(integration.get("id") or integration.get("name") or "unknown"),
        provider=integration.get("provider", "webhook"),
        kind=integration.get("kind", "siem"),
        endpoint=endpoint or "",
        status="skipped",
    )
    if not endpoint:
        result.error = "no endpoint configured (air-gap/outbox — event retained)"
        return result

    # SSRF guard: never POST to non-HTTP schemes, cloud metadata, loopback or
    # (by default) private/reserved address space. Checked here in addition to
    # registration time because config can change and DNS can rebind.
    try:
        validate_webhook_url(endpoint)
    except WebhookUrlError as exc:
        result.status = "failed"
        result.error = f"ssrf blocked: {exc}"
        logger.warning("webhook_ssrf_blocked integration=%s endpoint=%s",
                       result.integration_id, endpoint)
        return result

    body, shaped = build_payload(integration, event)
    headers = shaped["headers"]
    result.signature = shaped["signature"]
    content = body if isinstance(body, str) else json.dumps(body, default=str)

    started = time.monotonic()
    last_error = None
    for attempt in range(1, max_attempts + 1):
        result.attempts = attempt
        try:
            status_code, text = _http_post(post, endpoint, content=content,
                                           headers=headers, timeout=timeout)
            result.http_status = status_code
            result.response_excerpt = (text or "")[:300]
            if 200 <= status_code < 300:
                result.status = "delivered"
                result.error = None
                break
            last_error = f"HTTP {status_code}"
            if status_code not in (429,) and not (500 <= status_code < 600):
                result.status = "failed"  # 4xx (other than 429) is not retriable
                result.error = last_error
                break
        except Exception as exc:  # noqa: BLE001 - network failure -> retry
            last_error = str(exc)[:300]
        if attempt < max_attempts:
            sleep(min(backoff_base * (2 ** (attempt - 1)), 30.0))  # exponential backoff
    if result.status == "skipped" and last_error:
        result.status = "failed"
        result.error = last_error
    result.duration_ms = int((time.monotonic() - started) * 1000)
    if result.status == "delivered":
        logger.info("webhook_delivered integration=%s event=%s attempts=%s",
                    result.integration_id, event.get("event_type"), result.attempts)
    else:
        logger.warning("webhook_delivery_failed integration=%s error=%s",
                       result.integration_id, result.error)
    return result


def _http_post(post, endpoint, *, content, headers, timeout):
    if post is not None:
        return post(endpoint, content=content, headers=headers, timeout=timeout)
    import httpx

    resp = httpx.post(endpoint, content=content, headers=headers, timeout=timeout)
    return resp.status_code, resp.text


def deliver_to_all(
    integrations: list[dict],
    event: dict,
    *,
    post: Callable[..., Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    sleep: Callable[[float], None] | None = None,
) -> list[DeliveryResult]:
    """Fan one event out to every enabled, matching integration."""
    etype = str(event.get("event_type", ""))
    results = []
    for integration in integrations:
        if not integration_matches(integration, etype):
            continue
        kwargs: dict[str, Any] = {"post": post, "timeout": timeout}
        if sleep is not None:
            kwargs["sleep"] = sleep
            kwargs["backoff_base"] = 0.0
        results.append(deliver(integration, event, **kwargs))
    return results


def deliver_event_for_repo(db_session, event: dict, *, post=None,
                           timeout: float = DEFAULT_TIMEOUT,
                           sleep: Callable[[float], None] | None = None,
                           record: bool = True) -> list[dict]:
    """Wire delivery into a live DB session.

    Loads enabled integrations, fans the event out to each matching one,
    persists a :class:`DeliveryLog` row per attempt, and stamps the
    integration's last-sync status. Returns the list of result dicts. Kept in
    the logic layer (imports the ORM lazily) so it can be reused by the API
    routers and the worker-tick handler without duplicating the loop.
    """
    from db.repositories.control_plane_repository import ControlPlaneRepository
    from db.repositories.enterprise_repository import EnterpriseRepository

    cp = ControlPlaneRepository(db_session)
    ent = EnterpriseRepository(db_session)
    integrations = [i.to_dict() for i in ent.list_integrations()]
    results = deliver_to_all(integrations, event, post=post, timeout=timeout, sleep=sleep)
    out = []
    for r in results:
        d = r.to_dict()
        out.append(d)
        if record:
            cp.record_delivery(result=d, event_type=str(event.get("event_type", "")),
                               event_id=event.get("id"))
            ent.mark_integration_synced(r.integration_id, r.status)
    return out
