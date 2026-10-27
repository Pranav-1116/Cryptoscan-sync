"""Stripe gateway — real PSP integration over the tenant plan model.

Design (honest-outputs doctrine):
- When ``STRIPE_API_KEY`` is absent the gateway reports ``configured=False``
  and every entry point returns a clean "billing not configured" state — the
  product never fakes a subscription.
- Checkout Sessions are created against the real Stripe API
  (``POST /v1/checkout/sessions``, form-encoded, Idempotency-Key header).
- Webhooks are verified with Stripe's documented scheme
  (``Stripe-Signature: t=…,v1=…``, HMAC-SHA256 over ``"{t}.{payload}"``,
  constant-time compare, replay window enforced).
- Subscription state lands in the platform's key-value settings store —
  no schema change, fully replayable, auditable via ``updated_by``.

Prices are referenced by Stripe Price IDs (env: ``STRIPE_PRICE_FREE``,
``STRIPE_PRICE_PRO``, ``STRIPE_PRICE_ENTERPRISE``) — the platform never
invents amounts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any
from urllib.parse import urlencode

import httpx

API_BASE = "https://api.stripe.com/v1"
WEBHOOK_TOLERANCE_SECONDS = 300

# tenant plan -> Stripe price env var + lookup key fallback
PLAN_PRICE_ENV = {
    "FREE": "STRIPE_PRICE_FREE",
    "PRO": "STRIPE_PRICE_PRO",
    "ENTERPRISE": "STRIPE_PRICE_ENTERPRISE",
}


class StripeError(RuntimeError):
    """Raised on non-2xx Stripe API responses (message from Stripe kept)."""


def secret_key() -> str | None:
    value = os.environ.get("STRIPE_API_KEY", "").strip()
    return value or None


def webhook_secret() -> str | None:
    value = os.environ.get("STRIPE_WEBHOOK_SECRET", "").strip()
    return value or None


def configured() -> bool:
    return secret_key() is not None


# ---------------------------------------------------------------------------
# checkout sessions
# ---------------------------------------------------------------------------
def create_checkout_session(*, plan: str, tenant_id: str, tenant_name: str,
                            success_url: str, cancel_url: str,
                            api_key: str | None = None,
                            transport: httpx.BaseTransport | None = None,
                            now: float | None = None) -> dict[str, Any]:
    """Create a Stripe Checkout Session for a plan upgrade.

    Returns the raw session dict (contains ``url`` to redirect the customer
    to, ``id`` for audit). Raises StripeError on API failure and ValueError
    when the plan has no configured price.
    """
    key = api_key or secret_key()
    if not key:
        raise StripeError("billing_not_configured")
    price_env = PLAN_PRICE_ENV.get((plan or "").upper())
    price_id = os.environ.get(price_env, "").strip() if price_env else ""
    if not price_id:
        raise ValueError(f"no Stripe price configured for plan '{plan}' "
                         f"(set {price_env})")

    form = {
        "mode": "subscription",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": tenant_id,
        "customer_email": "",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "metadata[tenant_id]": tenant_id,
        "metadata[tenant_name]": tenant_name,
        "metadata[plan]": plan.upper(),
        "subscription_data[metadata][tenant_id]": tenant_id,
        "subscription_data[metadata][plan]": plan.upper(),
    }
    form.pop("customer_email")
    idem = "cs-" + hashlib.sha256(
        f"{tenant_id}:{plan}:{int(now or time.time()) // 600}".encode()
    ).hexdigest()  # stable per tenant+plan per 10-min bucket
    with httpx.Client(transport=transport, timeout=20.0) as client:
        response = client.post(
            f"{API_BASE}/checkout/sessions",
            content=urlencode(form),
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Idempotency-Key": idem,
                "Stripe-Version": "2024-06-20",
            },
        )
    if response.status_code >= 300:
        raise StripeError(f"stripe_{response.status_code}: {response.text[:300]}")
    return response.json()


# ---------------------------------------------------------------------------
# webhook verification (Stripe's documented signature scheme)
# ---------------------------------------------------------------------------
def sign_webhook_payload(payload: bytes, secret: str, *, timestamp: int | None = None) -> str:
    """Produce a Stripe-Signature header for ``payload`` (test/dev utility and
    the reference implementation of the verify side)."""
    t = timestamp if timestamp is not None else int(time.time())
    signed = f"{t}.".encode() + payload
    v1 = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={t},v1={v1}"


def verify_webhook(payload: bytes, header: str, secret: str | None = None,
                   *, now: float | None = None) -> dict[str, Any]:
    """Verify a Stripe webhook request and return the parsed event.

    Scheme (docs.stripe.com/webhooks#verify-official-libraries):
      signed_payload = "{t}.{raw_body}"; expected v1 = HMAC-SHA256(secret).
    Raises ValueError on missing/malformed header, bad signature, stale
    timestamp (replay window) — the caller maps that to HTTP 400.
    """
    secret = secret or webhook_secret()
    if not secret:
        raise ValueError("webhook secret not configured")
    try:
        parts = dict(
            item.split("=", 1) for item in header.split(",") if "=" in item
        )
        t = int(parts["t"].strip())
        v1 = parts["v1"].strip()
    except (KeyError, ValueError) as exc:
        raise ValueError("malformed Stripe-Signature header") from exc

    if abs((now if now is not None else time.time()) - t) > WEBHOOK_TOLERANCE_SECONDS:
        raise ValueError("webhook timestamp outside tolerance (replay?)")

    signed = f"{t}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise ValueError("webhook signature mismatch")
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("webhook payload is not JSON") from exc


# ---------------------------------------------------------------------------
# event -> subscription state
# ---------------------------------------------------------------------------
def subscription_state_from_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """Map a verified Stripe event to the tenant subscription state to store.

    Returns None for events we deliberately ignore. The state is the single
    source the status endpoint reads: {status, plan, customer, subscription,
    updated_at_epoch, last_event}.
    """
    kind = event.get("type") or ""
    obj = (event.get("data") or {}).get("object") or {}
    metadata = obj.get("metadata") or {}
    tenant_id = metadata.get("tenant_id") or obj.get("client_reference_id")
    if not tenant_id:
        return None  # not a platform-tenant subscription event
    if kind == "checkout.session.completed":
        return {
            "tenant_id": tenant_id,
            "status": "active",
            "plan": (metadata.get("plan") or obj.get("metadata", {}).get("plan") or "").upper() or None,
            "customer": obj.get("customer"),
            "subscription": obj.get("subscription"),
            "last_event": kind,
        }
    if kind == "invoice.payment_failed":
        return {
            "tenant_id": tenant_id,
            "status": "past_due",
            "last_event": kind,
        }
    if kind == "customer.subscription.deleted":
        return {
            "tenant_id": tenant_id,
            "status": "canceled",
            "subscription": obj.get("id"),
            "last_event": kind,
        }
    return None


