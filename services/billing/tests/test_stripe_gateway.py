"""Stripe gateway: signature scheme, event mapping, checkout session shape.

The webhook verification tests exercise the REAL HMAC scheme (Stripe's
documented ``t=…,v1=…`` over ``"{t}.{payload}"``) — no Stripe SDK, no network.
Checkout uses httpx.MockTransport to pin the exact request the gateway makes
against the production API endpoint.
"""

from __future__ import annotations

import json

import httpx
import pytest

from billing.stripe_gateway import (
    StripeError,
    create_checkout_session,
    sign_webhook_payload,
    subscription_state_from_event,
    verify_webhook,
)

SECRET = "whsec_test_secret_0123456789abcdef"


def test_signature_roundtrip_and_tamper():
    payload = json.dumps({"id": "evt_1", "type": "checkout.session.completed",
                          "data": {"object": {"metadata": {"tenant_id": "t1"}}}}).encode()
    header = sign_webhook_payload(payload, SECRET, timestamp=1_700_000_000)
    # verify with the exact timestamp (no replay skew)
    event = verify_webhook(payload, header, SECRET, now=1_700_000_000.0)
    assert event["id"] == "evt_1"

    # tampered payload -> mismatch
    with pytest.raises(ValueError, match="signature mismatch"):
        verify_webhook(payload + b" ", header, SECRET, now=1_700_000_000.0)

    # tampered signature -> mismatch
    bad = header[:-2] + ("00" if not header.endswith("00") else "11")
    with pytest.raises(ValueError, match="signature mismatch"):
        verify_webhook(payload, bad, SECRET, now=1_700_000_000.0)

    # stale timestamp (outside 300s tolerance) -> replay refused
    with pytest.raises(ValueError, match="replay|tolerance"):
        verify_webhook(payload, header, SECRET, now=1_700_000_000.0 + 4_000)

    # malformed header -> refused
    with pytest.raises(ValueError, match="malformed"):
        verify_webhook(payload, "v1=abc", SECRET)


def test_event_mapping_checkout_and_failures():
    completed = {
        "type": "checkout.session.completed",
        "data": {"object": {
            "id": "cs_123", "customer": "cus_9", "subscription": "sub_7",
            "client_reference_id": "tenant-abc",
            "metadata": {"tenant_id": "tenant-abc", "plan": "PRO"},
        }},
    }
    state = subscription_state_from_event(completed)
    assert state == {
        "tenant_id": "tenant-abc", "status": "active", "plan": "PRO",
        "customer": "cus_9", "subscription": "sub_7",
        "last_event": "checkout.session.completed",
    }
    failed = {"type": "invoice.payment_failed",
              "data": {"object": {"metadata": {"tenant_id": "tenant-abc"}}}}
    assert subscription_state_from_event(failed)["status"] == "past_due"
    deleted = {"type": "customer.subscription.deleted",
               "data": {"object": {"id": "sub_7", "metadata": {"tenant_id": "t"}}}}
    assert subscription_state_from_event(deleted)["status"] == "canceled"
    # foreign event / no tenant -> deliberately ignored
    assert subscription_state_from_event(
        {"type": "ping", "data": {"object": {}}}) is None
    assert subscription_state_from_event(
        {"type": "checkout.session.completed", "data": {"object": {}}}) is None


def test_checkout_session_request_shape(monkeypatch):
    monkeypatch.setenv("STRIPE_PRICE_PRO", "price_test_123")
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("Authorization", "")
        captured["idem"] = request.headers.get("Idempotency-Key", "")
        captured["body"] = request.content.decode()
        return httpx.Response(200, json={"id": "cs_test_1", "url": "https://pay/stub"})

    transport = httpx.MockTransport(handler)
    session = create_checkout_session(
        plan="PRO", tenant_id="tenant-1", tenant_name="acme",
        success_url="https://app/ok", cancel_url="https://app/back",
        api_key="sk_test_xyz", transport=transport)
    assert session["id"] == "cs_test_1"
    assert captured["url"].startswith("https://api.stripe.com/v1/checkout/sessions")
    assert captured["auth"] == "Bearer sk_test_xyz"
    assert captured["idem"].startswith("cs-")
    assert "mode=subscription" in captured["body"]
    assert "client_reference_id=tenant-1" in captured["body"]
    assert "metadata%5Bplan%5D=PRO" in captured["body"]


def test_checkout_requires_price_config(tmp_path, monkeypatch):
    monkeypatch.delenv("STRIPE_PRICE_PRO", raising=False)
    with pytest.raises(ValueError, match="no Stripe price"):
        create_checkout_session(
            plan="PRO", tenant_id="t", tenant_name="t",
            success_url="https://x/y", cancel_url="https://x/z",
            api_key="sk_test", transport=httpx.MockTransport(
                lambda req: httpx.Response(500)))


def test_api_error_surfaces_as_stripe_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(402, json={"error": {"message": "card declined"}})

    import os
    os.environ["STRIPE_PRICE_PRO"] = "price_123"
    try:
        with pytest.raises(StripeError, match="stripe_402"):
            create_checkout_session(
                plan="PRO", tenant_id="t", tenant_name="t",
                success_url="https://x/y", cancel_url="https://x/z",
                api_key="sk_test", transport=httpx.MockTransport(handler))
    finally:
        os.environ.pop("STRIPE_PRICE_PRO", None)
