"""POST /network/alerts/dispatch escalates + routes expiry alerts."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import hashlib
import hmac
import http.server
import json
import threading

import pytest
from httpx import ASGITransport, AsyncClient

from api.dependencies import get_current_user
from api.main import create_app


class WebhookReceiver:
    def __init__(self):
        self.captures = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 — http.server API
                length = int(self.headers.get("Content-Length") or 0)
                outer.captures.append(
                    {"headers": dict(self.headers.items()), "body": self.rfile.read(length)}
                )
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.server.timeout = 0.05
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                self.server.handle_request()
            except OSError:
                return
            except Exception as _handler_exc:  # noqa: BLE001
                logger.debug(
                    "expected_exception_boundary",
                    extra={"error_type": type(_handler_exc).__name__},
                )
                continue

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}/hook"

    def close(self):
        self.server.server_close()


@pytest.mark.asyncio
async def test_alert_dispatch_endpoint(monkeypatch):
    receiver = WebhookReceiver()
    try:
        monkeypatch.setenv("CRYPTOSCAN_ALERT_WEBHOOK_URL", receiver.url)
        monkeypatch.setenv("CRYPTOSCAN_ALERT_WEBHOOK_SECRET", "whsec")
        app = create_app()
        app.dependency_overrides[get_current_user] = lambda: "testuser"
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/network/alerts/dispatch",
                json={
                    "certificates": [
                        {"subject": "expired.example", "fingerprint_sha256": "fpA",
                         "days_until_expiry": -2, "usages": ["expired.example:443"]},
                        {"subject": "soon.example", "fingerprint_sha256": "fpB",
                         "days_until_expiry": 6, "usages": ["soon.example:443"]},
                    ],
                    "notification_state": {},
                    "days": 30,
                },
            )
        assert response.status_code == 200
        payload = response.json()
        assert payload["escalated"] == 2
        assert payload["severity_counts"]["CRITICAL"] == 1
        assert payload["severity_counts"]["HIGH"] == 1
        # state comes back for the caller to persist
        assert set(payload["notification_state"]) == {"fpA", "fpB"}
        channels = {channel["channel"]: channel for channel in payload["channels"]}
        assert channels["webhook"]["status"] == "DELIVERED"
        # the batch is signed and the expired cert headlines it
        capture = receiver.captures[0]
        expected = hmac.new(b"whsec", capture["body"], hashlib.sha256).hexdigest()
        assert capture["headers"]["X-Cryptoscan-Signature"] == expected
        events = json.loads(capture["body"])["events"]
        assert events[0]["type"] == "CERTIFICATE_EXPIRED"
    finally:
        receiver.close()


@pytest.mark.asyncio
async def test_alert_dispatch_without_webhook_is_log_only(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_ALERT_WEBHOOK_URL", raising=False)
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/network/alerts/dispatch",
            json={"certificates": [
                {"subject": "s", "fingerprint_sha256": "f", "days_until_expiry": 3}
            ]},
        )
    assert response.status_code == 200
    payload = response.json()
    assert [channel["channel"] for channel in payload["channels"]] == ["log"]
    assert payload["severity_counts"]["CRITICAL"] == 1
