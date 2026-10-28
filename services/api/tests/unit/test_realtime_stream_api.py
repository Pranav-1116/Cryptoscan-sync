"""The channel stream over real ASGI: what the console subscribes to and what it may see.

The streams are driven without buffering (``ASGIStream``), because the failure this guards
against is subtle: a filtered subscriber whose channel is quiet must not receive another
estate's event, and a catalogue must not advertise a channel it cannot prove arrived.
"""
from __future__ import annotations

import pytest

from api.main import create_app
from api.events.bus import reset_event_bus
from test_events_stream import ASGIStream
from test_sse_estate_contract import event, headers
from test_software_supply_chain_api import banks as banks  # noqa: F401 — fixture


@pytest.fixture
def realtime_banks(banks, monkeypatch):  # noqa: F811 — fixture reuse
    clients, db, _ = banks
    bus = reset_event_bus()
    monkeypatch.setattr("api.routers.realtime.RECHECK_SECONDS", 0.04)
    yield clients, db, bus
    reset_event_bus()


def test_catalog_lists_channels_with_their_resource_and_honest_last_event(realtime_banks):
    clients, _, bus = realtime_banks
    bus.publish("estate.change.detected", {"channel": "estate", "kind": "change_detected"}, tenant_id="a")
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_a"].cookies)
        body = client.get("/api/v1/realtime/catalog")
    assert body.status_code == 200, body.text
    data = body.json()
    names = [row["channel"] for row in data["channels"]]
    assert "estate" in names and "remediation" in names
    for row in data["channels"]:
        assert row["resource"].startswith("/")
        assert row["kinds"], row["channel"]

    estate = next(row for row in data["channels"] if row["channel"] == "estate")
    assert estate["last_event"]["kind"] == "change_detected"
    # a channel nothing has published on says so, rather than claiming to be live
    findings = next(row for row in data["channels"] if row["channel"] == "findings")
    assert findings["last_event"] is None
    assert any("not a live one" in limit for limit in data["limits"])


def test_catalog_does_not_leak_another_estates_last_event(realtime_banks):
    clients, _, bus = realtime_banks
    bus.publish("estate.change.detected", {"channel": "estate", "kind": "change_detected"}, tenant_id="b")
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_a"].cookies)
        data = client.get("/api/v1/realtime/catalog").json()
    estate = next(row for row in data["channels"] if row["channel"] == "estate")
    assert estate["last_event"] is None, "bank_a was shown bank_b's realtime activity"


def test_unknown_channel_is_a_refusal_not_an_empty_stream(realtime_banks):
    clients, _, _ = realtime_banks
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_a"].cookies)
        missing = client.get("/api/v1/realtime/channels/nowhere")
    assert missing.status_code == 404
    assert missing.json()["detail"]["error"] == "unknown_channel"


@pytest.mark.asyncio
async def test_stream_carries_only_the_requested_channel(realtime_banks):
    clients, _, bus = realtime_banks
    app = create_app()
    async with ASGIStream(
        app, "/api/v1/realtime/stream", params={"channels": "findings"},
        headers=headers(clients["bank_a"]),
    ) as stream:
        assert stream.status == 200
        lines = stream.lines()
        assert (await event(lines, "realtime.ready"))["channels"] == ["findings"]
        # an estate change on the same bus is not this subscriber's business
        bus.publish("estate.change.detected", {"channel": "estate", "kind": "change_detected"}, tenant_id="a")
        bus.publish("findings.status_changed", {"channel": "findings", "kind": "status_changed"}, tenant_id="a")
        delivered = await event(lines, "findings.status_changed")
        assert delivered["payload"]["kind"] == "status_changed"
    assert bus.subscriber_count() == 0, "a closed stream must not leave a subscription behind"


def test_stream_refuses_a_channel_it_does_not_know(realtime_banks):
    clients, _, _ = realtime_banks
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as client:
        client.cookies.update(clients["bank_a"].cookies)
        response = client.get("/api/v1/realtime/stream", params={"channels": "estate,nowhere"})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "bad_channel"
