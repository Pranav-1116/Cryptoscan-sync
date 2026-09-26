"""SSE stream endpoint: auth gate, backlog + live delivery, recent fallback.

Streaming is proven by driving the ASGI app directly and asserting that body
chunks arrive WHILE the response is still open — httpx's ASGITransport buffers
whole responses, so a plain client test would prove nothing about streaming.
Non-streaming endpoints use AsyncClient as usual.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import urllib.parse

import pytest
from httpx import ASGITransport, AsyncClient

from api import dependencies
from api.events.bus import reset_event_bus
from api.main import create_app

pytestmark = pytest.mark.asyncio


@pytest.fixture()
def app():
    application = create_app()
    application.dependency_overrides[dependencies.get_current_user] = lambda: "tester"
    return application


@pytest.fixture()
def bus():
    return reset_event_bus()


@pytest.fixture()
def plain_client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class ASGIStream:
    """Consume an ASGI app's response incrementally, as a server would."""

    def __init__(self, app, path: str, params: dict | None = None):
        self._app, self._path, self._params = app, path, params or {}
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self._queue: asyncio.Queue = asyncio.Queue()
        self._started = asyncio.Event()
        self._task = None

    async def __aenter__(self):
        query = urllib.parse.urlencode(self._params).encode()
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": "GET", "scheme": "http", "path": self._path,
            "raw_path": self._path.encode(), "query_string": query, "root_path": "",
            "headers": [(b"host", b"test")], "client": ("testclient", 123),
            "server": ("test", 80),
        }

        requested = False

        async def receive():
            nonlocal requested
            if not requested:
                requested = True
                return {"type": "http.request", "body": b"", "more_body": False}
            # healthy open connection: no further messages; a blocking receive
            # is exactly the "still connected" signal is_disconnected probes for
            await asyncio.Event().wait()

        async def send(message):
            if message["type"] == "http.response.start":
                self.status = message["status"]
                self.headers = {
                    k.decode().lower(): v.decode() for k, v in message["headers"]
                }
                self._started.set()
            elif message["type"] == "http.response.body":
                await self._queue.put(message.get("body", b""))

        async def run():
            try:
                await self._app(scope, receive, send)
            finally:
                await self._queue.put(None)  # sentinel: response finished

        self._task = asyncio.create_task(run())
        while not self._started.is_set() and not self._task.done():
            await asyncio.sleep(0)
        return self

    async def lines(self):
        buf = b""
        while True:
            item = await self._queue.get()
            if item is None:
                break
            buf += item
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                yield line.decode()
        if buf:
            yield buf.decode()

    async def __aexit__(self, *exc):
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        return False


async def test_stream_requires_auth(app, plain_client):
    app.dependency_overrides.pop(dependencies.get_current_user, None)
    resp = await plain_client.get("/api/v1/events/stream")
    assert resp.status_code == 401
    await plain_client.aclose()


async def test_stream_headers_and_backlog(app, bus):
    bus.publish("t.backlog", {"n": 1}, source="test")
    async with ASGIStream(app, "/api/v1/events/stream") as stream:
        assert stream.status == 200
        assert stream.headers["content-type"].startswith("text/event-stream")
        assert stream.headers["cache-control"] == "no-cache, no-transform"
        seen = False
        async for line in stream.lines():
            if line.startswith("event: t.backlog"):
                seen = True
                break
        assert seen  # delivered while the response was still open


async def test_stream_delivers_live_events(app, bus):
    async with ASGIStream(app, "/api/v1/events/stream") as stream:
        # publish while the stream is open — must arrive without reconnect
        bus.publish("t.live", {"tick": 42}, source="test")
        got = None
        async for line in stream.lines():
            if line.startswith("data: ") and '"t.live"' in line:
                got = json.loads(line[len("data: "):])
                break
        assert got is not None
        assert got["payload"] == {"tick": 42}
        assert got["type"] == "t.live"


async def test_stream_resumes_from_last_event_id(app, bus):
    first = bus.publish("t.keep", {"n": 1}, source="test")
    bus.publish("t.skip", {"n": 2}, source="test")
    async with ASGIStream(
        app, "/api/v1/events/stream", params={"last_event_id": first["id"]}
    ) as stream:
        types: list[str] = []
        async for line in stream.lines():
            if line.startswith("event: "):
                types.append(line[len("event: "):])
            if len(types) >= 2:
                break
        assert "t.skip" in types
        assert "t.keep" not in types


async def test_recent_endpoint_reports_history(plain_client, bus):
    bus.publish("t.one", {}, source="test")
    bus.publish("t.two", {}, source="test")
    body = (await plain_client.get("/api/v1/events/recent")).json()
    types = [e["type"] for e in body["events"]]
    assert "t.one" in types and "t.two" in types
    assert body["latest_id"] >= 2
    since = (
        await plain_client.get("/api/v1/events/recent", params={"since_id": body["latest_id"] - 1})
    ).json()
    assert [e["type"] for e in since["events"]] == [types[-1]]
    await plain_client.aclose()


async def test_stats_endpoint(plain_client, bus):
    body = (await plain_client.get("/api/v1/events/stats")).json()
    assert {"events_buffered", "subscribers", "latest_id", "tailer_running"} <= set(body)
    await plain_client.aclose()


# ------------------------------------------------------- telecom tailer

def test_telecom_tailer_drain_seeds_then_publishes():
    """First observation after boot seeds history without publishing; a NEW
    event publishes with the exact key contract the API's direct publisher
    registers (one event, one delivery across processes)."""
    from api.routers.events import _drain_telecom_events
    from api.routers.telecom import _event_key

    ev = {"kind": "TELECOM_REACHABILITY_LOST", "severity": "critical",
          "target": "sepp-01", "nf_type": "sepp", "carrier_code": "dt",
          "message": "gone", "at": "2026-09-12T12:00:00+00:00",
          "fingerprint": "UNREACHABLE|connect.refused|-"}
    seen: set[str] = set()
    published: list[dict] = []

    # seed pass (tailer's first read after boot): history learned, nothing published
    assert _drain_telecom_events(seen, lambda e: published.append(e),
                                 {"events": [ev]}, seed_only=True) == 0
    assert published == []
    assert _event_key(ev) in seen  # same key both sides compute

    # the same event arriving again (e.g. via the direct-publisher filter
    # failing) is NOT re-published
    assert _drain_telecom_events(seen, lambda e: published.append(e), {"events": [ev]}) == 0

    # a genuinely new event publishes
    new_ev = {**ev, "kind": "TELECOM_RECOVERED", "severity": "info",
              "at": "2026-09-12T12:05:00+00:00",
              "fingerprint": "TLS_OK|-"}
    assert _drain_telecom_events(seen, lambda e: published.append(e),
                                 {"events": [ev, new_ev]}) == 1
    assert [e["kind"] for e in published] == ["TELECOM_RECOVERED"]


def test_telecom_tailer_drain_empty_and_none_snapshots():
    from api.routers.events import _drain_telecom_events

    published: list[dict] = []
    seen: set[str] = set()
    assert _drain_telecom_events(seen, lambda e: published.append(e), None) == 0
    assert _drain_telecom_events(seen, lambda e: published.append(e), {}) == 0
    assert _drain_telecom_events(seen, lambda e: published.append(e), {"events": []}) == 0
    assert published == [] and seen == set()


def test_telecom_tailer_payload_carries_full_identity():
    """The tailer's bus payload keeps plane/endpoint so automation rules can
    target e.g. plane == roaming — not just nf/kind/severity."""
    from api.routers.events import _telecom_event_payload

    payload = _telecom_event_payload({
        "kind": "TELECOM_PQC_DROPPED", "severity": "high",
        "target": "gw-za-01", "nf_type": "sepp", "carrier_code": "de-telekom",
        "plane": "roaming", "endpoint": "za.lab:500",
        "message": "PQC regression", "at": "2026-09-13T05:00:00+00:00",
        "fingerprint": "TLS_OK|pqc.lost|-",
    })
    assert payload["nf_id"] == "gw-za-01"
    assert payload["plane"] == "roaming"
    assert payload["endpoint"] == "za.lab:500"
    assert payload["origin"] == "snapshot-tailer"
    assert payload["kind"] == "TELECOM_PQC_DROPPED"
    # automation maps it using the SAME payload the bus carries
    from telecom_scanner.automation import automation_event_kind
    assert automation_event_kind(payload) == "quantum_vulnerable_detected"
