"""Production-source realtime regression coverage.

These tests exercise the real HTTP/file connector implementations. They do not
inject events into a production monitor or assert a default-success response;
the local HTTP server is only the test's operator-configured source.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from universal_vendor.live.connectors import HttpVendorConnector, JsonLinesEventConnector
from universal_vendor.live.events import EventGateway, EventType, UniversalVendorEvent
from universal_vendor.live.monitoring import LiveVendorMonitor
from universal_vendor.live.vendor_monitors import CiscoLiveMonitor


class _ApiHandler(BaseHTTPRequestHandler):
    payload = {
        "version": "17.9.4",
        "tls": {"protocols": ["TLSv1.3"], "ciphers": ["AES-256-GCM"]},
        "private_key": "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----",
    }

    def do_GET(self):  # noqa: N802 - stdlib handler API
        body = json.dumps(self.payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def api_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/crypto"
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_no_source_is_explicitly_unavailable(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_LIVE_VENDOR_ENDPOINTS", raising=False)
    monkeypatch.delenv("CRYPTOSCAN_LIVE_VENDOR_ENDPOINT", raising=False)
    monitor = LiveVendorMonitor.from_environment(tenant_id="tenant-a")
    assert monitor.status()["status"] == "UNAVAILABLE"
    assert monitor.collect() == []


def test_http_source_is_real_evidence_and_incremental(api_server):
    connector = HttpVendorConnector(
        endpoint=api_server,
        vendor="Cisco",
        product="IOS-XE",
        asset_id="router-1",
        tenant_id="tenant-a",
    )
    events = connector.collect()
    assert len(events) == 1
    assert events[0].event_type == EventType.ASSET_DISCOVERED
    assert events[0].tenant_id == "tenant-a"
    assert events[0].evidence_reference.startswith("sha256:")
    assert events[0].vendor_metadata["artifact"]["private_key"] == "<redacted>"
    assert "BEGIN PRIVATE KEY" not in json.dumps(events[0].vendor_metadata)
    assert connector.collect() == []


def test_json_lines_stream_is_tenant_scoped_and_incremental(tmp_path: Path):
    path = tmp_path / "vendor-events.jsonl"
    path.write_text(json.dumps({
        "vendor": "Cisco", "product": "IOS-XE", "asset_id": "router-1",
        "event_type": "CONFIG_CHANGED", "config": "ipsec aes-gcm",
    }) + "\n")
    connector = JsonLinesEventConnector(
        path=str(path), vendor="Cisco", product="IOS-XE", asset_id="router-1",
        tenant_id="tenant-a",
    )
    event = connector.collect()[0]
    assert event.event_type == EventType.CONFIG_CHANGED
    assert event.tenant_id == "tenant-a"
    assert connector.collect() == []


def test_gateway_rejects_cross_tenant_event():
    gateway = EventGateway(tenant_id="tenant-a")
    with pytest.raises(PermissionError):
        gateway.ingest(UniversalVendorEvent(
            vendor="Cisco", product="IOS-XE", asset_id="router-2",
            tenant_id="tenant-b",
        ))


def test_injected_vendor_events_are_test_only(monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    with pytest.raises(RuntimeError, match="test-only"):
        CiscoLiveMonitor(asset_id="router-1", events=[{"domain": "tls"}])
