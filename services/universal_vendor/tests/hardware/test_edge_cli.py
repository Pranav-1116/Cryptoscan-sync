"""§21 edge agent CLI: ingest → durable queue, sync → control-plane flush."""

from __future__ import annotations

import json

import pytest

from universal_vendor.hardware.live.edge_cli import main
from universal_vendor.hardware.live.events import HardwareEventType


def _event_json(tmp_path) -> str:
    path = tmp_path / "event.json"
    path.write_text(json.dumps({
        "event_type": HardwareEventType.HARDWARE_DISCOVERED.value,
        "asset_id": "srv-1",
        "manufacturer": "Dell",
        "model": "R760",
        "device_type": "server",
    }))
    return str(path)


def test_ingest_writes_durable_queue_and_evidence(tmp_path):
    q = str(tmp_path / "queue")
    assert main(["--agent-id", "edge-a", "--queue-dir", q,
                 "ingest", _event_json(tmp_path)]) == 0
    lines = (tmp_path / "queue" / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["asset_id"] == "srv-1"
    evidence = (tmp_path / "queue" / "evidence.jsonl").read_text().strip().splitlines()
    assert len(evidence) == 1


def test_status_reports_queue_depth_and_evidence(tmp_path, capsys):
    q = str(tmp_path / "queue")
    main(["--agent-id", "edge-a", "--queue-dir", q, "ingest", _event_json(tmp_path)])
    capsys.readouterr()  # discard ingest output
    main(["--agent-id", "edge-a", "--queue-dir", q, "status"])
    out = json.loads(capsys.readouterr().out)
    assert out["agent_id"] == "edge-a"
    assert out["queue_depth"] == 1
    assert out["evidence_records"] == 1


def test_sync_flushes_queue_after_2xx_ack(tmp_path):
    q = str(tmp_path / "queue")
    main(["--agent-id", "edge-a", "--queue-dir", q, "ingest", _event_json(tmp_path)])

    from http.server import BaseHTTPRequestHandler, HTTPServer

    received: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"accepted": true}')

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        assert main(["--agent-id", "edge-a", "--queue-dir", q, "sync",
                     "--url", f"http://127.0.0.1:{port}/api/v1/hardware/edge/sync"]) == 0
    finally:
        server.shutdown()
    assert len(received) == 1
    assert received[0]["agent_id"] == "edge-a"
    assert received[0]["events"][0]["asset_id"] == "srv-1"
    # queue drained only after the ACK
    assert (tmp_path / "queue" / "events.jsonl").read_text().strip() == ""


def test_sync_fails_and_keeps_queue_when_control_plane_rejects(tmp_path):
    q = str(tmp_path / "queue")
    main(["--agent-id", "edge-a", "--queue-dir", q, "ingest", _event_json(tmp_path)])

    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Rejecting(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            self.send_response(500)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Rejecting)
    port = server.server_address[1]
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        rc = main(["--agent-id", "edge-a", "--queue-dir", q, "sync",
                   "--url", f"http://127.0.0.1:{port}/sync"])
    finally:
        server.shutdown()
    assert rc == 1
    # event survived the rejected sync — durable queue intact
    lines = (tmp_path / "queue" / "events.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1


def test_ingest_from_stdin(tmp_path):
    import io
    import sys
    q = str(tmp_path / "queue")
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(json.dumps({"event_type": "HARDWARE_CHANGED",
                                        "asset_id": "srv-9"}))
    try:
        assert main(["--agent-id", "edge-b", "--queue-dir", q, "ingest", "-"]) == 0
    finally:
        sys.stdin = old_stdin
    lines = (tmp_path / "queue" / "events.jsonl").read_text().strip().splitlines()
    assert json.loads(lines[0])["asset_id"] == "srv-9"
