"""Real loopback read-only HTTP, throttling/scope/redirect counter contracts."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import json
import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
import operator_http_workload as workload  # noqa: E402


@contextmanager
def server(status=200, estate="a"):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.command, self.path, self.headers.get("X-Tenant-ID")))
            self.send_response(status)
            if status == 302:
                self.send_header("Location", "/must-not-be-followed")
            self.end_headers()
            self.wfile.write(json.dumps({"estate_id": estate, "sections": {}}).encode())
        def log_message(self, *args):
            pass
    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True); thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}", requests
    finally:
        http.shutdown(); http.server_close(); thread.join()


@pytest.mark.parametrize("status,estate", [(200, "a"), (200, "b"), (429, "a"), (302, "a")])
def test_workload_records_transport_failures_without_mutating_or_forwarding(status, estate):
    with server(status, estate) as (base, requests):
        report = workload.run(base, "a", "synthetic-test-token", .11, 1)
    assert requests and all(method == "GET" and "operator-decisions" in path and owner == "a" for method, path, owner in requests)
    assert (report["failed_or_throttled"] == 0) == (status == 200 and estate == "a")
    assert report["scope_mismatches"] > 0 if estate == "b" else report["scope_mismatches"] == 0
    assert report["http_throttled"] > 0 if status == 429 else report["http_throttled"] == 0
    assert "synthetic-test-token" not in str(report)
    assert report["capacity_qualified"] is False
