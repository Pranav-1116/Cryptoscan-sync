"""Runtime adapter tests: real urllib I/O against a localhost HTTP server, and
lazy SDK guards for Kafka/Rabbit. Deterministic; no external network."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from devsecops import runtime_adapters as rt


class _Handler(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *a):  # silence
        pass

    def _read(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_POST(self):  # noqa: N802
        body = self._read()
        type(self).received.append({"method": "POST", "path": self.path,
                                    "headers": dict(self.headers), "body": body})
        if "/fail" in self.path:
            self.send_response(503); self.end_headers(); self.wfile.write(b"busy"); return
        payload = json.dumps({"code": 0, "ackId": 7}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        body = self._read()
        type(self).received.append({"method": "GET", "path": self.path,
                                    "headers": dict(self.headers), "body": body})
        payload = json.dumps({"result": [{"sys_id": "x1", "correlation_id": "cs-abc"}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.end_headers(); self.wfile.write(payload)


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def test_urllib_post_returns_http_result(server):
    _Handler.received.clear()
    post = rt.urllib_post()
    res = post(server + "/services/collector", content=b'{"a":1}',
               headers={"Authorization": "Splunk t", "Content-Type": "application/json"})
    assert res.ok and res.status == 200
    assert json.loads(res.body)["ackId"] == 7
    assert _Handler.received[0]["headers"]["Authorization"] == "Splunk t"


def test_urllib_post_http_error_not_raised(server):
    post = rt.urllib_post()
    res = post(server + "/fail", content=b"x", headers={})
    assert res.ok is False and res.status == 503 and "busy" in res.body


def test_urllib_get_for_ticket_sync(server):
    _Handler.received.clear()
    get = rt.urllib_get()
    res = get(server + "/api/now/table/incident", headers={"Authorization": "Basic x"})
    assert res.ok
    rows = json.loads(res.body)["result"]
    assert rows[0]["sys_id"] == "x1"
    assert _Handler.received[0]["method"] == "GET"


def test_urllib_get_connection_error_fails_closed():
    get = rt.urllib_get(timeout=1.0)
    # nothing listening on this port
    res = get("http://127.0.0.1:1/incident", headers={})
    assert res.ok is False and res.status is None and res.error


def test_servicenow_transport_adds_auth(server):
    _Handler.received.clear()
    t = rt.servicenow_get_transport("x.service-now.com", "BASICTOKEN")
    res = t(server + "/incident")
    assert res.ok
    assert _Handler.received[0]["headers"]["Authorization"] == "Basic BASICTOKEN"


def test_kafka_adapter_guards_missing_sdk():
    # confluent_kafka is not installed in the test env; factory must raise clearly
    if rt.kafka_available():
        pytest.skip("confluent_kafka present; lazy-guard not exercised")
    with pytest.raises(RuntimeError, match="confluent_kafka"):
        rt.confluent_kafka_producer("localhost:9092")


def test_pika_adapter_guards_missing_sdk():
    if rt.rabbit_available():
        pytest.skip("pika present; lazy-guard not exercised")
    with pytest.raises(RuntimeError, match="pika"):
        rt.pika_publisher("amqp://guest:guest@localhost:5672/")


def test_adapter_status_reports_http_always():
    st = rt.adapter_status()
    assert st["http"] is True
    assert isinstance(st["kafka"], bool) and isinstance(st["rabbitmq"], bool)
