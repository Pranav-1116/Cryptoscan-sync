"""`cryptoscan capture` — submit signed bodies, read receipts, hold no keys.

The command group exists so a bank integrator can drive the capture path from
the same operator terminal as everything else. Four properties are pinned:

* the body is submitted EXACTLY as signed — the CLI neither signs nor edits it;
* a receipt is tenant-owned — no tenant, no read;
* the trust-anchor probe reports configuration shape only, never key material;
* `doctor` surfaces the capture trust anchor as its own honest row
  (OK / NOT_CONFIGURED), not a green tick for an absent capability.
"""

from __future__ import annotations

import json
import urllib.parse

import pytest

from api import cli_remote
from api.cli import main

BASE = "https://control-plane.bank.internal"


class FakeControlPlane:
    def __init__(self, routes: dict[tuple[str, str], tuple[int, object]] | None = None) -> None:
        self.routes = routes or {}
        self.calls: list[tuple[str, str, dict[str, str], bytes | None]] = []

    def __call__(self, method, url, headers, body, context, timeout):  # noqa: ANN001
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        self.calls.append((method, path + (f"?{parsed.query}" if parsed.query else ""),
                           dict(headers), body))
        for (want_method, want_path), (status, payload) in self.routes.items():
            if method == want_method and path == want_path:
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return cli_remote.Response(status, {"content-type": "application/json"}, data)
        return cli_remote.Response(404, {},
                                   json.dumps({"detail": "no such route in this fake"}).encode())


@pytest.fixture
def env(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    monkeypatch.setattr(cli_remote, "DEFAULT_CONFIG_PATH", config)
    monkeypatch.setenv("CRYPTOSCAN_SERVER", BASE)
    monkeypatch.setenv("CRYPTOSCAN_TOKEN", "session-token")
    monkeypatch.delenv("CRYPTOSCAN_API_KEY", raising=False)
    return {"config": config, "tmp": tmp_path}


def run(monkeypatch, transport: FakeControlPlane, *argv: str) -> int:
    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    return main(list(argv))


RECEIPT = {
    "receipt_id": "r-1", "outcome": "stored", "source_type": "node_exporter",
    "payload_sha256": "a" * 64, "provenance_state": "signed-capture",
    "signer": {"key_id": "bank-2026-q4", "issuer": "bank-collector-1"},
    "accepted": 3, "duplicate": 0, "rejected": 1, "metric_ids": ["m1"],
    "metric_ids_truncated": False, "refused": [], "refusals_truncated": False,
    "note": "raw snapshots stay under bank custody",
}


def test_capture_submit_posts_the_body_exactly_as_signed(tmp_path, monkeypatch, env, capsys):
    body = {"tenant_id": "tenant-a", "asset_ref": "app:svc-pay",
            "source_id": "node-1", "source_type": "node_exporter",
            "authorization_ref": "AUTH-77", "observed_at": "2026-10-16T12:00:00+00:00",
            "payload": {"metrics": {}}, "attestation": {"schema": "x", "signature": "s"}}
    path = tmp_path / "signed.json"
    path.write_text(json.dumps(body), encoding="utf-8")
    transport = FakeControlPlane(
        {("POST", "/api/v1/performance/captures/import"): (200, RECEIPT)})
    assert run(monkeypatch, transport, "capture", "submit", "--body", str(path)) == 0
    (method, request_path, _headers, sent), = transport.calls
    assert method == "POST" and request_path == "/api/v1/performance/captures/import"
    assert json.loads(sent) == body, "the CLI must submit the body exactly as signed"
    out = capsys.readouterr().out
    assert "r-1" in out and "signed-capture" in out
    assert "holds no key" in out


def test_capture_submit_refuses_a_body_it_cannot_read(tmp_path, monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "capture", "submit",
               "--body", str(tmp_path / "missing.json")) == 3
    assert transport.calls == [], "no request for a body the CLI cannot read"
    assert "REFUSED" in capsys.readouterr().err


def test_capture_receipt_is_tenant_owned_and_never_read_across_tenants(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/performance/captures/r-1"): (200, RECEIPT)})
    # no tenant anywhere -> refused before any request
    monkeypatch.delenv("CRYPTOSCAN_TENANT", raising=False)
    assert run(monkeypatch, transport, "capture", "receipt", "r-1") == 3
    assert transport.calls == []
    assert "tenant" in capsys.readouterr().err
    # with --tenant the receipt is read, and the query names the tenant
    assert run(monkeypatch, transport, "capture", "receipt", "r-1",
               "--tenant", "tenant-a") == 0
    (_method, request_path, _headers, _body), = transport.calls
    assert "tenant_id=tenant-a" in request_path
    assert "retain the original signed capture" in capsys.readouterr().out


def test_capture_trust_anchor_reports_shape_only(monkeypatch, env, capsys):
    anchor = {"configured": True, "status": "ready", "form": "keyset",
              "key_count": 2, "production_requires_signature": True,
              "note": "bank capture signatures verify against this anchor"}
    transport = FakeControlPlane(
        {("GET", "/api/v1/performance/captures/trust-anchor"): (200, anchor)})
    assert run(monkeypatch, transport, "capture", "trust-anchor") == 0
    out = capsys.readouterr().out
    assert "keyset" in out and "2" in out
    assert "PUBLIC KEY" not in out


def test_doctor_names_the_capture_trust_anchor_honestly(monkeypatch, env, capsys):
    health = {"status": "ok"}
    missing = {"configured": False, "status": "unconfigured",
               "production_requires_signature": True,
               "note": "refuses unsigned captures"}
    routes = {
        ("GET", "/api/v1/healthz/dependencies"): (200, health),
        ("GET", "/api/v1/healthz/schema"): (200, health),
        ("GET", "/api/v1/health/worker-fleet"): (200, health),
        ("GET", "/api/v1/health/connectors"): (200, health),
        ("GET", "/api/v1/control/health"): (200, health),
        ("GET", "/api/v1/graph/health"): (200, health),
        ("GET", "/api/v1/automation/health/platform"): (200, health),
        ("GET", "/api/v1/auth/me"): (200, {"username": "operator"}),
        ("GET", "/api/v1/performance/captures/trust-anchor"): (200, missing),
    }
    transport = FakeControlPlane(routes)
    run(monkeypatch, transport, "doctor")
    out = capsys.readouterr().out
    assert "capture trust anchor" in out
    assert "NOT_CONFIGURED" in out
    assert "PERFORMANCE_CAPTURE_PUBLIC_KEY_FILE" in out
