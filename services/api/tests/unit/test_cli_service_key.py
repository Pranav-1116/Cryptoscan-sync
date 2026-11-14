"""Service identity from the operator CLI — short-lived by default.

`service-key issue` mints a machine identity against the existing api-keys
routes and defaults to a 30-day lifetime: a permanent key is the named
exception (`--no-expiry`), never the default. `rotate` mints a replacement
copying the old key's policy and can retire the old one in the same step.
The raw key is shown exactly once.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timedelta, timezone

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
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return {"config": config, "tmp": tmp_path}


def run(monkeypatch, transport: FakeControlPlane, *argv: str) -> int:
    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    return main(list(argv))


CREATED = {
    "id": "key-001", "name": "ci-puller", "key_prefix": "csk_ab12",
    "raw_key": "csk_ab12cd34ef56gh78ij90klmnop",
    "roles": ["viewer"], "scopes": [], "allowed_methods": ["GET"],
    "allowed_ips": [], "rate_per_minute": 0, "rotate_after_days": None,
    "expires_at": "2026-11-15T00:00:00+00:00", "rotation_state": "ok",
}


def _sent_expiry(body: bytes) -> datetime | None:
    raw = json.loads(body).get("expires_at")
    return datetime.fromisoformat(raw) if raw else None


def test_issue_defaults_to_a_thirty_day_lifetime(monkeypatch, env, capsys):
    transport = FakeControlPlane({("POST", "/api/v1/api-keys"): (201, CREATED)})
    before = datetime.now(timezone.utc)
    assert run(monkeypatch, transport, "service-key", "issue", "--name", "ci-puller") == 0
    (method, path, _h, body), = transport.calls
    assert method == "POST" and path == "/api/v1/api-keys"
    sent = json.loads(body)
    expires = _sent_expiry(body)
    assert expires is not None, "issue must be short-lived by default — a key with no expiry is the exception"
    assert before + timedelta(days=29) <= expires <= datetime.now(timezone.utc) + timedelta(days=30, minutes=1)
    assert sent["roles"] == ["viewer"] and sent["allowed_methods"] == ["GET"]
    out = capsys.readouterr().out
    assert "SHOWN ONCE" in out and CREATED["raw_key"] in out
    assert out.count(CREATED["raw_key"]) == 1, "the raw key is shown exactly once"


def test_issue_no_expiry_names_the_exception(monkeypatch, env, capsys):
    transport = FakeControlPlane({("POST", "/api/v1/api-keys"): (201, CREATED)})
    err = capsys.readouterr()
    assert run(monkeypatch, transport, "service-key", "issue", "--name", "ci-puller",
               "--no-expiry") == 0
    (_m, _p, _h, body), = transport.calls
    assert json.loads(body)["expires_at"] is None
    captured = capsys.readouterr()
    assert "PERMANENT" in captured.err, "a permanent credential must be called out before it exists"


def test_issue_carries_the_named_policy(monkeypatch, env):
    transport = FakeControlPlane({("POST", "/api/v1/api-keys"): (201, CREATED)})
    assert run(monkeypatch, transport, "service-key", "issue", "--name", "siem-puller",
               "--role", "reader", "--expires-in-days", "7",
               "--scope", "/findings", "--scope", "/scans",
               "--method", "GET", "--method", "POST",
               "--rate", "60", "--ip", "10.0.0.0/8",
               "--rotate-after-days", "30") == 0
    (_m, _p, _h, body), = transport.calls
    sent = json.loads(body)
    assert sent["roles"] == ["reader"]
    assert sent["scopes"] == ["/findings", "/scans"]
    assert sent["allowed_methods"] == ["GET", "POST"]
    assert sent["rate_per_minute"] == 60 and sent["allowed_ips"] == ["10.0.0.0/8"]
    assert sent["rotate_after_days"] == 30
    expires = _sent_expiry(body)
    assert expires is not None and expires <= datetime.now(timezone.utc) + timedelta(days=7, minutes=1)


def test_revoke_fails_the_key_closed(monkeypatch, env, capsys):
    transport = FakeControlPlane({("DELETE", "/api/v1/api-keys/key-001"): (200, {"ok": True})})
    assert run(monkeypatch, transport, "service-key", "revoke", "key-001") == 0
    (method, path, _h, _b), = transport.calls
    assert method == "DELETE" and path == "/api/v1/api-keys/key-001"
    assert "revoked" in capsys.readouterr().out


def test_report_reads_the_rotation_report(monkeypatch, env):
    report = {"keys_needing_rotation": [], "rotation_state": "ok"}
    transport = FakeControlPlane(
        {("GET", "/api/v1/api-keys/rotation/report"): (200, report)})
    assert run(monkeypatch, transport, "service-key", "report", "--json") == 0
    (method, path, _h, _b), = transport.calls
    assert method == "GET" and path == "/api/v1/api-keys/rotation/report"


def test_list_shows_expiry_and_rotation_state(monkeypatch, env, capsys):
    listing = [{"id": "key-001", "name": "ci-puller", "key_prefix": "csk_ab12…",
                "roles": ["viewer"], "expires_at": "2026-11-15T00:00:00+00:00",
                "rotation_state": "ok"}]
    transport = FakeControlPlane({("GET", "/api/v1/api-keys"): (200, listing)})
    assert run(monkeypatch, transport, "service-key", "list") == 0
    out = capsys.readouterr().out
    assert "ci-puller" in out and "2026-11-15" in out and "ok" in out


def test_rotate_copies_the_policy_and_retire_revokes_the_old(monkeypatch, env):
    old = {"id": "key-001", "name": "ci-puller", "key_prefix": "csk_ab12",
           "roles": ["reader"], "scopes": ["/findings"], "allowed_methods": ["GET"],
           "rate_per_minute": 60, "allowed_ips": ["10.0.0.0/8"], "rotate_after_days": 30}
    listing = [old]
    transport = FakeControlPlane({
        ("GET", "/api/v1/api-keys"): (200, listing),
        ("POST", "/api/v1/api-keys"): (201, CREATED),
        ("DELETE", "/api/v1/api-keys/key-001"): (200, {"ok": True}),
    })
    assert run(monkeypatch, transport, "service-key", "rotate", "key-001",
               "--name", "ci-puller-v2", "--retire") == 0
    methods = [c[0] for c in transport.calls]
    assert methods == ["GET", "POST", "DELETE"], "mint the replacement before retiring the old key"
    body = json.loads(transport.calls[1][3])
    assert body["name"] == "ci-puller-v2"
    assert body["roles"] == ["reader"] and body["scopes"] == ["/findings"]
    assert body["allowed_methods"] == ["GET"] and body["rate_per_minute"] == 60
    assert body["allowed_ips"] == ["10.0.0.0/8"] and body["rotate_after_days"] == 30
    assert body["expires_at"] is not None, "the replacement is short-lived too"
    assert transport.calls[2][0] == "DELETE"
    assert transport.calls[2][1] == "/api/v1/api-keys/key-001"


def test_rotate_without_retire_leaves_the_old_key_running(monkeypatch, env):
    old = {"id": "key-001", "name": "ci-puller", "roles": ["viewer"],
           "scopes": [], "allowed_methods": ["GET"], "rate_per_minute": 0,
           "allowed_ips": [], "rotate_after_days": None}
    transport = FakeControlPlane({
        ("GET", "/api/v1/api-keys"): (200, [old]),
        ("POST", "/api/v1/api-keys"): (201, CREATED),
    })
    assert run(monkeypatch, transport, "service-key", "rotate", "key-001") == 0
    methods = [c[0] for c in transport.calls]
    assert methods == ["GET", "POST"], "without --retire the old key keeps working until the operator revokes it"


def test_rotate_unknown_key_refuses_honestly(monkeypatch, env, capsys):
    transport = FakeControlPlane({("GET", "/api/v1/api-keys"): (200, [])})
    assert run(monkeypatch, transport, "service-key", "rotate", "key-nope") != 0
    assert "no service key named key-nope" in capsys.readouterr().err
