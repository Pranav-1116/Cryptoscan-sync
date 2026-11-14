"""Legacy twin migration — bare terminals use the API, never a local database.

`graph-load` and `graph-verify` are migrated: from an operator terminal (no
session_factory) they call the control plane's graph-store endpoints, and the
in-process bank-server CLI keeps its local handlers. Everything unmigrated
still refuses on a bare terminal rather than reaching for whatever database
the host happens to have.
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
    monkeypatch.delenv("DATABASE_URL", raising=False)
    return {"config": config, "tmp": tmp_path}


def run(monkeypatch, transport: FakeControlPlane, *argv: str) -> int:
    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    return main(list(argv))


def test_graph_load_from_a_bare_terminal_uses_the_control_plane(monkeypatch, env):
    plan = {"dry_run": True, "statements": 12, "nodes": 3, "relationships": 2}
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/twin/graph/load"): (200, plan)})
    assert run(monkeypatch, transport, "twin", "graph-load") == 0
    (method, path, _headers, body), = transport.calls
    assert method == "POST" and path == "/api/v1/estate/evidence/twin/graph/load"
    sent = json.loads(body)
    assert sent["dry_run"] is True, "the plan is the default — nothing is written"
    assert sent["batch_size"] == 500


def test_graph_load_apply_sends_dry_run_false_and_names_the_mode(monkeypatch, env, capsys):
    applied = {"dry_run": False, "statements": 12, "nodes": 3, "relationships": 2}
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/twin/graph/load"): (200, applied)})
    assert run(monkeypatch, transport, "twin", "graph-load",
               "--apply", "--batch-size", "250", "--prune-missing") == 0
    (_m, _p, _h, body), = transport.calls
    sent = json.loads(body)
    assert sent["dry_run"] is False and sent["batch_size"] == 250
    assert sent["prune_missing"] is True
    assert "APPLY" in capsys.readouterr().out


def test_graph_verify_calls_the_verify_endpoint_and_names_not_connected(monkeypatch, env, capsys):
    result = {"verdict": "NOT_CONNECTED", "detail": "no graph store is configured"}
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/twin/graph/verify"): (200, result)})
    assert run(monkeypatch, transport, "twin", "graph-verify") == 0
    (method, path, _headers, _body), = transport.calls
    assert method == "POST" and path.endswith("/twin/graph/verify")
    out = capsys.readouterr().out
    assert "NOT_CONNECTED" in out and "not parity" in out


def test_unmigrated_twin_still_refuses_on_a_bare_terminal(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "twin", "placement") == 3
    assert transport.calls == []
    assert "bank-server service operation" in capsys.readouterr().err
