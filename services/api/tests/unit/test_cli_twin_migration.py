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


def test_placement_asset_search_why_use_the_twin_reads(monkeypatch, env):
    transport = FakeControlPlane({
        ("GET", "/api/v1/estate/evidence/twin/placement"): (200, {"placement": []}),
        ("GET", "/api/v1/estate/evidence/twin/assets/pay-1"): (200, {"asset": "pay-1"}),
        ("GET", "/api/v1/estate/evidence/twin/search"): (200, {"results": [
            {"kind": "ALGORITHM", "name": "RSA", "algorithm": "RSA"}]}),
        ("GET", "/api/v1/estate/evidence/twin/why"): (200, {"because": "recorded"}),
    })
    assert run(monkeypatch, transport, "twin", "placement") == 0
    assert run(monkeypatch, transport, "twin", "asset", "pay-1") == 0
    assert run(monkeypatch, transport, "twin", "search", "RSA") == 0
    assert run(monkeypatch, transport, "twin", "why", "pay-1", "--fact", "uses") == 0
    paths = [call[1] for call in transport.calls]
    assert "/api/v1/estate/evidence/twin/assets/pay-1" in paths
    why_call = [c for c in transport.calls if c[1].split("?")[0].endswith("/twin/why")][0]
    assert "subject=pay-1" in why_call[1] and "predicate=uses" in why_call[1]


def test_graph_traversal_posts_the_blast_radius_selector(monkeypatch, env, capsys):
    impact = {"impacted": ["pay-1"], "blind_spots": ["unlinked network hop"]}
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/twin/impact"): (200, impact)})
    assert run(monkeypatch, transport, "twin", "graph-traversal", "pay-1",
               "--depth", "4") == 0
    (_m, _p, _h, body), = transport.calls
    sent = json.loads(body)
    assert sent == {"asset": "pay-1", "depth": 4}
    assert "unlinked network hop" in capsys.readouterr().out


def test_simulate_runs_on_a_copy_and_save_maps_to_persist(monkeypatch, env, capsys):
    result = {"status": "SIMULATED", "live_projection_changed": False, "persisted": True}
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/twin/simulate"): (200, result)})
    assert run(monkeypatch, transport, "twin", "simulate",
               "--from", "RSA", "--to", "ML-KEM-768", "--kind", "REPLACE_ALGORITHM",
               "--label", "pqc-rehearsal", "--save") == 0
    (_m, _p, _h, body), = transport.calls
    sent = json.loads(body)
    assert sent["from"] == "RSA" and sent["to"] == "ML-KEM-768"
    assert sent["persist"] is True and sent["label"] == "pqc-rehearsal"
    out = capsys.readouterr().out
    assert "COPY of the twin" in out and "persisted" in out


def test_changes_maps_the_feed_filters(monkeypatch, env):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/changes"): (200, {"changes": []})})
    assert run(monkeypatch, transport, "twin", "changes",
               "--severity", "CRITICAL", "--unacknowledged", "--limit", "5") == 0
    (_m, path, _h, _b), = transport.calls
    assert "severity=CRITICAL" in path and "unacknowledged_only=True" in path
    assert "limit=5" in path


def test_simulations_listing_uses_the_twin_endpoint(monkeypatch, env):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/simulations"): (200, {"simulations": []})})
    assert run(monkeypatch, transport, "twin", "simulations", "--limit", "7") == 0
    (_m, path, _h, _b), = transport.calls
    assert "limit=7" in path


def test_unmigrated_twin_still_refuses_on_a_bare_terminal(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    assert run(monkeypatch, transport, "twin", "algorithms") == 3
    assert transport.calls == []
    assert "bank-server service operation" in capsys.readouterr().err
