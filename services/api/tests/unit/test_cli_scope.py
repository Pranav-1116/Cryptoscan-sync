"""`scope snapshot / snapshots / diff` — the CLI renders the server's verdicts.

The diff markers (+ added, - removed, ~ changed, ! blocked) are printed from
GET /api/v1/scope/diff's response and nothing else: a terminal that could
compute the diff locally could also invent it. The honest emptiness notes are
pinned here — an empty diff or an empty snapshot list is never proof about the
estate.
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


def test_scope_diff_renders_every_verdict_marker(monkeypatch, env, capsys):
    diff = {
        "from": {"ref": "v1", "snapshot_id": "snap-1", "label": "before",
                 "content_hash": "a" * 64},
        "to": {"ref": "current", "snapshot_id": None, "label": None,
               "content_hash": "b" * 64},
        "added": [{"kind": "application", "target": "pay.example", "enabled": True}],
        "removed": [{"kind": "network", "target": "10.0.0.0/24", "was_effective": True}],
        "changed": [{"kind": "cloud", "target": "aws-prod",
                     "before": {"enabled": True, "detail": {}},
                     "after": {"enabled": True, "detail": {"tier": "gold"}}}],
        "blocked": [{"kind": "application", "target": "blocked.example", "reason": "disabled"},
                    {"kind": "network", "target": "10.9.9.9", "reason": "excluded",
                     "excluded_by": "10.9.9.9"}],
        "envelope_changed": {"exclusions": {"before": [], "after": ["10.9.9.9"]}},
        "summary": {"added": 1, "removed": 1, "changed": 1, "blocked": 2,
                    "envelope_fields_changed": 1},
    }
    transport = FakeControlPlane({("GET", "/api/v1/scope/diff"): (200, diff)})
    assert run(monkeypatch, transport, "scope", "diff",
               "--from", "snap-1", "--to", "current") == 0
    (method, path, _h, _b), = transport.calls
    assert method == "GET" and path.startswith("/api/v1/scope/diff?")
    assert "from=snap-1" in path and "to=current" in path
    out = capsys.readouterr().out
    assert "+  added" in out and "pay.example" in out
    assert "-  removed" in out and "10.0.0.0/24" in out and "was effective" in out
    assert "~  changed" in out and "aws-prod" in out
    assert "!  blocked" in out and "blocked.example" in out and "disabled" in out
    assert "excluded by 10.9.9.9" in out
    assert "~  envelope.exclusions" in out
    assert "added 1 · removed 1 · changed 1 · blocked 2" in out


def test_scope_diff_defaults_both_sides_to_current(monkeypatch, env):
    diff = {"from": {"ref": "current"}, "to": {"ref": "current"},
            "added": [], "removed": [], "changed": [], "blocked": [],
            "envelope_changed": {}, "summary": {}}
    transport = FakeControlPlane({("GET", "/api/v1/scope/diff"): (200, diff)})
    assert run(monkeypatch, transport, "scope", "diff") == 0
    (_m, path, _h, _b), = transport.calls
    assert "from=current" in path and "to=current" in path


def test_scope_diff_empty_is_not_proof(monkeypatch, env, capsys):
    diff = {"from": {"ref": "current"}, "to": {"ref": "current"},
            "added": [], "removed": [], "changed": [], "blocked": [],
            "envelope_changed": {},
            "summary": {"added": 0, "removed": 0, "changed": 0, "blocked": 0,
                        "envelope_fields_changed": 0}}
    transport = FakeControlPlane({("GET", "/api/v1/scope/diff"): (200, diff)})
    assert run(monkeypatch, transport, "scope", "diff") == 0
    out = capsys.readouterr().out
    assert "not proof the scope was enforced" in out


def test_scope_snapshot_captures_a_named_revision(monkeypatch, env, capsys):
    created = {"id": "snap-9", "label": "before-change",
               "content_hash": "c" * 64, "created_at": "2026-10-16T10:00:00+00:00",
               "entries": 3}
    transport = FakeControlPlane({("POST", "/api/v1/scope/snapshots"): (201, created)})
    assert run(monkeypatch, transport, "scope", "snapshot",
               "--label", "before-change") == 0
    (method, path, _h, _b), = transport.calls
    assert method == "POST" and path.startswith("/api/v1/scope/snapshots")
    assert "label=before-change" in path
    out = capsys.readouterr().out
    assert "snap-9" in out and "before-change" in out
    assert "not proof the scope was enforced" in out


def test_scope_snapshots_lists_revisions(monkeypatch, env, capsys):
    listing = [{"id": "snap-9", "label": "before-change",
                "created_at": "2026-10-16T10:00:00+00:00", "entries": 3,
                "content_hash": "c" * 64}]
    transport = FakeControlPlane({("GET", "/api/v1/scope/snapshots"): (200, listing)})
    assert run(monkeypatch, transport, "scope", "snapshots") == 0
    out = capsys.readouterr().out
    assert "snap-9" in out and "before-change" in out


def test_scope_snapshots_empty_says_what_it_does_not_mean(monkeypatch, env, capsys):
    transport = FakeControlPlane({("GET", "/api/v1/scope/snapshots"): (200, [])})
    assert run(monkeypatch, transport, "scope", "snapshots") == 0
    out = capsys.readouterr().out
    assert "not proof" in out and "scope never changed" in out
