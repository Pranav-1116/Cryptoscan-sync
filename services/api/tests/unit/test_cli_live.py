"""``cryptoscan live``, ``observe push`` and ``bom --download`` against a fake control plane.

The CLI is the bank's control-plane client, so the three properties that matter are the
ones that keep it honest under a change window: it prints the endpoint it read, a
dry-run collects and writes nothing, and a download is described as a projection of the
twin rather than a stored document.
"""
from __future__ import annotations

import json
import urllib.parse
from pathlib import Path

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
        self.calls.append((method, parsed.path, dict(headers), body))
        for (want_method, want_path), (status, payload) in self.routes.items():
            if method == want_method and parsed.path == want_path:
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return cli_remote.Response(status, {"content-type": "application/json"}, data)
        return cli_remote.Response(404, {}, json.dumps({"detail": "no such route in this fake"}).encode())


@pytest.fixture
def env(tmp_path, monkeypatch):
    config = tmp_path / "config.json"
    monkeypatch.setattr(cli_remote, "DEFAULT_CONFIG_PATH", config)
    monkeypatch.setenv("CRYPTOSCAN_SERVER", BASE)
    monkeypatch.setenv("CRYPTOSCAN_TOKEN", "session-token")
    monkeypatch.delenv("CRYPTOSCAN_API_KEY", raising=False)
    return {"config": config, "tmp": tmp_path}


def run(monkeypatch, transport, *argv: str) -> int:
    monkeypatch.setattr(cli_remote, "TRANSPORT", transport)
    return main(list(argv))


def _observation() -> dict:
    return {
        "estate": "payments",
        "scope": "production",
        "assets": [{"ref": "host-01", "type": "HOST", "name": "host-01"}],
        "evidence": [
            {
                "source": "linux-static",
                "evidence_type": "STATIC_OBSERVED",
                "target": "host-01",
                "layer": "PLATFORM",
                "facts": {"hostname": "host-01"},
            }
        ],
    }


def test_live_status_prints_the_connection_as_measured(monkeypatch, env, capsys):
    payload = {
        "connection": {
            "state": "STALE",
            "last_observation": "2026-10-29T11:00:00+00:00",
            "seconds_since": 900,
            "interval_seconds": 300,
        },
        "twin": {"state": "OBSERVED", "projection_id": "abc123", "assets": 3, "evidence": 4},
        "boms": {"counts": {"CBOM": 2, "SBOM": 1}},
        "changes_today": {"count": 4, "unacknowledged": 2},
        "trust": {"findings": ["NO_TRUSTED_COLLECTOR_KEY: nothing can be authenticated here"]},
    }
    transport = FakeControlPlane({("GET", "/api/v1/ingestion/live/status"): (200, payload)})

    assert run(monkeypatch, transport, "live", "status") == 0
    out = capsys.readouterr().out
    assert "STALE" in out
    assert "900s" in out
    assert "a quiet estate and an agent that stopped reporting look identical" in out
    assert "NO_TRUSTED_COLLECTOR_KEY" in out
    assert "source: GET /api/v1/ingestion/live/status (HTTP 200)" in out


def test_live_patterns_never_claim_an_incident(monkeypatch, env, capsys):
    payload = {
        "window_seconds": 3600,
        "window": {"from": "2026-10-29T10:00:00+00:00", "to": "2026-10-29T11:00:00+00:00"},
        "events_considered": 2,
        "signals_considered": 3,
        "highest_level": 2,
        "summary": {"by_level": {"1": 0, "2": 1, "3": 0, "4": 0}},
        "patterns": [
            {
                "pattern_id": "PAT-abc",
                "level": 2,
                "level_name": "SUSPICIOUS_ACTIVITY",
                "headline": "trust path mutation: payments-api",
                "why": "a crypto artefact and the edge that reaches it moved together",
                "next_action": "walk the relationships in the twin",
            }
        ],
    }
    transport = FakeControlPlane({("GET", "/api/v1/estate/evidence/threat/patterns"): (200, payload)})

    assert run(monkeypatch, transport, "live", "patterns") == 0
    out = capsys.readouterr().out
    assert "PAT-abc" in out
    assert "level 3 (incident) is never assigned" in out
    assert "source: GET /api/v1/estate/evidence/threat/patterns" in out


def test_observe_push_dry_run_sends_nothing(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    source = Path(env["tmp"]) / "observation.json"
    source.write_text(json.dumps(_observation()))

    assert run(monkeypatch, transport, "observe", "push", "--file", str(source), "--dry-run") == 0
    out = capsys.readouterr().out
    assert "dry run: nothing was collected and nothing was written" in out
    assert transport.calls == []


def test_observe_push_reports_that_nothing_was_stored_when_nothing_changed(monkeypatch, env, capsys):
    payload = {
        "state": "NO_CHANGE",
        "stored": False,
        "run_id": None,
        "projection_id": "abc123",
        "authenticity": {"status": "UNSIGNED", "deployment_findings": ["not authenticated"]},
    }
    transport = FakeControlPlane({("POST", "/api/v1/ingestion/observations"): (200, payload)})
    source = Path(env["tmp"]) / "observation.json"
    source.write_text(json.dumps(_observation()))

    assert run(monkeypatch, transport, "observe", "push", "--file", str(source)) == 0
    out = capsys.readouterr().out
    assert "NO_CHANGE" in out
    assert "nothing was stored" in out
    assert "source: POST /api/v1/ingestion/observations (HTTP 200)" in out


def test_observe_push_signs_with_the_named_key(monkeypatch, env, tmp_path, capsys):
    from shared_models import release_signature

    keys = release_signature.generate_keypair(tmp_path / "keys", name="collector")
    transport = FakeControlPlane(
        {
            ("POST", "/api/v1/ingestion/observations"): (
                201,
                {
                    "state": "CHANGED",
                    "stored": True,
                    "run_id": "run-1",
                    "projection_id": "abc123",
                    "bom_impact": {"affected": ["CBOM", "TECHBOM"]},
                    "detection": {"headline": "1 change(s): 1× asset added"},
                    "authenticity": {"status": "VALID"},
                },
            )
        }
    )
    source = Path(env["tmp"]) / "observation.json"
    source.write_text(json.dumps(_observation()))

    assert run(
        monkeypatch, transport, "observe", "push", "--file", str(source), "--sign-key", keys["private_key"]
    ) == 0
    body = json.loads(transport.calls[0][3])
    assert body["signature"]["key_id"].startswith("ed25519:")
    out = capsys.readouterr().out
    assert "CHANGED" in out
    assert "CBOM" in out
    assert "VALID" in out


def test_observe_push_refuses_a_file_that_is_not_an_observation(monkeypatch, env, capsys):
    transport = FakeControlPlane()
    source = Path(env["tmp"]) / "not-an-observation.json"
    source.write_text(json.dumps({"hello": "world"}))

    assert run(monkeypatch, transport, "observe", "push", "--file", str(source)) == 3
    err = capsys.readouterr().err
    assert "has no `assets`" in err
    assert transport.calls == []


def test_bom_download_writes_the_projection_and_names_it(monkeypatch, env, capsys):
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/boms/CBOM/export"): (200, json.dumps(document).encode())}
    )
    destination = Path(env["tmp"]) / "cbom.cdx.json"

    assert run(monkeypatch, transport, "bom", "CBOM", "--download", str(destination)) == 0
    assert json.loads(destination.read_text()) == document
    out = capsys.readouterr().out
    assert "projection of the current twin" in out
    assert "source: GET /api/v1/estate/evidence/boms/CBOM/export?fmt=cyclonedx (HTTP 200)" in out


def test_a_failed_download_is_not_an_empty_bom(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {
            ("GET", "/api/v1/estate/evidence/boms/CBOM/export"): (
                404,
                {"detail": {"error": "no_estate_discovery"}},
            )
        }
    )
    destination = Path(env["tmp"]) / "cbom.json"

    code = run(monkeypatch, transport, "bom", "CBOM", "--download", str(destination))

    assert code == 1
    assert not destination.exists(), "a failed download must not leave a file that looks like a BOM"
    err = capsys.readouterr().err
    assert "no_estate_discovery" in err


def test_live_patterns_prints_the_collectors_behind_a_pattern(monkeypatch, env, capsys):
    payload = {
        "window_seconds": 3600,
        "window": {"from": "2026-10-29T10:00:00+00:00", "to": "2026-10-29T11:00:00+00:00"},
        "events_considered": 1,
        "signals_considered": 2,
        "highest_level": 2,
        "summary": {"by_level": {"2": 1}},
        "patterns": [
            {
                "pattern_id": "PAT-abc",
                "level": 2,
                "level_name": "SUSPICIOUS_ACTIVITY",
                "headline": "trust path mutation: payments-api",
                "why": "a crypto artefact and the edge that reached it moved together",
                "next_action": "walk the relationships in the twin",
                "corroboration": {
                    "collectors": ["linux-static", "network-tls"],
                    "independent_sources": 2,
                    "note": "2 independent collectors corroborate this pattern",
                },
            }
        ],
    }
    transport = FakeControlPlane({("GET", "/api/v1/estate/evidence/threat/patterns"): (200, payload)})

    assert run(monkeypatch, transport, "live", "patterns") == 0
    out = capsys.readouterr().out
    assert "sources: linux-static, network-tls" in out
    assert "2 independent" in out


def test_live_compact_is_a_dry_run_unless_confirmed(monkeypatch, env, capsys):
    payload = {
        "dry_run": True,
        "cutoff": "2026-09-29T00:00:00+00:00",
        "keep_days": 30,
        "candidates": {"observations": 4, "change_events": 9, "approx_bytes": 2048},
        "deleted": {"observations": 0, "change_events": 0},
        "preserved": {"newest_observations": 3, "unacknowledged_events": 2},
        "note": "nothing was deleted",
    }
    transport = FakeControlPlane({("POST", "/api/v1/ingestion/live/compact"): (200, payload)})

    assert run(monkeypatch, transport, "live", "compact") == 0
    out = capsys.readouterr().out
    assert "nothing was deleted" in out
    assert "4 observation(s)" in out
    body = json.loads(transport.calls[0][3])
    assert body["confirm"] is False
    assert "source: POST /api/v1/ingestion/live/compact (HTTP 200)" in out


def test_live_compact_passes_the_policy_choices(monkeypatch, env):
    payload = {
        "dry_run": False,
        "cutoff": "2026-09-29T00:00:00+00:00",
        "keep_days": 7,
        "candidates": {"observations": 1, "change_events": 0, "approx_bytes": 100},
        "deleted": {"observations": 1, "change_events": 0},
        "preserved": {"newest_observations": 1, "unacknowledged_events": 0},
        "note": "the listed rows were deleted",
    }
    transport = FakeControlPlane({("POST", "/api/v1/ingestion/live/compact"): (200, payload)})

    assert run(
        monkeypatch, transport, "live", "compact", "--keep-days", "7", "--keep-latest", "1",
        "--no-events", "--confirm",
    ) == 0
    assert json.loads(transport.calls[0][3]) == {
        "keep_days": 7,
        "keep_latest_observations": 1,
        "include_change_events": False,
        "acknowledged_only": True,
        "confirm": True,
    }
