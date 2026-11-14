"""Legacy twin migration — bare terminals use the API, never a local database.

The migration is COMPLETE: every twin subcommand, from an operator terminal
(no session_factory), calls the control plane's twin, catalog, history,
evidence and changes routes — the control plane owns the graph-store
connection and this CLI still never touches one. The in-process bank-server
CLI keeps its local handlers for the daemon. The honest notes and exit
semantics travel with the migration: an unobserved estate is INCOMPLETE,
never an empty answer.
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


def test_every_twin_command_is_migrated_to_the_control_plane(monkeypatch, env, capsys):
    # The migration is finished: no twin subcommand is left behind on the
    # terminal's database. This walks the parser, so a future subcommand
    # that forgets to migrate fails here rather than silently reaching for
    # whatever database the host happens to have.
    from api.cli import MIGRATED_TWIN_COMMANDS, REMOTE_TWIN_COMMANDS, _build_parser

    parser = _build_parser()
    command_action = next(a for a in parser._actions if a.dest == "command")
    twin_parser = command_action.choices["twin"]
    twin_action = next(a for a in twin_parser._actions if a.dest == "twin_command")
    subcommands = set(twin_action.choices)
    assert subcommands <= (REMOTE_TWIN_COMMANDS | MIGRATED_TWIN_COMMANDS), (
        f"unmigrated twin commands: {sorted(subcommands - REMOTE_TWIN_COMMANDS - MIGRATED_TWIN_COMMANDS)}")

    # and the last migrated command proves the path: remote, no local database
    registry = {"algorithms": [], "meaning": "registry is empty until something is observed"}
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/catalog/crypto"): (200, registry)})
    assert run(monkeypatch, transport, "twin", "algorithms") == 0
    assert [c[1].split("?")[0] for c in transport.calls] == \
        ["/api/v1/estate/evidence/catalog/crypto"]
    assert "nothing has been observed" in capsys.readouterr().out


# --- the second migration slice: the ten remaining reads -------------------------


def test_assets_browses_the_catalogue_with_its_filters(monkeypatch, env, capsys):
    listing = {
        "count": 1,
        "assets": [{"asset_type": "HSM", "name": "pay-hsm", "lifecycle_state": "ACTIVE",
                    "observation_count": 7, "environment": "production",
                    "asset_id": "a-1", "evidence_count": 3, "owner": "payments"}],
        "note": "the catalogue is derived from evidence and kept across observations",
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/catalog/assets"): (200, listing)})
    assert run(monkeypatch, transport, "twin", "assets",
               "--type", "HSM", "--environment", "production",
               "--owner", "payments", "--lifecycle", "ACTIVE",
               "--q", "pay", "--limit", "5") == 0
    (_m, path, _h, _b), = transport.calls
    assert path.split("?")[0] == "/api/v1/estate/evidence/catalog/assets"
    for part in ("asset_type=HSM", "environment=production", "owner=payments",
                 "lifecycle=ACTIVE", "q=pay", "limit=5"):
        assert part in path, f"filter {part} did not reach the control plane"
    out = capsys.readouterr().out
    assert "pay-hsm" in out and "seen 7×" in out and "ev=3" in out


def test_assets_empty_is_not_an_empty_bank(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/catalog/assets"): (
            200, {"count": 0, "assets": []})})
    assert run(monkeypatch, transport, "twin", "assets") == 0
    out = capsys.readouterr().out
    assert "that is not 'the bank has no assets'" in out


def test_algorithms_reads_the_registry_and_filters_by_query(monkeypatch, env, capsys):
    registry = {
        "algorithms": [{
            "algorithm": "RSA", "asset_count": 2,
            "usage_states": {"IN_USE": 2},
            "assets": [{"asset_type": "certificate", "asset_name": "pay-leaf",
                        "usage_state": "IN_USE"}],
        }],
        "meaning": "use and capability are counted apart",
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/catalog/crypto"): (200, registry)})
    assert run(monkeypatch, transport, "twin", "algorithms",
               "--q", "RSA", "--type", "certificate") == 0
    (_m, path, _h, _b), = transport.calls
    assert path.split("?")[0] == "/api/v1/estate/evidence/catalog/crypto"
    assert "q=RSA" in path and "asset_type=certificate" in path
    out = capsys.readouterr().out
    assert "RSA" in out and "2 asset(s)" in out and "pay-leaf" in out
    assert "use and capability are counted apart" in out


def test_conflicts_never_resolves_the_disagreement(monkeypatch, env, capsys):
    conflicts = {
        "count": 1, "real_count": 1, "explained_count": 0,
        "by_classification": {"UNKNOWN": 0},
        "conflicts": [{
            "asset_name": "pay-gw", "asset_id": "a-1", "classification": "REAL",
            "field": "key_size",
            "values": [{"value": "2048", "source": "scan-1", "evidence_type": "OBSERVED",
                        "layer": "network"}],
            "reason": "two sources on one plane disagree",
        }],
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/conflicts"): (200, conflicts)})
    assert run(monkeypatch, transport, "twin", "conflicts") == 0
    out = capsys.readouterr().out
    assert "1 conflict(s): 1 real" in out
    assert "! pay-gw · key_size · REAL" in out
    assert "two sources on one plane disagree" in out


def test_conflicts_empty_is_not_agreement(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/conflicts"): (200, {"count": 0})})
    assert run(monkeypatch, transport, "twin", "conflicts") == 0
    out = capsys.readouterr().out
    assert "not a statement that the bank's sources agree" in out


def test_lifecycle_names_where_the_loop_breaks(monkeypatch, env, capsys):
    lifecycle = {
        "phases": [
            {"phase": "collect", "status": "CONNECTED", "question": "is anything collected?"},
            {"phase": "project", "status": "PARTIAL", "question": "do the BOMs project?",
             "detail": "two planes are silent"},
        ],
        "loop_closed": False, "first_break": "project",
        "meaning": "the loop is the product",
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/lifecycle"): (200, lifecycle)})
    assert run(monkeypatch, transport, "twin", "lifecycle") == 0
    out = capsys.readouterr().out
    assert "collect" in out and "CONNECTED" in out
    assert "the loop does not close: it breaks first at project" in out
    assert "two planes are silent" in out


def test_intel_is_incomplete_when_the_estate_is_unobserved(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/intel"): (
            200, {"status": "NOT_OBSERVED", "detail": "no observation"})})
    assert run(monkeypatch, transport, "twin", "intel") == 2
    err = capsys.readouterr().err
    assert "That is not a clean answer" in err


def test_intel_counts_use_and_capability_apart(monkeypatch, env, capsys):
    intel = {
        "artifacts_examined": 5,
        "weak": {"count": 1, "in_use_count": 1, "capability_only_count": 0,
                 "entries": [{"asset_name": "legacy-vpn", "asset_id": "a-2",
                              "algorithm": "3DES", "status": "WEAK", "usage_state": "IN_USE",
                              "layer": "network", "in_use": True}]},
        "unknown": {"count": 1, "unrecognised_count": 1, "mislabelled_count": 0},
        "pqc": {"vulnerable_artifacts": 3, "pending_migration_count": 2,
                "vendor_bound_blocker_count": 1},
        "next_action": "start with what is in use",
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/intel"): (200, intel)})
    assert run(monkeypatch, transport, "twin", "intel", "--limit", "5") == 0
    (_m, path, _h, _b), = transport.calls
    assert "limit=5" in path
    out = capsys.readouterr().out
    assert "5 crypto artefact(s) examined" in out
    assert "! legacy-vpn · 3DES · WEAK · IN_USE · network" in out
    assert "post-quantum 3 artefact(s)" in out
    assert "start with what is in use" in out


def test_algorithm_detail_keeps_use_and_capability_apart(monkeypatch, env, capsys):
    detail = {
        "found": True, "query": "RSA", "algorithm": "RSA", "status": "ACCEPTABLE",
        "artifacts": 2, "in_use": 1, "capability_only": 1,
        "by_asset_type": {"certificate": 2},
        "assets": [{"asset_name": "pay-leaf", "asset_id": "a-1", "algorithms": ["RSA"]}],
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/algorithm/RSA"): (200, detail)})
    assert run(monkeypatch, transport, "twin", "algorithm", "RSA") == 0
    out = capsys.readouterr().out
    assert "RSA · ACCEPTABLE · 2 artefact(s): 1 in use, 1 capability only" in out
    assert "pay-leaf: RSA" in out


def test_algorithm_not_found_is_not_a_denial(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/algorithm/Nope"): (
            200, {"found": False, "query": "Nope"})})
    assert run(monkeypatch, transport, "twin", "algorithm", "Nope") == 0
    out = capsys.readouterr().out
    assert "not a statement that the estate does not use it" in out


def test_trust_paths_render_chains_and_the_broken_note(monkeypatch, env, capsys):
    trust = {
        "count": 1, "longest_chain": 3, "by_status": {"BROKEN": 1},
        "chains": [{
            "asset_name": "pay-leaf", "asset_id": "a-1", "status": "BROKEN",
            "chain": [{"asset_name": "pay-leaf", "asset_id": "a-1", "present": True},
                      {"asset_name": None, "asset_id": None, "present": False}],
        }],
        "broken_count": 1, "unjudged_count": 0,
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/twin/trust-paths"): (200, trust)})
    assert run(monkeypatch, transport, "twin", "trust-paths") == 0
    out = capsys.readouterr().out
    assert "1 certificate chain(s), longest 3 link(s)" in out
    assert "pay-leaf: BROKEN · pay-leaf -> ? (not collected)" in out
    assert "not proof the certificate is untrusted" in out


def test_history_marks_current_historical_and_conflict(monkeypatch, env, capsys):
    history = {
        "fact_count": 2,
        "facts": [
            {"fact_type": "key_size", "state": "CURRENT", "current_values": ["2048"],
             "timeline": [{"state": "CURRENT", "value": "2048"},
                          {"state": "HISTORICAL", "value": "1024",
                           "last_seen_at": "2026-09-01", "observation_count": 4}]},
            {"fact_type": "protocol", "state": "CONFLICT", "current_values": ["TLSv1.2", "TLSv1.3"],
             "timeline": []},
        ],
        "conflicted_facts": ["protocol"],
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/history/assets/pay-leaf"): (200, history)})
    assert run(monkeypatch, transport, "twin", "history", "pay-leaf") == 0
    out = capsys.readouterr().out
    assert "pay-leaf · 2 fact(s)" in out
    assert "  key_size" in out and "was '1024' until 2026-09-01 (seen 4x)" in out
    assert "! protocol" in out
    assert "disputes  protocol — both values still asserted, nothing chosen" in out


def test_history_unobserved_is_incomplete_not_empty(monkeypatch, env, capsys):
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/history/assets/ghost"): (
            200, {"fact_count": 0, "facts": []})})
    assert run(monkeypatch, transport, "twin", "history", "ghost") == 2
    err = capsys.readouterr().err
    assert "not observed" in err


def test_evidence_lists_records_and_empty_is_incomplete(monkeypatch, env, capsys):
    records = {
        "count": 1,
        "records": [{"evidence_type": "OBSERVED", "collector": "nmap-collector",
                     "observation_count": 3, "evidence_id": "ev-1"}],
    }
    transport = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/evidence/records"): (200, records)})
    assert run(monkeypatch, transport, "twin", "evidence",
               "--target", "pay-leaf", "--type", "OBSERVED", "--limit", "5") == 0
    (_m, path, _h, _b), = transport.calls
    assert "target=pay-leaf" in path and "evidence_type=OBSERVED" in path and "limit=5" in path
    out = capsys.readouterr().out
    assert "1 evidence record(s)" in out and "ev-1" in out

    empty = FakeControlPlane(
        {("GET", "/api/v1/estate/evidence/evidence/records"): (200, {"count": 0})})
    assert run(monkeypatch, empty, "twin", "evidence") == 2
    assert "nothing has been observed" in capsys.readouterr().err


def test_detect_compares_now_and_says_what_was_recorded(monkeypatch, env, capsys):
    detection = {
        "severity": "WARNING", "verdict": "CHANGED",
        "headline": "one asset demoted",
        "changes": [{"kind": "CRYPTO_DEMOTED", "detail": "pay-leaf: RSA -> 3DES"}],
        "next_action": "re-check the collector's last run",
        "recorded": {"created": True, "event_id": "ev-9"},
    }
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/changes/detect"): (200, detection)})
    assert run(monkeypatch, transport, "twin", "detect") == 0
    (method, path, _h, _b), = transport.calls
    assert method == "POST" and path == "/api/v1/estate/evidence/changes/detect"
    out = capsys.readouterr().out
    assert "severity   WARNING" in out and "verdict    CHANGED" in out
    assert "CRYPTO_DEMOTED" in out and "recorded ev-9" in out


def test_ack_marks_a_change_seen_and_an_unknown_event_is_incomplete(monkeypatch, env, capsys):
    acked = {"event_id": "ev-9", "acknowledged_by": "cli", "acknowledged_at": "2026-10-16T10:00:00Z"}
    transport = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/changes/ev-9/acknowledge"): (200, acked)})
    assert run(monkeypatch, transport, "twin", "ack", "ev-9", "--note", "seen in triage") == 0
    (method, path, _h, body), = transport.calls
    assert method == "POST"
    assert path == "/api/v1/estate/evidence/changes/ev-9/acknowledge"
    assert json.loads(body) == {"note": "seen in triage"}
    out = capsys.readouterr().out
    assert "acknowledged ev-9 by cli" in out and "findings unchanged" in out

    missing = FakeControlPlane(
        {("POST", "/api/v1/estate/evidence/changes/ev-404/acknowledge"): (
            404, {"detail": "no such change event"})})
    assert run(monkeypatch, missing, "twin", "ack", "ev-404") == 2
    assert "no change event 'ev-404' for this tenant" in capsys.readouterr().err
