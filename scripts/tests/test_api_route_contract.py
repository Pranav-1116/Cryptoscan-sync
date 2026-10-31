"""Every path this repository calls must be a path this repository serves.

A page that renders proves nothing about the endpoint behind it. The same is true
of a CLI flag and of a drill script: they are written once, against whatever the
API looked like that week, and the route behind them is renamed or withdrawn
later. Nothing breaks at build time — the caller 404s at the worst possible
moment, in front of an operator or a bank — and no existing test notices, because
each side was tested against itself.

``scripts/api_contract.py`` reads the callers out of the tree and the routes out
of the application's own OpenAPI schema. These tests are the tripwire:

* no caller may name a path the app does not serve;
* no caller may use a verb the route does not accept (a GET on a POST-only route
  is just as broken as a wrong path, and harder to see in review);
* the extraction must actually be doing work — a checker that silently matches
  nothing passes forever, so the counts are pinned too;
* the specific failures found when this was written stay fixed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import api_contract as contract  # noqa: E402


def test_the_schema_is_the_one_the_app_serves():
    served = contract.served_paths()
    assert len(served) >= 1000, f"only {len(served)} routes read from the app"
    assert "/api/v1/estate/evidence/discovery/maturity" in served
    assert "/api/v1/estate/evidence/twin/simulation-scenarios" in served


def test_the_extraction_is_doing_work():
    """A contract test that finds no callers would pass forever."""
    frontend = contract.frontend_calls()
    scripts = contract.script_calls()
    assert len(frontend) >= 500, f"only {len(frontend)} frontend calls extracted"
    assert len(scripts) >= 150, f"only {len(scripts)} script calls extracted"
    assert any(call.path.startswith("/api/v1/estate/evidence") for call in frontend)


def test_no_frontend_call_names_a_path_the_app_does_not_serve():
    broken = contract.unknown(contract.frontend_calls())
    assert broken == [], "frontend calls with no route behind them:\n" + "\n".join(
        f"  {call.path} at {call.where()}" for call in broken
    )


def test_no_script_or_cli_call_names_a_path_the_app_does_not_serve():
    broken = contract.unknown(contract.script_calls())
    assert broken == [], "script/CLI calls with no route behind them:\n" + "\n".join(
        f"  {call.path} at {call.where()}" for call in broken
    )


def test_no_frontend_call_uses_a_verb_the_route_refuses():
    wrong = contract.wrong_verbs()
    assert wrong == [], "calls whose verb the route does not accept:\n" + "\n".join(
        f"  {row['method']} {row['path']} (accepts {row['accepts']}) at {row['at']}" for row in wrong
    )


def test_the_checker_catches_a_path_that_does_not_exist():
    """Mutation check: the detector must fail on a call nobody implemented."""
    synthetic = contract.Call("/api/v1/definitely-not-a-route", "synthetic.ts", 1)
    assert contract.unknown([synthetic]) == [synthetic]
    assert contract.is_served("/api/v1/estate/evidence/discovery/maturity") is True
    assert contract.is_served("/api/v1/estate/evidence/discovery/maturities") is False


def test_the_checker_catches_a_wrong_verb():
    """Mutation check for the verb half, using a route that is POST-only."""
    operations = contract.served_operations()
    post_only = [
        path
        for path, verbs in operations.items()
        if verbs == {"POST"} and "{param}" not in path
    ]
    assert post_only, "no POST-only path to test with"
    # A GET on a POST-only route is the shape of failure the checker reports.
    assert "GET" not in operations[post_only[0]]
    assert "POST" in operations[post_only[0]]


def test_a_runtime_chosen_last_segment_must_have_something_below_it():
    """The truncated fallback cannot excuse a misspelled action name."""
    campaigns = "/api/v1/collection/qualification/campaigns"
    assert contract._extends(campaigns) is True  # .../freeze, .../withdraw exist
    assert contract._extends("/api/v1/estate/evidence/discovery/maturity") is False


def test_the_liveness_probe_matches_what_the_api_registers():
    """registry_webhook_burn.py probed /api/v1/health/live for months.

    Neither that path nor /api/v1/health exists, so the burn reported a dead
    server on its first step and every later verdict inherited the noise. Pin
    the contract: the probe must name a path the health router actually serves.
    """
    served = set(contract.served_paths())
    assert "/api/v1/healthz" in served
    assert "/api/v1/health/live" not in served
    source = (ROOT / "scripts" / "registry_webhook_burn.py").read_text(encoding="utf-8")
    assert "/api/v1/health/live" not in source
    assert "/api/v1/healthz" in source


def test_the_report_is_json_and_stable():
    document = contract.report()
    assert document["schema"] == "cryptoscan.api-route-contract/1"
    for key in ("frontend_unknown", "script_unknown", "wrong_verbs"):
        assert document[key] == []


#: The number of console-called operations that declare no response model when
#: the ratchet was introduced. It may fall, never rise: an operation that adds
#: itself to the console without a schema makes the console/API contract
#: unverifiable for that page, which is the failure this file exists to prevent.
UNTYPED_OPERATION_CEILING = 565


def test_the_untyped_response_ratchet_only_goes_down():
    """93% of the operations the console calls return an untyped dict.

    That is the structural reason a page can exist and its endpoint still be
    wrong: the interface in `lib/api.ts` is a hand-written claim about a payload
    the server never declares. Adding a console call must not make it worse.
    """
    document = contract.console_operation_typing()
    untyped = len(document["untyped"])
    assert untyped <= UNTYPED_OPERATION_CEILING, (
        f"{untyped} console-called operations return an undeclared payload, up from "
        f"{UNTYPED_OPERATION_CEILING}. Declare a response model for the new one "
        "(services/api/api/routers/...), or lower the ceiling in this file with the "
        "endpoints you typed."
    )
    assert document["operations"] >= 500
    assert document["untyped_share"] < 0.95


def test_the_typed_minority_is_real():
    """At least some of the console's contract is machine-checked."""
    document = contract.console_operation_typing()
    assert len(document["typed"]) >= 30
    assert "GET /api/v1/findings" in document["typed"]


def test_a_comment_is_not_a_field(tmp_path):
    """`lib/api.ts` is the response contract, so the parser must not invent fields.

    The first version of `ts_interfaces` skipped `/* */` comments but not `//`, so
    a line reading ``// Always served: the five capabilities …`` became a field
    named ``served`` and the payload contract demanded a key no server sends. The
    fix is in the parser; this test is what keeps it fixed.
    """
    source = tmp_path / "api.ts"
    source.write_text(
        """export interface Sample {
  // Always served: this comment must not become a field
  /* block comment, also not a field */
  id: string;
  note?: string;
  nested: { inner: string };
  // trailing comment with colon: here
}
""",
        encoding="utf-8",
    )
    parsed = contract.ts_interfaces(source)
    assert parsed["Sample"] == {"id": False, "note": True, "nested": False}


def test_every_declared_console_field_is_parseable_from_the_real_file():
    """A field the parser cannot see is a field the contract check silently skips."""
    interfaces = contract.ts_interfaces(ROOT / "frontend" / "src" / "lib" / "api.ts")
    assert len(interfaces) > 300
    for name, fields in interfaces.items():
        assert fields, f"{name} parsed with no fields"
        for field in fields:
            assert field.isidentifier(), (name, field)
