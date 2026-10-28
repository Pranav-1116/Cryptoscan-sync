"""``cryptoscan twin`` — the same twin, from a terminal (spec 94 §17, §20).

The API is not the only place a bank runs things: an operator will reach for a CLI in
a change window, when a graph store load or a "what if we moved to ML-KEM" question
needs to run from a jump host against the same database.

Two properties are under test, and both are really the same one:

* ``twin graph-load`` plans by default and writes only with ``--apply`` — a command
  whose side effect is a graph in a store must not write because it was invoked;
* ``twin simulate`` prints the answer with the live twin's state named as UNCHANGED,
  and ``--save`` stores it *quarantined*: it never appears among the snapshots, and
  ``twin simulations`` says so in the row it prints.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.repositories.scan_run_repository import ScanRunRepository

from test_estate_twin import _payload

BASE = "/api/v1/estate/evidence"


@pytest.fixture()
def cli_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def with_discovery(cli_session):
    """Store an estate discovery exactly as ``POST /discover`` would."""
    ScanRunRepository(cli_session).create_run(
        {"estate_discovery": _payload()},
        target_kind="estate-discovery",
    )
    cli_session.commit()
    return cli_session


def test_graph_load_plans_by_default(cli_session, with_discovery, capsys):
    from api import cli

    code = cli.main(["twin", "graph-load"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "DRY RUN" in out
    assert "pass --apply to write" in out
    assert "statements" in out


def test_graph_load_json_is_the_same_object_the_api_returns(cli_session, with_discovery, capsys):
    from api import cli

    cli.main(["twin", "graph-load", "--json"], session_factory=lambda: with_discovery)
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "cryptoscan.estate-graph-load/1"
    assert payload["dry_run"] is True
    assert payload["expected"]["nodes"] > 0
    assert payload["source_of_truth"]


def test_apply_without_a_store_fails_instead_of_reporting_success(cli_session, with_discovery, capsys):
    from api import cli

    code = cli.main(["twin", "graph-load", "--apply"], session_factory=lambda: with_discovery)
    out = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "NOT_CONNECTED" in out.out + out.err


def test_simulate_says_the_live_twin_was_not_touched(cli_session, with_discovery, capsys):
    from api import cli

    code = cli.main(
        ["twin", "simulate", "--from", "AES-256", "--to", "ML-KEM"],
        session_factory=lambda: with_discovery,
    )
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "UNCHANGED" in out


def test_saved_simulations_are_listed_as_quarantined_history(cli_session, with_discovery, capsys):
    from api import cli

    cli.main(
        ["twin", "simulate", "--from", "AES-256", "--to", "ML-KEM", "--save", "--label", "pqc-2027"],
        session_factory=lambda: with_discovery,
    )
    capsys.readouterr()
    code = cli.main(["twin", "simulations", "--json"], session_factory=lambda: with_discovery)
    payload = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    assert payload["quarantined"] is True
    assert payload["is_estate_state"] is False
    assert payload["simulations"][0]["label"] == "pqc-2027"


def test_a_saved_simulation_does_not_appear_as_history_of_the_estate(cli_session, with_discovery, capsys):
    """`twin simulations` is a list of questions asked; it is not the snapshot list."""
    from api import cli
    from api import estate_twin_store

    cli.main(
        ["twin", "simulate", "--from", "AES-256", "--to", "ML-KEM", "--save"],
        session_factory=lambda: with_discovery,
    )
    capsys.readouterr()
    assert estate_twin_store.list_snapshots(with_discovery, tenant_id=None, limit=10) == []
    cli.main(["twin", "simulations"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert "REPLACE_ALGORITHM" in out


def test_no_stored_simulations_says_so_rather_than_printing_an_empty_table(cli_session, with_discovery, capsys):
    from api import cli

    code = cli.main(["twin", "simulations"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "nothing has been asked of a copy" in out


def test_a_twin_command_without_an_observation_refuses_to_invent_one(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "graph-load"], session_factory=lambda: cli_session)
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "NOT_OBSERVED" in captured.err


# -- the change feed from a terminal --------------------------------------- #


def test_changes_on_an_empty_feed_says_what_quiet_does_not_mean(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "changes"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "no changes recorded" in out
    assert "an empty feed is not a safe estate" in out


def test_detect_without_an_observation_refuses_to_compare_against_nothing(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "detect"], session_factory=lambda: cli_session)
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "nothing has been observed yet" in captured.err


def test_detect_records_a_change_and_changes_lists_it(cli_session, with_discovery, capsys):
    from api import cli
    from db.repositories.scan_run_repository import ScanRunRepository

    changed = _payload()
    changed["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04"})
    ScanRunRepository(with_discovery).create_run(
        {"estate_discovery": changed}, target_kind="estate-discovery"
    )
    with_discovery.commit()
    capsys.readouterr()

    code = cli.main(["twin", "detect"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "HSM-04" in out
    assert "recorded chg_" in out

    code = cli.main(["twin", "changes"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "change event(s)" in out
    assert "asset added" in out.lower()
    assert "not acknowledged" in out


def test_acknowledging_from_the_cli_leaves_the_findings_alone(cli_session, with_discovery, capsys):
    from api import cli
    from db.repositories.scan_run_repository import ScanRunRepository

    changed = _payload()
    changed["assets"].append({"ref": "hsm2", "type": "HSM", "name": "HSM-04"})
    ScanRunRepository(with_discovery).create_run(
        {"estate_discovery": changed}, target_kind="estate-discovery"
    )
    with_discovery.commit()
    cli.main(["twin", "detect", "--json"], session_factory=lambda: with_discovery)
    payload = json.loads(capsys.readouterr().out)
    event_id = payload["recorded"]["event_id"]
    assert event_id

    code = cli.main(
        ["twin", "ack", event_id, "--note", "ticket CR-1"],
        session_factory=lambda: with_discovery,
    )
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "findings unchanged" in out

    code = cli.main(["twin", "changes", "--unacknowledged"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    # an empty *filtered* view is not an empty feed, and it must not read like a
    # quiet estate
    assert "no change events match this filter" in out


def test_acknowledging_an_unknown_change_fails_loudly(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "ack", "chg_missing"], session_factory=lambda: cli_session)
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "no change event" in captured.err


# -- the durable catalogue from a terminal --------------------------------- #


def test_assets_lists_catalogue_records_with_their_lifecycle(cli_session, with_discovery, capsys):
    from api import cli, estate_catalog
    from shared_models.estate_graph import build_graph

    estate_catalog.sync(with_discovery, build_graph(_payload()), tenant_id=None, run_id="run-1")
    capsys.readouterr()

    code = cli.main(["twin", "assets"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "Payment API" in out
    assert "ACTIVE" in out
    assert "seen 1×" in out


def test_an_empty_catalogue_says_it_is_about_collection(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "assets"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "not 'the bank has no assets'" in out


def test_asset_detail_prints_crypto_edges_and_refused_candidates(cli_session, with_discovery, capsys):
    from api import cli, estate_catalog
    from shared_models.estate_graph import build_graph

    estate_catalog.sync(with_discovery, build_graph(_payload()), tenant_id=None, run_id="run-1")
    capsys.readouterr()

    code = cli.main(["twin", "asset", "Payment API"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "Payment API" in out
    assert "lifecycle" in out
    assert "AES-256-GCM" in out


def test_an_unknown_asset_fails_without_claiming_it_does_not_exist(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "asset", "nothing"], session_factory=lambda: cli_session)
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "never have been observed" in captured.err


def test_algorithms_keeps_capability_and_use_apart(cli_session, with_discovery, capsys):
    from api import cli, estate_catalog
    from shared_models.estate_graph import build_graph

    payload = _payload()
    payload["assets"].append({"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL"})
    payload["evidence"].append({
        "evidence_id": "ev-9", "source": "linux-static", "evidence_type": "STATIC_OBSERVED",
        "target": "ossl", "layer": "APPLICATION", "facts": {"supported_algorithms": ["AES-128"]},
    })
    estate_catalog.sync(with_discovery, build_graph(payload), tenant_id=None, run_id="run-1")
    capsys.readouterr()

    code = cli.main(["twin", "algorithms"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "AES-256-GCM" in out
    assert "AES-128" in out
    assert "SUPPORTED" in out and "OBSERVED" in out


def test_placement_prints_the_levels_and_what_nothing_asserts(cli_session, with_discovery, capsys):
    from api import cli

    code = cli.main(["twin", "placement"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "estate     Synthetic Bank" in out
    assert "not observed: REGION" in out
    assert "no region" in out


def test_placement_without_an_observation_refuses_to_invent_a_hierarchy(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "placement"], session_factory=lambda: cli_session)
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "NOT_OBSERVED" in captured.err


def _record_history(session, region: str = "me-central-1"):
    from api import estate_observations
    from shared_models.estate_graph import build_graph

    payload = _payload()
    target = next(item for item in payload["assets"] if item["name"] == "Payment API")
    target["attributes"] = {"region": region}
    estate_observations.sync_all(session, build_graph(payload), tenant_id=None)
    return session


def test_history_shows_a_window_that_closed(with_discovery, capsys):
    from api import cli

    _record_history(with_discovery, region="me-central-1")
    _record_history(with_discovery, region="me-west-1")

    code = cli.main(["twin", "history", "Payment API"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "attribute:region" in out
    assert "me-west-1" in out
    assert "was 'me-central-1'" in out


def test_history_says_absence_is_not_a_denial(cli_session, capsys):
    from api import cli

    code = cli.main(["twin", "history", "Unknown"], session_factory=lambda: cli_session)
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "not observed" in captured.err


def test_why_names_the_evidence_and_its_limit(with_discovery, capsys):
    from api import cli

    _record_history(with_discovery)
    code = cli.main(
        ["twin", "why", "Payment API", "--fact", "attribute:region"],
        session_factory=lambda: with_discovery,
    )
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "attribute:region" in out
    assert "limit" in out
    assert "not one record per attribute value" in out


def test_why_refuses_to_invent_an_explanation(with_discovery, capsys):
    from api import cli

    _record_history(with_discovery)
    code = cli.main(
        ["twin", "why", "Payment API", "--fact", "attribute:nowhere"],
        session_factory=lambda: with_discovery,
    )
    captured = capsys.readouterr()
    assert code == cli.EXIT_INCOMPLETE
    assert "not evidence" in captured.err


def test_evidence_lists_stored_records(with_discovery, capsys):
    from api import cli

    _record_history(with_discovery)
    code = cli.main(["twin", "evidence", "--json"], session_factory=lambda: with_discovery)
    body = json.loads(capsys.readouterr().out)
    assert code == cli.EXIT_OK
    assert body["count"] >= 1
    assert body["records"][0]["evidence_id"]


def test_search_finds_across_kinds_from_a_terminal(with_discovery, capsys):
    from api import cli
    from api import estate_catalog
    from shared_models.estate_graph import build_graph

    estate_catalog.sync(with_discovery, build_graph(_payload()), tenant_id=None)
    code = cli.main(["twin", "search", "HSM"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "match(es) for" in out


def test_search_says_a_miss_is_a_gap_in_the_record(with_discovery, capsys):
    from api import cli
    from api import estate_catalog
    from shared_models.estate_graph import build_graph

    estate_catalog.sync(with_discovery, build_graph(_payload()), tenant_id=None)
    code = cli.main(["twin", "search", "Kyber-1024"], session_factory=lambda: with_discovery)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "not evidence the bank has none" in out
