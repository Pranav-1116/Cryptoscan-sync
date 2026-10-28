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
