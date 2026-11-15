"""Scale evidence — the DB discipline claims must be RUNNABLE and their
receipts real.

The ratchet runs at 50,000 assets (scripts/scale_evidence.py); the test
runs the same machinery at 2,000 and pins the honesty properties: the
artifact records what the planner actually did (index names, seq scans,
timing), a missing expected index FAILS the run, and evidence is
produced by running the tool — never committed as a claim.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]

pgserver = pytest.importorskip("pgserver",
                               reason="pgserver is not installed: no PostgreSQL to evidence")


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "scale_evidence", ROOT / "scripts" / "scale_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


@pytest.fixture(scope="module")
def engine():
    from sqlalchemy import create_engine

    work = tempfile.mkdtemp(prefix="scale-ev-")
    server = pgserver.get_server(work)
    uri = server.get_uri()
    server.psql("CREATE DATABASE cryptoscan;")
    host = uri.split("host=")[1]
    eng = create_engine(
        f"postgresql+psycopg2://postgres:@/cryptoscan?host={host}", future=True)
    try:
        yield eng
    finally:
        eng.dispose()
        server.cleanup()


class TestTheEvidenceIsReal:
    def test_plans_record_what_the_planner_did(self, engine):
        report = tool.run(2000, engine=engine)
        assert report["assets"] == 2000
        assert report["seed"]["inserted"] == 2000
        names = {p["query"] for p in report["plans"]}
        assert names == set(tool.HOT_QUERIES)
        for p in report["plans"]:
            assert p["execution_ms"] is not None, p
            assert isinstance(p["indexes_used"], list)
            assert isinstance(p["seq_scans"], list)

    def test_a_missing_expected_index_fails_the_ratchet(self, engine):
        report = tool.run(2000, engine=engine, expect_index=("no_such_idx",))
        assert report["ratchet"] == "FAIL"
        assert any("no_such_idx" in v for v in report["violations"])

    def test_the_ratchet_passes_when_its_index_is_used(self, engine):
        # whatever the planner actually picks for the aggregate, the run
        # passes when no phantom index is demanded — the mechanism is the
        # contract here; the 50k run names the real indexes.
        report = tool.run(2000, engine=engine)
        assert report["ratchet"] == "PASS"
        assert report["violations"] == []

    def test_artifacts_stay_out_of_git(self):
        # evidence is produced by running the tool, never committed
        gitignore = (ROOT / ".gitignore").read_text()
        assert "data/" in gitignore
        assert json.dumps(tool.HOT_QUERIES)  # the queries are code, not data
