"""The collector-authority matrix, pinned.

Guide 116's claim is a number: eleven planes, six questions, sixty-six cells,
every one of them a refusal the drill watched happen. A committed artifact is the
only place that claim can be checked without running the drill, so it is checked
here — including the negative control, because a matrix that reports PROBED for
everything is worth nothing if it also would with the gate removed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "docs" / "bank-environment" / "116-collector-authority.json"
MARKDOWN = ROOT / "docs" / "bank-environment" / "116-collector-authority.md"

QUESTIONS = ("who", "what_target", "which_revision", "when", "how_long", "permission")

#: The refusal each question has to produce. A cell that reports PROBED without
#: one of these in its observed evidence is reporting a drill that did not look.
EXPECTED = {
    "who": "401",
    "what_target": "TARGET_REFUSED",
    "which_revision": "STALE_REVISION",
    "when": "OUTSIDE_WINDOW",
    "how_long": "EXHAUSTED",
    "permission": "PERMISSION_DENIED",
}
PLANES = ("NETWORK", "RUNTIME", "STATIC", "PKI", "CLOUD", "KUBERNETES", "CMDB",
          "KMS", "HSM", "HARDWARE", "VENDOR")


@pytest.fixture(scope="module")
def report() -> dict:
    if not ARTIFACT.exists():  # pragma: no cover - the artifact ships with the repo
        pytest.skip("the guide 116 artifact has not been generated")
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def test_every_plane_answers_every_question(report):
    assert [row["plane"] for row in report["rows"]] == list(PLANES)
    for row in report["rows"]:
        assert sorted(row["cells"]) == sorted(QUESTIONS)
        assert row["absent"] == [], f"{row['plane']} has an unproven question"
        assert row["verdict"] == "PROVEN"
    assert report["counts"] == {"PROVEN": 11, "PARTIAL": 0, "GAP": 0}
    assert report["cells"] == {"probed": 66, "total": 66}


def test_each_cell_records_the_refusal_it_demanded(report):
    """A PROBED cell names the code it expected and the code it saw."""
    for row in report["rows"]:
        for question, cell in row["cells"].items():
            assert cell["state"] == "PROBED", (row["plane"], question)
            if question == "who":
                assert cell["observed"] == 401
                continue
            code = EXPECTED[question]
            assert code in cell["expected"], (row["plane"], question, cell["expected"])
            assert code in json.dumps(cell["observed"]), (row["plane"], question,
                                                          cell["observed"])


def test_the_control_shows_the_matrix_depends_on_the_gate(report):
    control = report["control"]
    assert control["probed"] < control["total"]
    # only the session check is answered outside the authority
    assert control["survived"]["who"] == 11
    for question in QUESTIONS[1:]:
        assert control["survived"][question] == 0


def test_the_wiring_gap_is_stated_rather_than_implied(report):
    wiring = report["wiring"]
    assert wiring["call_site"].endswith("_collect")
    assert wiring["wired"] is False
    assert "_collect" in wiring["remaining"]


def test_the_markdown_headline_matches_the_json(report):
    text = MARKDOWN.read_text(encoding="utf-8")
    counts = report["counts"]
    assert (f"{counts['PROVEN']} proven · {counts['PARTIAL']} partial · "
            f"{counts['GAP']} gap") in text
    assert "66 of 66 cells" in text
    assert "The one gap left, named" in text
