"""Guide 118's artifact, pinned — including the audit page it added.

The frontend rows are static counts over ``frontend/src``, so the artifact is the
only place their claim can be checked without re-reading the source. Three things
must stay true: the counts in the markdown match the JSON, the audit trail has a
surface of its own (it was a redirect before this pass), and the negative control
still collapses the grades — an audit whose control passes would be decoration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = ROOT / "docs" / "bank-environment" / "118-frontend-hardening.json"
MARKDOWN = ROOT / "docs" / "bank-environment" / "118-frontend-hardening.md"
AUDIT_PAGE = ROOT / "frontend" / "src" / "pages" / "Audit.tsx"
AUDIT_TEST = ROOT / "frontend" / "src" / "pages" / "Audit.test.tsx"

BEHAVIOURS = (
    "contract_coverage", "error_handling", "empty_states", "large_graphs",
    "realtime", "authorization_views", "auditability", "degraded_coverage",
    "page_test_coverage",
)


@pytest.fixture(scope="module")
def report() -> dict:
    if not ARTIFACT.exists():  # pragma: no cover - the artifact ships with the repo
        pytest.skip("the guide 118 artifact has not been generated")
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def rows(report: dict) -> dict[str, dict]:
    return {row["id"]: row for row in report["rows"]}


def test_every_behaviour_is_graded_and_only_typing_is_partial(report):
    assert tuple(row["id"] for row in report["rows"]) == BEHAVIOURS
    assert report["counts"] == {"PASS": 8, "PARTIAL": 1, "FAIL": 0}
    graded = rows(report)
    assert graded["contract_coverage"]["verdict"] == "PARTIAL"
    # the partial is the untyped call sites, and the artifact says so
    assert "Record<string, unknown>" in graded["contract_coverage"]["limit"]
    assert "typing" in graded["contract_coverage"]["limit"]


def test_the_console_never_calls_a_path_the_api_does_not_serve(report):
    measured = rows(report)["contract_coverage"]["measured"]
    assert measured["calls_with_no_route"] == 0
    assert measured["typed_call_sites"] > 100


def test_the_audit_trail_has_a_real_surface_and_a_rendered_test(report):
    assert AUDIT_PAGE.exists(), "the audit trail page must exist"
    assert AUDIT_TEST.exists(), "the audit trail page must have a rendered test"
    source = AUDIT_PAGE.read_text(encoding="utf-8")
    # it reads the API's own record and its chain verdict, not a client log
    assert "/api/v1/auth/audit" in source
    assert "/api/v1/auth/audit/verify" in source
    # and it never renders a verified chain it did not receive
    assert "CHAIN NOT VERIFIED" in source

    graded = rows(report)
    assert graded["auditability"]["verdict"] == "PASS"
    assert graded["auditability"]["measured"]["audit_surfaces"]


def test_the_negative_control_still_collapses_every_grade(report):
    control = report["negative_control"]
    assert control["stripped_counts"]["PASS"] == 0, (
        "a row that still passes with the behaviour stripped is not measuring it: "
        f"{control['stripped_verdicts']}"
    )
    # the trail is behaviour too: stripping it must cost the auditability row
    assert control["stripped_verdicts"]["auditability"] != "PASS"


def test_the_markdown_headline_matches_the_json(report):
    text = MARKDOWN.read_text(encoding="utf-8")
    counts = report["counts"]
    assert (f"{counts['PASS']} pass · {counts['PARTIAL']} partial · "
            f"{counts['FAIL']} fail") in text
    for behaviour in BEHAVIOURS:
        assert f"### `{behaviour}`" in text, behaviour
