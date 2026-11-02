"""Component completeness: unmeasured is not clean, and partial is not complete.

A component with no findings is only "a component without cryptography" if
something finished looking. The tests below are about the three claims that must
never render the same way — nobody looked, somebody stopped early, everybody
looked and agreed — and about the total that may be quoted from them.
"""

from __future__ import annotations

from cbom import inventory_completeness as ic

SYFT = {"task": "syft-sbom", "status": "COMPLETE"}
SEMGREP = {"task": "semgrep-crypto", "status": "COMPLETE"}
FINDING = {"task": "semgrep-crypto", "algorithm": "AES-128-CBC", "evidence_id": "EV-1"}


def _component(tasks, claims=(), name="payments"):
    return ic.component(claims, tasks, name=name)


# --------------------------------------------------------------------------- #
# the four readings


def test_a_component_nobody_scanned_is_unmeasured():
    result = _component([], [])
    assert result["state"] == "UNMEASURED"
    assert result["quotable"] is False
    assert "nobody looked" in result["reading"]
    assert "never inspected" in result["statement"]


def test_a_component_whose_task_timed_out_is_incomplete_whatever_was_found():
    result = _component([SEMGREP, {"task": "syft-sbom", "status": "TIMEOUT"}], [FINDING])
    assert result["state"] == "INCOMPLETE"
    assert result["quotable"] is False
    assert [row["task"] for row in result["unfinished_tasks"]] == ["syft-sbom"]
    assert "did not finish" in result["statement"]


def test_a_component_every_task_finished_on_and_found_nothing_is_empty():
    result = _component([SYFT, SEMGREP])
    assert result["state"] == "EMPTY"
    assert result["quotable"] is True
    assert "which is a measurement" in result["statement"]


def test_a_component_with_agreement_is_complete():
    result = _component([SEMGREP], [FINDING])
    assert result["state"] == "COMPLETE"
    assert result["quotable"] is True
    assert result["algorithms"] == ["AES-128-CBC"]


def test_the_reading_explains_what_an_absence_means_in_each_state():
    for state in ic.STATES:
        assert state in ic.READING and ic.READING[state]
    assert "not evidence of absence" in ic.READING["UNMEASURED"]


# --------------------------------------------------------------------------- #
# contradictions


def test_a_task_reporting_nothing_while_another_finds_something_is_a_contradiction():
    syft_says_clean = {"task": "syft-sbom", "status": "COMPLETE", "found": False}
    result = _component([syft_says_clean, SEMGREP], [FINDING])
    assert result["state"] == "CONTRADICTED"
    assert result["quotable"] is False
    contradiction = result["contradictions"][0]
    assert contradiction["kind"] == "REPORTED_EMPTY_AND_FOUND"
    assert contradiction["empty_from"] == "syft-sbom"
    assert contradiction["found_by"] == ["semgrep-crypto"]
    assert contradiction["evidence_ids"] == ["EV-1"]


def test_the_contradiction_is_not_a_majority_vote():
    syft_says_clean = {"task": "syft-sbom", "status": "COMPLETE", "found": False}
    trivy_says_clean = {"task": "trivy", "status": "COMPLETE", "found": False}
    result = _component([syft_says_clean, trivy_says_clean, SEMGREP], [FINDING])
    assert result["state"] == "CONTRADICTED"
    assert len(result["contradictions"]) == 2


def test_two_tasks_agreeing_on_a_finding_are_one_algorithm_with_both_evidences():
    other = {"task": "syft-sbom", "algorithm": "AES-128-CBC", "evidence_id": "EV-2"}
    result = _component([SYFT, SEMGREP], [FINDING, other])
    assert result["state"] == "COMPLETE"
    entry = result["by_algorithm"][0]
    assert entry["tasks"] == ["semgrep-crypto", "syft-sbom"]
    assert entry["evidence_ids"] == ["EV-1", "EV-2"]


def test_an_unfinished_task_stops_the_state_before_a_contradiction_is_considered():
    syft_says_clean = {"task": "syft-sbom", "status": "COMPLETE", "found": False}
    result = _component([syft_says_clean, SEMGREP,
                         {"task": "trivy", "status": "FAILED"}], [FINDING])
    assert result["state"] == "INCOMPLETE"
    assert result["contradictions"]  # recorded, but the state is the weaker claim


# --------------------------------------------------------------------------- #
# claims that cannot be weighed


def test_a_finding_from_a_task_that_did_not_finish_is_a_candidate():
    result = _component([{"task": "semgrep-crypto", "status": "TIMEOUT"}], [FINDING])
    assert result["findings"] == []
    assert result["candidates"][0]["algorithm"] == "AES-128-CBC"
    assert "not quotable" in result["candidates"][0]["reason"]


def test_a_finding_from_a_task_that_never_ran_is_refused():
    result = _component([SYFT], [{"task": "gitleaks", "algorithm": "RSA-2048",
                                  "evidence_id": "EV-3"}])
    assert result["refused"][0]["algorithm"] == "RSA-2048"
    assert "never ran" in result["refused"][0]["reason"]


def test_a_finding_with_no_evidence_id_is_refused():
    result = _component([SEMGREP], [{"task": "semgrep-crypto",
                                     "algorithm": "AES-128-CBC"}])
    assert "no evidence id" in result["refused"][0]["reason"]


def test_a_finding_with_no_task_cannot_be_weighed():
    result = _component([SEMGREP], [{"algorithm": "AES-128-CBC", "evidence_id": "EV-1"}])
    assert "names no task" in result["refused"][0]["reason"]


def test_a_claim_that_is_not_an_object_is_refused():
    result = _component([SEMGREP], ["AES-128-CBC"])
    assert result["refused"][0]["reason"] == "a claim must be an object"


def test_a_task_with_no_status_is_unfinished():
    result = _component([{"task": "half-run"}], [])
    assert result["state"] == "INCOMPLETE"
    assert result["unfinished_tasks"][0]["status"] == "UNKNOWN"


def test_finished_status_spellings_are_recognised():
    for status in ("COMPLETE", "OK", "SUCCESS", "DONE", "FINISHED"):
        assert _component([{"task": "t", "status": status}])["state"] == "EMPTY", status


def test_unfinished_status_spellings_are_recognised():
    for status in ("TIMEOUT", "FAILED", "SKIPPED", "CANCELLED", "PARTIAL", "RUNNING"):
        assert _component([{"task": "t", "status": status}])["state"] == "INCOMPLETE"


# --------------------------------------------------------------------------- #
# the inventory total


def _inventory(*components):
    return ic.inventory(components)


def test_a_total_may_only_be_quoted_when_every_component_is_complete():
    partial = _inventory(_component([SEMGREP], [FINDING], name="a"),
                         _component([], [], name="b"))
    assert partial["may_report_total"] is False
    assert partial["statement"].endswith("no total may be quoted for the inventory")
    assert "2 component(s): 1 complete" in partial["statement"]
    assert "1 unmeasured" in partial["statement"]
    assert partial["unmeasurable"] == ["b"]


def test_a_fully_complete_inventory_may_quote_its_total():
    complete = _inventory(_component([SEMGREP], [FINDING], name="a"),
                          _component([SEMGREP], [FINDING], name="b"))
    assert complete["may_report_total"] is True
    assert complete["complete_share"] == 100.0
    assert "a total may be quoted" in complete["statement"]


def test_a_measured_empty_component_makes_a_total_quotable():
    """Empty is a finding, not a gap: every task finished and none found anything."""
    result = _inventory(_component([SEMGREP], [], name="a"),
                        _component([SEMGREP], [FINDING], name="b"))
    assert result["measured"] == 2
    assert result["counts"]["EMPTY"] == 1
    assert result["may_report_total"] is True
    assert result["complete_share"] == 50.0


def test_an_empty_inventory_quotes_nothing():
    result = ic.inventory([])
    assert result["components"] == 0
    assert result["may_report_total"] is False
    assert result["complete_share"] == 0.0


def test_the_inventory_counts_every_state():
    result = _inventory(_component([], [], name="unmeasured"),
                        _component([{"task": "t", "status": "TIMEOUT"}], name="incomplete"),
                        _component([SEMGREP], [], name="empty"),
                        _component([SEMGREP], [FINDING], name="complete"))
    assert result["counts"] == {"COMPLETE": 1, "CONTRADICTED": 0, "EMPTY": 1,
                                "INCOMPLETE": 1, "UNMEASURED": 1}
    # complete and measured-empty are both quotable; incomplete and unmeasured are not
    assert result["quotable"] == 2
