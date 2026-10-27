"""VEX generation: what the engine asserts, and what it refuses to assert.

The distinction these tests protect: a CVE match the platform found is reported
``exploitable`` (that is the advisory's own claim for the matched range), while
``not_affected`` is only ever produced by an explicit operator statement with a
valid justification — never by the platform guessing about reachability.
"""

from __future__ import annotations

import pytest

from devsecops import sbom_vex as vx


def _bom(*, fixed=None, ref="pkg:npm/left-pad@1.0.0"):
    vuln = {"id": "CVE-2024-0001", "ratings": [{"severity": "high"}],
            "affects": [{"ref": ref}]}
    if fixed:
        vuln["affects"][0]["versions"] = [{"version": fixed, "status": "unaffected"}]
        vuln["recommendation"] = f"upgrade to {fixed} or later"
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"timestamp": "2026-09-01T00:00:00Z", "authors": [{"name": "ci"}],
                         "component": {"type": "application", "name": "payment-api",
                                       "bom-ref": "root"}},
            "components": [{"type": "library", "name": "left-pad", "version": "1.0.0",
                            "bom-ref": ref, "purl": ref}],
            "vulnerabilities": [vuln]}


def test_match_is_exploitable_with_remediation():
    rows = vx.statements(_bom(fixed="1.1.0"))
    assert len(rows) == 1
    row = rows[0]
    assert row["state"] == "exploitable"
    assert row["fixed_version"] == "1.1.0"
    assert row["response"] == ["update"]
    assert row["source"] == "derived"
    assert "1.1.0" in row["detail"]
    # the platform does not invent a justification for an exploitable finding
    assert row["justification"] is None


def test_match_without_a_fix_is_in_triage_not_a_guess():
    row = vx.statements(_bom())[0]
    assert row["state"] == "in_triage"
    assert row["response"] == ["can_not_fix"]
    assert row["fixed_version"] is None
    assert "no fixed version recorded" in row["detail"]


def test_absent_vulnerable_component_is_provably_not_affected():
    bom = _bom()
    # the advisory is about a version this document does not contain, so the
    # affected component is provably absent
    bom["vulnerabilities"][0]["affects"] = [{"ref": "pkg:npm/left-pad@0.0.1"}]
    row = vx.statements(bom)[0]
    assert row["state"] == "not_affected"
    assert row["justification"] == "code_not_present"
    assert row["affected_components"] == []


def test_operator_override_is_honoured_and_attributed():
    rows = vx.statements(_bom(), analyses={"CVE-2024-0001": {
        "state": "not_affected", "justification": "code_not_reachable",
        "detail": "parser entry point is never called", "response": ["will_not_fix"]}})
    row = rows[0]
    assert row["state"] == "not_affected" and row["source"] == "operator"
    assert row["justification"] == "code_not_reachable"
    assert row["response"] == ["will_not_fix"]
    assert "never called" in row["detail"]


def test_not_affected_without_a_justification_is_refused():
    # CycloneDX requires a justification — an unexplained "not affected" is the
    # rubber stamp VEX exists to prevent.
    with pytest.raises(ValueError) as exc:
        vx.statements(_bom(), analyses={"CVE-2024-0001": {"state": "not_affected"}})
    assert "requires a justification" in str(exc.value)
    # and the enum is enforced instead of being passed through
    with pytest.raises(ValueError):
        vx.statements(_bom(), analyses={"CVE-2024-0001": {"state": "definitely_fine"}})
    with pytest.raises(ValueError):
        vx.statements(_bom(), analyses={"CVE-2024-0001": {"state": "not_affected",
                                                          "justification": "vibes"}})
    with pytest.raises(ValueError):
        vx.statements(_bom(), analyses={"CVE-2024-0001": {"state": "resolved",
                                                          "response": ["ignore_it"]}})


def test_empty_document_produces_no_statements():
    assert vx.statements({}) == []
    assert vx.counts([]) == {}
    assert "No advisories" in vx.render_markdown([])


def test_vex_document_is_a_valid_cyclonedx_shape():
    document = vx.build_vex_document(_bom(fixed="1.1.0"), author="analyst")
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["serialNumber"].startswith("urn:uuid:")
    entry = document["vulnerabilities"][0]
    assert entry["id"] == "CVE-2024-0001"
    assert entry["analysis"]["state"] == "exploitable"
    assert entry["affects"] == [{"ref": "pkg:npm/left-pad@1.0.0"}]
    assert entry["recommendation"] == "upgrade to 1.1.0 or later"
    # the target component travels with the document so a consumer knows what
    # the statements are about
    assert document["metadata"]["component"]["name"] == "payment-api"
    assert document["compositions"][0]["vulnerabilities"] == ["CVE-2024-0001"]


def test_vex_markdown_names_the_action():
    markdown = vx.render_markdown(vx.statements(_bom(fixed="1.1.0")), target="payment-api")
    assert "# VEX statements — payment-api" in markdown
    assert "| CVE-2024-0001 | HIGH | exploitable | — | left-pad@1.0.0 | upgrade to 1.1.0 |" in markdown
