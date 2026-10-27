"""License compliance engine: inventory, classification, policy verdicts.

The engine must never present a policy trigger as a legal ruling, so the tests
pin down both what it claims and what it refuses to claim.
"""

from __future__ import annotations

from devsecops.sbom_license import (check_license_policy, classify, license_inventory,
                                    normalize_expression, render_license_report)


def _cdx(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": components}


def _comp(name, version, licenses=None):
    comp = {"type": "library", "name": name, "version": version, "bom-ref": f"pkg:npm/{name}@{version}"}
    if licenses is not None:
        comp["licenses"] = licenses
    return comp


def test_normalize_expression_splits_spdx_operators():
    assert [e["id"] for e in normalize_expression("MIT OR Apache-2.0")] == ["MIT", "Apache-2.0"]
    assert [e["id"] for e in normalize_expression("(MIT AND BSD-3-Clause)")] == ["MIT", "BSD-3-Clause"]
    with_exception = normalize_expression("GPL-2.0-only WITH Classpath-exception-2.0")
    assert with_exception == [{"id": "GPL-2.0-only", "base": "GPL-2.0-only",
                               "exception": "Classpath-exception-2.0"}]
    # de-duplicated, and nothing invented for ambiguous input
    assert [e["id"] for e in normalize_expression("MIT or mit")] == ["MIT"]
    for empty in ("", None, "NOASSERTION", "NONE", "UNKNOWN"):
        assert normalize_expression(empty) == []


def test_classify_license_families():
    assert classify("AGPL-3.0-only") == "strong_copyleft"
    assert classify("GPL-3.0-or-later") == "strong_copyleft"
    assert classify("LGPL-2.1-only") == "weak_copyleft"
    assert classify("MPL-2.0") == "weak_copyleft"
    assert classify("Apache-2.0") == "permissive"
    assert classify("MIT") == "permissive"
    assert classify("LicenseRef-Proprietary") == "proprietary"
    assert classify("SomeVendor-EULA") == "unknown"
    assert classify("") == "unknown"


def test_inventory_groups_licenses_and_surfaces_undeclared():
    bom = _cdx([
        _comp("a", "1.0.0", [{"license": {"id": "MIT"}}]),
        _comp("b", "1.0.0", [{"license": {"id": "MIT"}}]),
        _comp("c", "1.0.0", [{"expression": "Apache-2.0 OR MIT"}]),
        _comp("d", "1.0.0"),                       # declares nothing
    ])
    inventory = license_inventory(bom)
    by_id = {row["spdx_id"]: row for row in inventory["licenses"]}
    assert by_id["MIT"]["count"] == 3          # a, b and c's OR clause
    assert by_id["Apache-2.0"]["count"] == 1
    assert inventory["distinct_licenses"] == 2
    assert inventory["component_count"] == 4
    assert inventory["undeclared"] == [{"component": "d", "version": "1.0.0"}]
    # an undeclared license is never classified as permitted or denied
    assert inventory["classes"] == {"permissive": 4}


def test_inventory_reads_spdx_documents():
    bom = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
           "documentNamespace": "https://x", "dataLicense": "CC0-1.0",
           "packages": [
               {"SPDXID": "SPDXRef-Package-a", "name": "a", "versionInfo": "1",
                "licenseDeclared": "GPL-3.0-only"},
               {"SPDXID": "SPDXRef-Package-b", "name": "b", "versionInfo": "2",
                "licenseDeclared": "NOASSERTION", "licenseConcluded": "MIT"}]}
    inventory = license_inventory(bom)
    assert {row["spdx_id"] for row in inventory["licenses"]} == {"GPL-3.0-only", "MIT"}
    assert inventory["undeclared"] == []       # concluded license counts as declared


def test_policy_fails_on_forbidden_and_reviews_on_restricted():
    bom = _cdx([
        _comp("a", "1.0.0", [{"license": {"id": "AGPL-3.0-only"}}]),
        _comp("b", "1.0.0", [{"license": {"id": "LGPL-2.1-only"}}]),
        _comp("c", "1.0.0", [{"license": {"id": "MIT"}}]),
    ])
    clean = check_license_policy(bom)
    assert clean["verdict"] == "PASS"          # no policy configured -> nothing denied

    strict = check_license_policy(bom, policy={"forbidden": ["AGPL-3.0-only"],
                                               "restricted": ["LGPL-2.1-only"]})
    assert strict["verdict"] == "FAIL"
    codes = [v["code"] for v in strict["violations"]]
    assert codes == ["LICENSE-FORBIDDEN", "LICENSE-RESTRICTED"]
    assert "a" in strict["violations"][0]["detail"]

    # restricted alone is a review, not a failure
    review = check_license_policy(bom, policy={"forbidden": [], "restricted": ["LGPL-2.1-only"]})
    assert review["verdict"] == "REVIEW"


def test_policy_require_declared_and_copyleft_review_trigger():
    bom = _cdx([
        _comp("agpl-lib", "1.0.0", [{"license": {"id": "AGPL-3.0-only"}}]),
        _comp("mystery", "1.0.0"),             # no license at all
    ])
    report = check_license_policy(bom, policy={"require_declared": True})
    assert report["verdict"] == "REVIEW"
    codes = {v["code"] for v in report["violations"]}
    assert "LICENSE-UNDECLARED" in codes
    assert "LICENSE-REVIEW-COPYLEFT" in codes
    conflict = report["conflicts"][0]
    # the wording must be a policy trigger, never a compatibility ruling
    assert "not a compatibility ruling" in conflict["detail"]
    assert "no license" in conflict["detail"]

    # the review trigger is switchable off, and fires only when a copyleft
    # license really is combined with something unresolved
    quiet = check_license_policy(bom, policy={"require_declared": True, "review_copyleft": False})
    assert "LICENSE-REVIEW-COPYLEFT" not in {v["code"] for v in quiet["violations"]}
    tidy = check_license_policy(_cdx([_comp("agpl-lib", "1", [{"license": {"id": "AGPL-3.0-only"}}]),
                                      _comp("mit-lib", "1", [{"license": {"id": "MIT"}}])]))
    assert tidy["verdict"] == "PASS" and tidy["conflicts"] == []


def test_license_report_markdown_is_auditable():
    bom = _cdx([_comp("a", "1.0.0", [{"license": {"id": "MIT"}}]), _comp("b", "2.0.0")])
    report = check_license_policy(bom, policy={"require_declared": True})
    markdown = render_license_report(report)
    assert "License verdict: **REVIEW**" in markdown
    assert "| MIT | permissive | 1 |" in markdown
    assert "Undeclared licenses (1): b" in markdown
    assert "LICENSE-UNDECLARED" in markdown
