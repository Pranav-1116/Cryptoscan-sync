"""Coverage and empty CBOMs: a floor is not a total, and empty is not absent.

The review's items 18 and 19. These tests pin the two sentences a CBOM must not
be able to say: "the bank has N" over a partial estate, and "there is no
cryptography" from a document nobody filled in.
"""

from __future__ import annotations

from cbom import coverage_render as cr

PARTIAL = {"systems": 100, "with_cbom": 62,
           "counts": {"NO_TARGET": 5, "NEVER_SCANNED": 25, "CURRENT": 50, "STALE": 12,
                      "FAILED": 8}}
COMPLETE = {"systems": 10, "with_cbom": 10,
            "counts": {"NO_TARGET": 0, "NEVER_SCANNED": 0, "CURRENT": 10, "STALE": 0,
                       "FAILED": 0}}


# --------------------------------------------------------------------------- #
# the coverage block


def test_a_partial_estate_is_a_floor_not_a_total():
    block = cr.inventory_coverage(PARTIAL, assets=480)
    assert block["completeness"] == "PARTIAL"
    assert block["may_report_total"] is False
    assert block["systems_inspected"] == 62 and block["systems_total"] == 100
    assert block["coverage_pct"] == 62.0
    assert block["statement"].startswith("480 crypto asset(s) discovered")
    assert "not what exists" in block["statement"]


def test_the_statement_names_the_unscanned_and_the_failed():
    block = cr.inventory_coverage(PARTIAL, assets=480)
    assert "25 never scanned" in block["statement"]
    assert "8 failed" in block["statement"]
    assert any("never scanned" in caveat for caveat in block["caveats"])
    assert any("failure is not an empty result" in caveat for caveat in block["caveats"])


def test_a_complete_estate_may_report_a_total():
    block = cr.inventory_coverage(COMPLETE, assets=40)
    assert block["completeness"] == "COMPLETE"
    assert block["may_report_total"] is True
    assert cr.quotable_counts(block)["phrasing"] == "TOTAL"


def test_an_unknown_estate_makes_no_coverage_claim():
    block = cr.inventory_coverage({}, assets=3)
    assert block["completeness"] == "UNKNOWN"
    assert block["may_report_total"] is False
    assert block["coverage_pct"] == 0.0


def test_inspected_can_never_exceed_total():
    block = cr.inventory_coverage({"systems": 5, "with_cbom": 9,
                                   "counts": {"CURRENT": 9}}, assets=1)
    assert block["systems_inspected"] == 5


def test_a_floor_count_is_phrased_with_the_coverage():
    quotable = cr.quotable_counts(cr.inventory_coverage(PARTIAL, assets=480))
    assert quotable["phrasing"] == "FLOOR"
    assert "62/100" in quotable["text"]
    assert "floor, not a total" in quotable["caveat"]


# --------------------------------------------------------------------------- #
# properties


def test_the_block_travels_in_the_document_as_a_property():
    properties = {row["name"]: row["value"]
                  for row in cr.document_properties(cr.inventory_coverage(PARTIAL, assets=480))}
    assert properties[cr.PROPERTY_COMPLETENESS] == "PARTIAL"
    assert properties[cr.PROPERTY_PCT] == "62.0"
    assert properties[cr.PROPERTY_ASSETS] == "480"
    import json

    block = json.loads(properties[cr.PROPERTY_COVERAGE])
    assert block["may_report_total"] is False
    assert block["status_counts"]["FAILED"] == 8


def test_attaching_coverage_twice_does_not_duplicate_it():
    bom = {"metadata": {}, "components": []}
    once = cr.render_coverage(bom, cr.inventory_coverage(PARTIAL, assets=2))
    twice = cr.render_coverage(once, cr.inventory_coverage(PARTIAL, assets=2))
    names = [row["name"] for row in twice["metadata"]["properties"]]
    assert names.count(cr.PROPERTY_COVERAGE) == 1
    assert bom == {"metadata": {}, "components": []}, "the input document is not mutated"


# --------------------------------------------------------------------------- #
# empty documents


def test_a_non_empty_document_has_nothing_to_explain():
    body = cr.empty_reasons(components=3)
    assert body["empty"] is False and body["reasons"] == []


def test_no_crypto_detected_requires_a_complete_inspected_scan():
    body = cr.empty_reasons(components=0, files_scanned=900, detectors_ran=5,
                            coverage_block={"completeness": "COMPLETE"})
    assert body["reasons"] == ["NO_CRYPTO_DETECTED"]
    assert body["may_conclude_no_crypto"] is True
    assert "not about the estate" in body["statement"]


def test_an_empty_document_without_a_scan_is_not_a_statement_about_crypto():
    body = cr.empty_reasons(components=0)
    assert body["reasons"] == ["NO_INVENTORY_INGESTED"]
    assert body["may_conclude_no_crypto"] is False
    assert "not evidence that no cryptography exists" in body["statement"]


def test_a_failed_scan_is_never_an_empty_result():
    body = cr.empty_reasons(components=0, errors=["scanner crashed"], files_scanned=3)
    assert body["reasons"] == ["SCAN_FAILED"]
    assert body["may_conclude_no_crypto"] is False


def test_skipped_paths_are_named():
    body = cr.empty_reasons(components=0, files_scanned=10, files_skipped=4,
                            coverage_block={"completeness": "COMPLETE"})
    assert body["reasons"] == ["PATHS_UNSUPPORTED_OR_EXCLUDED"]
    assert body["may_conclude_no_crypto"] is False


def test_an_import_with_no_detector_run_is_not_a_scan_result():
    body = cr.empty_reasons(components=0, imported=True)
    assert body["reasons"] == ["NO_INVENTORY_INGESTED"]


def test_partial_coverage_is_an_extra_reason_not_a_replacement():
    body = cr.empty_reasons(components=0, files_scanned=900, detectors_ran=2,
                            coverage_block={"completeness": "PARTIAL"})
    assert body["reasons"] == ["NO_CRYPTO_DETECTED", "COVERAGE_INCOMPLETE"]
    assert body["may_conclude_no_crypto"] is False, "a complete-per-scan but partial estate " \
                                                   "cannot support the conclusion"


def test_reasons_are_reported_in_a_stable_order():
    body = cr.empty_reasons(components=0, errors=["boom"], files_scanned=0, files_skipped=2,
                            coverage_block={"completeness": "PARTIAL"})
    assert body["reasons"] == ["PATHS_UNSUPPORTED_OR_EXCLUDED", "SCAN_FAILED",
                               "COVERAGE_INCOMPLETE"]
    assert body["reasons"] == [reason for reason in cr.EMPTY_REASONS
                               if reason in body["reasons"]]


def test_the_document_carries_the_explanation():
    bom = {"bomFormat": "CycloneDX", "metadata": {}, "components": []}
    rendered = cr.render_empty(bom, components=0, errors=["boom"], files_scanned=0)
    properties = {row["name"]: row["value"] for row in rendered["metadata"]["properties"]}
    assert properties[cr.PROPERTY_EMPTY] == "true"
    assert "SCAN_FAILED" in properties[cr.PROPERTY_EMPTY_REASONS]
    assert "not evidence that no cryptography exists" in properties[cr.PROPERTY_EMPTY_STATEMENT]
    assert bom["metadata"] == {}, "the input document is not mutated"


def test_an_empty_rendered_document_keeps_everything_else():
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"timestamp": "t"},
           "components": [], "dependencies": [{"ref": "root", "dependsOn": []}]}
    rendered = cr.render_empty(bom, components=0, files_scanned=1)
    assert rendered["dependencies"] == bom["dependencies"]
    assert rendered["specVersion"] == "1.5"
    assert rendered["metadata"]["timestamp"] == "t"


def test_a_non_empty_document_is_returned_untouched():
    bom = {"metadata": {}, "components": [{"name": "AES-256-GCM"}]}
    assert cr.render_empty(bom, components=1) == bom
