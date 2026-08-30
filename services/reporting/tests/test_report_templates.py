"""Audit-ready report templates: evaluation, attestation, tamper hash."""

from __future__ import annotations

from reporting.compliance_report import render_html, render_json
from reporting.report_templates import (
    canonical_hash,
    evaluate_template,
    template_ids,
    template_metadata,
)


def _finding(rule_id, standard, result, path="src/Pay.java", line=7, algorithm="DES"):
    return {
        "algorithm": algorithm,
        "file_path": path,
        "line_number": line,
        "compliance_status": "FAIL" if result == "FAIL" else "PASS",
        "policy_evaluation": {
            "rules_evaluated": [
                {"rule_id": rule_id, "standard_reference": standard, "evaluation_result": result}
            ]
        },
    }


def test_template_registry_lists_all_six_plus_custom():
    ids = template_ids()
    assert ids == sorted(ids)
    for expected in ("custom", "dora", "fips-140-3", "iso-27001", "nist-sp-800-131a", "pci-dss-4.0", "soc2"):
        assert expected in ids
    meta = {row["id"]: row for row in template_metadata()}
    assert meta["soc2"]["source"] == "mapped" and meta["soc2"]["mapping_note"]
    assert meta["pci-dss-4.0"]["source"] == "native"


def test_pci_evaluation_pass_fail_and_evidence_chain():
    findings = [
        _finding("PCIDSS-005", "PCI-DSS 4.0 req. 4.2.1", "FAIL", path="net/Tls.java", line=3, algorithm="TLS-1.0"),
        _finding("PCIDSS-004", "PCI-DSS 4.0 req. 8.3.2", "PASS", algorithm="PBKDF2"),
    ]
    result = evaluate_template(findings, "pci-dss-4.0")
    by_id = {row["id"]: row for row in result["requirements"]}
    assert by_id["4.2.1"]["status"] == "FAIL"
    assert by_id["4.2.1"]["failure_locations"] == ["net/Tls.java:3"]
    assert by_id["8.3.2"]["status"] == "PASS"
    assert by_id["3.5.1"]["status"] == "NOT_EVALUATED"  # honest: nothing touched it
    assert result["summary"]["fail"] == 1 and result["summary"]["not_evaluated"] == 6  # 2 estate + 4 payment (-pay) requirements lack evidence here


def test_custom_selection_and_rejections():
    findings = [_finding("BASELINE-004", "Internal Security Baseline", "FAIL")]
    custom = evaluate_template(findings, "custom", requirements=["CC6.1", "A.8.24"])
    assert [row["id"] for row in custom["requirements"]] == ["CC6.1", "A.8.24"]
    assert custom["template"]["source"] == "custom"
    for bad in (
        lambda: evaluate_template([], "custom"),
        lambda: evaluate_template([], "custom", requirements=["nope"]),
        lambda: evaluate_template([], "not-a-template"),
    ):
        try:
            bad()
            raised = False
        except ValueError:
            raised = True
        assert raised


def test_hash_is_deterministic_and_detects_tampering():
    body = {"b": 2, "a": [1, {"x": None}]}
    first = canonical_hash(body)
    assert first == canonical_hash({"a": [1, {"x": None}], "b": 2})  # key order irrelevant
    assert first != canonical_hash({"b": 3, "a": [1, {"x": None}]})


def test_render_json_with_template_attaches_attestation_and_hash():
    scan = {"id": "scan-1", "target_location": "https://github.com/org/app.git"}
    findings = [_finding("PCIDSS-005", "PCI-DSS 4.0 req. 4.2.1", "FAIL")]
    report = render_json(
        scan=scan, findings=findings, template_id="pci-dss-4.0", policy_pack_hash="packhash123"
    )
    assert report["template_evaluation"]["summary"]["fail"] == 1
    assert report["attestation"]["policy_pack_hash"] == "packhash123"
    assert report["attestation"]["signature"] is None  # no fake PKI
    # the recorded hash reproduces from the body — and catches tampering
    body = {k: v for k, v in report.items() if k != "report_hash"}
    assert canonical_hash(body) == report["report_hash"]
    body["totals"]["fail"] = 0
    assert canonical_hash(body) != report["report_hash"]
    # without a template the report shape is unchanged (back-compat)
    plain = render_json(scan=scan, findings=findings)
    assert "report_hash" not in plain and "template_evaluation" not in plain


def test_render_html_includes_requirement_table():
    scan = {"id": "scan-1", "target_location": "org/app"}
    findings = [_finding("PCIDSS-005", "PCI-DSS 4.0 req. 4.2.1", "FAIL")]
    report = render_json(scan=scan, findings=findings, template_id="pci-dss-4.0")
    page = render_html(report)
    assert "PCI-DSS 4.0" in page and "<td>4.2.1</td>" in page and "<td>FAIL</td>" in page
    assert report["report_hash"] in page and "Attestation:" in page
