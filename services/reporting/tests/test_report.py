from reporting.compliance_report import render_html, render_json


def test_report_json_and_html():
    report = render_json(
        scan={"target_location": "local://demo"},
        findings=[
            {
                "compliance_status": "FAIL",
                "policy_evaluation": {
                    "rules_evaluated": [
                        {"rule_id": "BASELINE-001", "evaluation_result": "FAIL", "standard_reference": "NIST"}
                    ]
                },
            }
        ],
        agility={"score": 40},
        quantum={"overall_hndl_risk": "HIGH"},
        gate={"decision": "FAIL"},
    )
    assert report["totals"]["fail"] == 1
    html = render_html(report)
    assert "BASELINE-001" not in html or "NIST" in html
    assert "CryptoScan compliance report" in html
    assert "HIGH" in html
