"""Report distribution (email) tests — pure rendering + honest SMTP gating."""

from __future__ import annotations

from reporting.distribution import email_report, render_email


def _report(**overrides) -> dict:
    report = {
        "report_hash": "a" * 64,
        "totals": {"findings": 5, "pass": 2, "fail": 3, "warn": 0},
        "template_evaluation": {
            "summary": {"pass": 2, "fail": 3, "not_evaluated": 0, "compliant_pct": 40.0}
        },
        "payment_crypto": {
            "summary": {"keys_total": 4, "active_weak_algorithm_keys": 1,
                        "ceremonies_total": 2, "rotations_next_90d": 1},
            "findings": [{"rule_id": "PAY-001", "key_id": "key-1",
                          "blocking": True, "message": "weak algorithm"}],
            "upcoming_rotations": [{"kind": "key", "reference": "key-1",
                                    "days_left": 30, "status": "SCHEDULED"}],
        },
    }
    report.update(overrides)
    return report


class TestRenderEmail:
    def test_subject_carries_findings_and_hash(self):
        subject, _ = render_email(_report(), template_id="pci_dss",
                                  schedule_name="Quarterly PCI")
        assert "pci_dss" in subject
        assert "5 findings" in subject
        assert "3 violations" in subject
        assert "(sha256 " in subject and "…)" in subject  # truncated hash preview

    def test_body_sections(self):
        _, body = render_email(_report(), template_id="pci_dss",
                               schedule_name="Quarterly PCI")
        assert "Quarterly PCI (pci_dss)" in body
        assert "Findings: 5 (pass 2, fail 3, warn 0)" in body
        assert "40.0% compliant" in body
        assert body.count("a" * 64) == 1  # full hash once
        assert "Policy engine" in body or "policy engine" in body

    def test_payment_section_present(self):
        _, body = render_email(_report(), template_id="pci_dss",
                               schedule_name="Quarterly PCI")
        assert "Payment crypto (HSM inventory):" in body
        assert "4" in body  # keys_total
        assert "BLOCKING PAY-001 key-1" in body
        assert "upcoming rotations" in body

    def test_no_payment_data_no_section(self):
        report = _report()
        del report["payment_crypto"]
        _, body = render_email(report, template_id="pci_dss",
                               schedule_name="Quarterly PCI")
        assert "Payment crypto" not in body

    def test_signature_line_when_present(self):
        report = _report(signature={"value": "sig===", "alg": "RS256",
                                    "key_id": "k-1"})
        _, body = render_email(report, template_id="x", schedule_name="s")
        assert "PKI signature: RS256 (key k-1)" in body

    def test_signature_line_honest_when_absent(self):
        _, body = render_email(_report(), template_id="x", schedule_name="s")
        assert "PKI signature: none (no signing key configured)" in body


class TestEmailReport:
    def test_no_recipients_skipped(self):
        result = email_report(report=_report(), template_id="x", schedule_name="s",
                              recipients=[])
        assert result["status"] == "SKIPPED_NO_RECIPIENTS"

    def test_no_smtp_skipped(self):
        result = email_report(report=_report(), template_id="x", schedule_name="s",
                              recipients=["a@example.com"], smtp_host="")
        assert result["status"] == "SKIPPED_NO_SMTP"

    def test_returns_error_when_smtp_unreachable(self):
        result = email_report(report=_report(), template_id="x", schedule_name="s",
                              recipients=["a@example.com"],
                              smtp_host="127.0.0.1", smtp_port=1,
                              smtp_user="u", smtp_password="p", sender="s@example.com")
        # honest failure — never pretends delivery
        assert result["status"] == "FAILED"
        assert result.get("detail")
