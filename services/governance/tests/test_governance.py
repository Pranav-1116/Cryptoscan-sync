"""Deterministic governance approval + migration validation tests (no AI)."""

from __future__ import annotations

from governance.migration_validate import (
    MigrationSnapshot,
    validate_migration,
)
from governance.rules import (
    ChangeRequest,
    Decision,
    RiskLevel,
    can_decide,
    evaluate,
)


# ------------------------------------------------------------ approvals
def test_low_risk_report_export_auto_approved():
    res = evaluate(ChangeRequest(request_type="report_export", requested_by="analyst"))
    assert res.decision is Decision.AUTO_APPROVED
    assert res.risk_level is RiskLevel.LOW


def test_executable_plugin_requires_approval_and_window():
    res = evaluate(ChangeRequest(
        request_type="plugin_enable_executable",
        requested_by="dev",
        in_maintenance_window=False,
        has_valid_ticket=False,
    ))
    assert res.decision is Decision.REQUIRES_APPROVAL
    assert res.risk_level is RiskLevel.HIGH
    assert "security-approver" in res.required_approvers
    assert any(r["rule"] == "maintenance-window" for r in res.rules)


def test_secret_material_is_denied():
    res = evaluate(ChangeRequest(
        request_type="config_change",
        requested_by="dev",
        payload={"api_secret": "AKIA...", "secret_ref": None},
    ))
    assert res.decision is Decision.DENIED
    assert "secret" in res.rationale.lower()


def test_secret_reference_is_not_denied():
    res = evaluate(ChangeRequest(
        request_type="credential_reference_change",
        requested_by="dev",
        payload={"vault_secret_ref": "vault://payments/key"},
    ))
    assert res.decision is not Decision.DENIED


def test_high_risk_with_ticket_in_window_still_needs_approver_sod():
    res = evaluate(ChangeRequest(
        request_type="policy_exception",
        requested_by="dev",
        in_maintenance_window=True,
        has_valid_ticket=True,
    ))
    assert res.decision is Decision.REQUIRES_APPROVAL
    # SoD: a high-risk change always needs a separate security approver
    assert "security-approver" in res.required_approvers


def test_can_decide_role_coverage():
    assert can_decide(["admin"], ["security-approver", "risk-officer"]) is True
    assert can_decide(["security-approver"], ["security-approver", "risk-officer"]) is False
    assert can_decide(["security-approver", "risk-officer"], ["security-approver", "risk-officer"]) is True


def test_decision_is_deterministic():
    req = ChangeRequest(request_type="scope_grant", requested_by="x", has_valid_ticket=False)
    assert evaluate(req).as_dict() == evaluate(req).as_dict()


# ------------------------------------------------------------ migration
def _finding(algo, path, system="s1"):
    return {"algorithm": algo, "file_path": path, "line_number": 10, "system_id": system}


def test_migration_pass_when_deprecated_remediated_no_regression():
    pre = MigrationSnapshot.from_findings(
        [_finding("DES", "a.java"), _finding("AES", "b.java")],
        covered_assets={"s1", "s2"},
    )
    post = MigrationSnapshot.from_findings(
        [_finding("AES", "b.java")],  # DES gone
        covered_assets={"s1", "s2"},
    )
    res = validate_migration(pre, post)
    assert res.passed is True
    assert any(r["algorithm"] == "DES" for r in res.remediated)


def test_migration_fails_when_deprecated_remains():
    pre = MigrationSnapshot.from_findings([_finding("DES", "a.java")], {"s1"})
    post = MigrationSnapshot.from_findings([_finding("DES", "a.java")], {"s1"})
    res = validate_migration(pre, post)
    assert res.passed is False
    assert any(r["kind"] == "deprecated_remaining" for r in res.regressions)


def test_migration_fails_on_new_finding_regression():
    pre = MigrationSnapshot.from_findings([_finding("AES", "b.java")], {"s1"})
    post = MigrationSnapshot.from_findings(
        [_finding("AES", "b.java"), _finding("RSA-1024", "new.java")], {"s1"}
    )
    res = validate_migration(pre, post)
    assert res.passed is False
    assert any(r["kind"] == "new_weak_finding" for r in res.regressions)


def test_migration_algorithm_upgrade_at_same_location_passes():
    # DES -> AES-GCM at the same file/line is a remediation, not a regression
    pre = MigrationSnapshot.from_findings([_finding("DES", "a.java")], {"s1"})
    post = MigrationSnapshot.from_findings([_finding("AES-GCM", "a.java")], {"s1"})
    res = validate_migration(pre, post)
    assert res.passed is True
    assert any(r["algorithm"] == "DES" for r in res.remediated)


def test_migration_fails_on_coverage_loss():
    pre = MigrationSnapshot.from_findings([_finding("AES", "b.java")], {"s1", "s2"})
    post = MigrationSnapshot.from_findings([_finding("AES", "b.java")], {"s1"})
    res = validate_migration(pre, post)
    assert res.passed is False
    assert res.coverage_delta["lost_assets"] == ["s2"]
