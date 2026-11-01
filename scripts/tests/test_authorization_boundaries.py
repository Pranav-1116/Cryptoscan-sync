"""The authorization boundary drill: declarations, decisions, and the comparator.

The drill is slow (it sends a few thousand requests), so these tests drive the
pieces that can be wrong in a quiet way — the declaration reader, the comparator,
the public-path classifier — and then run the whole thing once to assert the
matrix has no violation and no escape.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _module():
    sys.path.insert(0, str(ROOT / "scripts"))
    import authorization_boundaries  # noqa: PLC0415

    return authorization_boundaries


@pytest.fixture(scope="module")
def report() -> dict:
    return _module().measure()


def test_the_comparator_can_report_a_violation():
    module = _module()
    requirement = module.Requirement("permission", frozenset({"superadmin"}), ["x"])
    assert module._violation(requirement, "readonly", 200)
    assert not module._violation(requirement, "readonly", 403)
    assert not module._violation(requirement, "superadmin", 200)


def test_a_session_requirement_allows_any_authenticated_role():
    module = _module()
    requirement = module.Requirement("session", frozenset())
    assert requirement.allows("readonly")
    assert not module._violation(requirement, "readonly", 200)


def test_tenant_guards_are_not_compared_as_catalog_roles():
    module = _module()
    requirement = module.Requirement("tenant-role", frozenset(), ["require_tenant_roles"], False)
    assert requirement.comparable is False


def test_public_paths_are_exempted_and_the_safety_switch_is_not_swept():
    module = _module()
    assert module._public("/api/v1/auth/login")
    assert module._public("/api/v1/webhooks/github")
    assert not module._public("/api/v1/assets")
    assert module.DESTRUCTIVE.search("/api/v1/network/crypto-stop")
    assert module.DESTRUCTIVE.search("/api/v1/network/crypto-safety")
    assert not module.DESTRUCTIVE.search("/api/v1/assets")


def test_declarations_resolve_to_roles():
    module = _module()
    module._prepare_environment()
    operations = module.declared_requirements()
    guarded = [op for op in operations if op["kind"] != "session"]
    assert guarded, "no operation declares a guard — the walk is broken"
    assert any(op["kind"] == "permission" and op["allowed_roles"] for op in operations)
    assert all(op["comparable"] for op in operations
               if op["kind"] in {"role", "permission"})


def test_no_principal_escapes_its_declaration(report):
    assert report["schema"] == "cryptoscan.authorization-boundaries/1"
    for row in report["rows"]:
        if row["id"].startswith("boundary_"):
            assert row["verdict"] == "PASS", row
    assert report["counts"]["FAIL"] == 0, [
        (row["id"], [p for p in row["probes"] if not p["ok"]]) for row in report["rows"]
    ]


def test_a_write_without_a_session_is_refused(report):
    row = next(r for r in report["rows"] if r["id"] == "anonymous_refused")
    assert row["verdict"] == "PASS", row["allowed"]
    assert row["allowed"] == []


def test_a_foreign_signed_token_gets_nowhere(report):
    row = next(r for r in report["rows"] if r["id"] == "forged_credentials")
    assert row["verdict"] == "PASS", row["allowed"]


def test_a_read_only_principal_cannot_write(report):
    """The old row reported the session-only write surface and graded PARTIAL.

    It is now a measured ceiling: read-only roles are refused on every mutating
    method outside self-service, which the drill executes per principal.
    """
    row = next(r for r in report["rows"] if r["id"] == "session_only_writes")
    assert row["verdict"] == "PASS", row["probes"]
    names = {probe["probe"] for probe in row["probes"]}
    assert {"viewer-cannot-write", "auditor-cannot-write",
            "writes-not-blanket-refused", "self-service-exempt",
            "attestation-exempt", "comparator-can-fail"} <= names
    assert row["viewer_open"] == [], "a write open to a viewer would still be a gap"
    # Every probe must be able to fail: the observed text is the measurement.
    assert all(probe["observed"] for probe in row["probes"])


def test_target_authorization_is_enforced_server_side(report):
    row = next(r for r in report["rows"] if r["id"] == "target_authorization")
    assert row["verdict"] == "PASS", row["probes"]
    names = {probe["probe"] for probe in row["probes"]}
    assert {"no-scope-fails-closed", "scope-rejects-cidr", "scope-rejects-metadata",
            "out-of-scope-host-refused"} <= names
