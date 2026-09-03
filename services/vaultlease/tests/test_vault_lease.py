"""Deterministic vault-lease policy tests (no AI/ML; no secret storage)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


from vaultlease.lease import (
    HARD_MAX_TTL_SECONDS,
    CredentialInfo,
    LeaseDenied,
    issue_lease,
    release_lease,
    validate_lease,
)

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)


def _cred(**kw):
    base = dict(
        name="cloud-readonly",
        secret_ref="arn:aws:secretsmanager:us-east-1:123:secret:zelnx-ro-AbCd",
        status="active",
        allowed_components=frozenset({"cloud_scanner", "container_scanner"}),
        scope=frozenset({"assets:read", "findings:read"}),
        max_ttl_seconds=600,
        last_rotated_at=NOW - timedelta(days=10),
        rotation_policy_days=90,
    )
    base.update(kw)
    return CredentialInfo(**base)


def test_lease_issued_reference_only():
    r = issue_lease(_cred(), "cloud_scanner", ["assets:read"], now=NOW, ttl_seconds=300)
    assert r.allowed is True
    lease = r.lease
    assert lease.secret_ref.startswith("arn:")
    assert lease.expires_at == lease.issued_at + timedelta(seconds=300)
    # audit dict never carries key material (there is none to carry)
    assert "secret" not in lease.to_audit_dict().get("scope", [])
    assert lease.ttl_seconds == 300


def test_inactive_credential_denied():
    r = issue_lease(_cred(status="pending"), "cloud_scanner", ["assets:read"], now=NOW)
    assert r.reason == LeaseDenied.CREDENTIAL_NOT_ACTIVE.value


def test_expired_credential_denied():
    r = issue_lease(_cred(expires_at=NOW - timedelta(days=1)), "cloud_scanner",
                    ["assets:read"], now=NOW)
    assert r.reason == LeaseDenied.CREDENTIAL_EXPIRED.value


def test_rotation_overdue_denied():
    r = issue_lease(_cred(last_rotated_at=NOW - timedelta(days=200)), "cloud_scanner",
                    ["assets:read"], now=NOW)
    assert r.reason == LeaseDenied.ROTATION_OVERDUE.value


def test_component_not_allowed():
    r = issue_lease(_cred(), "unknown_scanner", ["assets:read"], now=NOW)
    assert r.reason == LeaseDenied.COMPONENT_NOT_ALLOWED.value


def test_scope_exceeded_fail_closed():
    r = issue_lease(_cred(), "cloud_scanner", ["assets:read", "secrets:write"], now=NOW)
    assert r.reason == LeaseDenied.SCOPE_EXCEEDED.value


def test_subset_scope_allowed():
    r = issue_lease(_cred(), "cloud_scanner", ["findings:read"], now=NOW)
    assert r.allowed is True


def test_ttl_capped_denies_overbroad():
    r = issue_lease(_cred(), "cloud_scanner", ["assets:read"], now=NOW,
                    ttl_seconds=HARD_MAX_TTL_SECONDS + 1)
    assert r.reason == LeaseDenied.TTL_TOO_LONG.value


def test_credential_max_ttl_below_hard_cap_enforced():
    r = issue_lease(_cred(max_ttl_seconds=120), "cloud_scanner", ["assets:read"],
                    now=NOW, ttl_seconds=300)
    assert r.reason == LeaseDenied.TTL_TOO_LONG.value


def test_inline_secret_material_in_ref_rejected():
    r = issue_lease(_cred(secret_ref="-----BEGIN PRIVATE KEY-----\nMII..."), "cloud_scanner",
                    ["assets:read"], now=NOW)
    assert r.reason == LeaseDenied.SECRET_MATERIAL_IN_REF.value


def test_malformed_ref_rejected():
    r = issue_lease(_cred(secret_ref="has space and weird!"), "cloud_scanner",
                    ["assets:read"], now=NOW)
    assert r.reason == LeaseDenied.BAD_SECRET_REF.value


def test_lease_expiry_validation():
    r = issue_lease(_cred(), "cloud_scanner", ["assets:read"], now=NOW, ttl_seconds=300)
    assert validate_lease(r.lease, now=NOW + timedelta(seconds=299)).allowed is True
    v = validate_lease(r.lease, now=NOW + timedelta(seconds=301))
    assert v.allowed is False and v.reason == LeaseDenied.LEASE_EXPIRED.value


def test_release_then_use_denied():
    r = issue_lease(_cred(), "cloud_scanner", ["assets:read"], now=NOW)
    release_lease(r.lease)
    v = validate_lease(r.lease, now=NOW)
    assert v.reason == LeaseDenied.LEASE_ALREADY_RELEASED.value


def test_empty_scope_falls_back_to_credential_scope():
    # when the component asks for nothing specific, grant exactly the credential scope
    r = issue_lease(_cred(), "cloud_scanner", [], now=NOW)
    assert r.allowed is True
    assert r.lease.scope == frozenset({"assets:read", "findings:read"})


def test_deterministic_with_pinned_handle():
    kw = dict(now=NOW, ttl_seconds=300, lease_handle="fixed-handle")
    a = issue_lease(_cred(), "cloud_scanner", ["assets:read"], **kw).as_dict()
    b = issue_lease(_cred(), "cloud_scanner", ["assets:read"], **kw).as_dict()
    assert a["lease"]["handle"] == b["lease"]["handle"] == "fixed-handle"
