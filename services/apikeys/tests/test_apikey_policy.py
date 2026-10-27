"""Deterministic API-key platform policy tests (scopes, methods, quota)."""

from __future__ import annotations

import pytest
from apikeys.policy import (
    DenyReason,
    FixedWindowQuota,
    KeyPolicy,
    authorize,
    normalize_methods,
    normalize_rate,
    normalize_scopes,
    path_in_scope,
)


# ------------------------------------------------------------ normalization
def test_normalize_scopes_accepts_relative_and_full_paths():
    assert normalize_scopes(["/findings", "scans/123"]) == ["/findings", "/scans/123"]
    assert normalize_scopes(["/api/v1/runtime"]) == ["/runtime"]
    assert normalize_scopes(None) == []
    assert normalize_scopes("/findings,/assets") == ["/findings", "/assets"]


def test_normalize_scopes_rejects_bad_paths():
    with pytest.raises(ValueError):
        normalize_scopes(["not a path"])
    with pytest.raises(ValueError):
        normalize_scopes(["/find ings"])


def test_normalize_methods_and_rate():
    assert normalize_methods(["get", "POST"]) == ["GET", "POST"]
    assert normalize_methods(None) == []
    with pytest.raises(ValueError):
        normalize_methods(["BREW"])
    assert normalize_rate(120) == 120
    assert normalize_rate(0) == 0
    with pytest.raises(ValueError):
        normalize_rate(-1)
    assert normalize_rate(10**9) == 1_000_000  # capped


# ------------------------------------------------------------ scope matching
def test_empty_scopes_unrestricted():
    assert path_in_scope("/api/v1/anything", []) is True
    assert path_in_scope("/api/v1/anything", None) is True


def test_scope_prefix_boundary():
    scopes = ["/findings"]
    assert path_in_scope("/api/v1/findings", scopes) is True
    assert path_in_scope("/api/v1/findings/123/ack", scopes) is True
    # must not grant a sibling resource
    assert path_in_scope("/api/v1/findingsx", scopes) is False
    assert path_in_scope("/api/v1/scans", scopes) is False


def test_method_allowlist():
    from apikeys.policy import method_allowed

    assert method_allowed("get", ["GET"]) is True
    assert method_allowed("POST", ["GET"]) is False
    assert method_allowed("POST", []) is True  # no restriction


# ------------------------------------------------------------ authorize
def _key(**kw):
    return KeyPolicy(
        scopes=tuple(kw.get("scopes", ())),
        methods=tuple(kw.get("methods", ("GET", "POST"))),
        rate_per_minute=kw.get("rate", 0),
    )


def test_authorize_allows_in_scope_get():
    res = authorize(key_id="k", method="GET", path="/api/v1/findings",
                    policy=_key(scopes=("/findings",)))
    assert res.allowed is True and res.reason is None


def test_authorize_denies_out_of_scope():
    res = authorize(key_id="k", method="GET", path="/api/v1/scans",
                    policy=_key(scopes=("/findings",)))
    assert res.allowed is False and res.reason is DenyReason.SCOPE


def test_authorize_denies_method():
    res = authorize(key_id="k", method="DELETE", path="/api/v1/findings",
                    policy=_key(scopes=("/findings",), methods=("GET",)))
    assert res.allowed is False and res.reason is DenyReason.METHOD


def test_authorize_quota_fixed_window():
    q = FixedWindowQuota()
    pol = _key(rate=2)
    t0 = 1000.0
    r1 = authorize(key_id="k", method="GET", path="/api/v1/findings", policy=pol, quota=q, now=t0)
    r2 = authorize(key_id="k", method="GET", path="/api/v1/findings", policy=pol, quota=q, now=t0)
    r3 = authorize(key_id="k", method="GET", path="/api/v1/findings", policy=pol, quota=q, now=t0)
    assert r1.allowed and r2.allowed
    assert r3.allowed is False and r3.reason is DenyReason.QUOTA
    # window resets after 60s
    r4 = authorize(key_id="k", method="GET", path="/api/v1/findings", policy=pol, quota=q, now=t0 + 61)
    assert r4.allowed is True


def test_quota_zero_means_unlimited():
    q = FixedWindowQuota()
    pol = _key(rate=0)
    for i in range(100):
        r = authorize(key_id="k", method="GET", path="/x", policy=pol, quota=q, now=10.0)
        assert r.allowed
