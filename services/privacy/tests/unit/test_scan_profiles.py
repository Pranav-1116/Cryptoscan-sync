"""Scan Profile resolver tests (spec #8)."""

from __future__ import annotations

import pytest

from privacy.profiles import get_profile, resolve_profile, SCAN_PROFILES


def test_profiles_have_sanctioned_ids():
    for pid in ("bank-production", "healthcare-production", "cloud-audit",
                "pqc-discovery", "low-impact", "deep-assessment", "ot-safe"):
        assert pid in SCAN_PROFILES


def test_bank_production_resolves_read_only_minimal():
    r = resolve_profile("bank-production", sector="banking")
    pol = r["policy"]
    assert pol.scan.mode == "read-only"
    assert pol.scan.intensity == "low"
    assert pol.scan.production_protection is True
    assert pol.privacy.collect_secrets is False
    assert pol.privacy.collect_pii is False
    assert pol.privacy.redact_secrets is True


def test_sector_never_loosened_after_profile():
    # a deep-assessment profile (high intensity) on a banking sector must be
    # clamped back down to the sector's read-only / low-safe posture
    r = resolve_profile("deep-assessment", sector="banking")
    pol = r["policy"]
    # banking sector forces read-only + treat-prod-protection; the profile's
    # controlled_active/high must be overridden by the sector (never loosens)
    assert pol.scan.mode == "read-only"
    assert pol.scan.production_protection is True


def test_ot_safe_passive():
    r = resolve_profile("ot-safe", sector="energy")
    pol = r["policy"]
    assert pol.scan.mode == "read-only"
    assert pol.privacy.collect_secrets is False
    assert r["limits"].requests_per_second <= 2  # energy clamps qps down


def test_limits_clamp_down_never_up():
    # even a "deep-assessment" profile requesting qps 20 stays within the
    # ambient limit default (20) and is not raised
    r = resolve_profile("deep-assessment")
    assert r["limits"].requests_per_second <= 20


def test_unknown_profile_raises():
    with pytest.raises(KeyError):
        get_profile("does-not-exist")


def test_profile_to_dict_shape():
    p = get_profile("cloud-audit")
    d = p.to_dict()
    assert d["mode"] == "read-only"
    assert d["schedule"] == "on_change"
    assert "limit" in d and "scope" in d
