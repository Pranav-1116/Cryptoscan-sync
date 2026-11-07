"""Deprecation/sunset policy tests (gap-analysis §B: API maturity).

A deprecated endpoint is a promise: successor + reason + sunset trail,
never a silent removal. The registry holds the product's REAL withdrawn
family — the /api/v1/enterprise/airgap/* routes (2026-10-31)."""

from __future__ import annotations

from datetime import date

import pytest

from api.deprecation import (
    DEPRECATIONS, DEPRECATED, WITHDRAWN, headers_for, may_remove,
    register_deprecation,
)


def _record(**over):
    base = dict(path="/api/v1/thing", state=DEPRECATED,
                announced_at="2026-11-01", sunset_at="2027-03-01",
                successor="use /api/v1/thing-v2", reason="superseded by v2",
                successor_doc="/docs/thing-v2.md")
    base.update(over)
    return register_deprecation(**base)


def test_a_successor_is_mandatory():
    with pytest.raises(ValueError):
        _record(successor="")
    with pytest.raises(ValueError):
        _record(successor_doc="")


def test_a_reason_is_mandatory_no_silent_removals():
    with pytest.raises(ValueError) as exc:
        _record(reason="")
    assert "silent removal" in str(exc.value)


def test_sunset_cannot_precede_the_announcement():
    with pytest.raises(ValueError):
        _record(announced_at="2026-11-01", sunset_at="2026-10-31")
    with pytest.raises(ValueError):
        _record(announced_at="not-a-date", sunset_at="2027-03-01")
    with pytest.raises(ValueError):
        _record(state="REMOVED")


def test_headers_are_the_rfc_8594_lifecycle_trail():
    record = _record()
    headers = record.headers()
    assert headers["Deprecation"] == "true"
    assert "Sunset" in headers and "GMT" in headers["Sunset"]
    assert headers["Link"] == "</docs/thing-v2.md>; rel=\"successor-version\""


def test_removal_only_after_sunset_and_only_with_successor_and_reason():
    record = _record(announced_at="2026-11-01", sunset_at="2026-11-30")
    assert may_remove(record, now=date(2026, 11, 30)) is False
    assert may_remove(record, now=date(2026, 12, 1)) is True


def test_the_registry_holds_the_real_airgap_family_never_fakes():
    expected = {
        "/api/v1/enterprise/airgap/bundle",
        "/api/v1/enterprise/airgap/export",
        "/api/v1/enterprise/airgap/import",
    }
    assert set(DEPRECATIONS) == expected
    for record in DEPRECATIONS.values():
        assert record.state == WITHDRAWN
        # real withdrawal date (commit ad7c3f59), not invented dates
        assert record.announced_at == "2026-10-31"
        assert record.sunset_at == "2026-10-31"
        assert record.successor and record.reason
        assert "cryptoscan bundle export" in record.successor
        assert "could not be audited" in record.reason
        assert headers_for(record.path)["Deprecation"] == "true"
    # live endpoints carry no lifecycle headers
    assert headers_for("/api/v1/assets") == {}
