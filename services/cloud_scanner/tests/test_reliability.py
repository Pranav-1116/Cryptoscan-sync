"""Reliability layer tests: throttle retry, pagination, telemetry verdicts.

Enterprise contract under test — a configured-but-failing live scan must be
reported as FAILED, never as an empty success; caps must be recorded as
truncations instead of silently shrinking the estate.
"""

from __future__ import annotations

import pytest

from cloud_scanner.aws.scanners import _list
from cloud_scanner.config.settings import load_settings
from cloud_scanner.core import scanner as scanner_mod
from cloud_scanner.core.reliability import (
    MAX_RETRIES,
    ScanTelemetry,
    call_with_retry,
    cap_items,
    is_throttle_error,
    paginate,
)
from cloud_scanner.core.scanner import CloudScanner


# --------------------------------------------------------------------------
# throttle classification & retry
# --------------------------------------------------------------------------


class FakeThrottle(Exception):
    pass


def test_throttle_markers_recognised():
    assert is_throttle_error(FakeThrottle("Rate exceeded: Throttling"))
    assert is_throttle_error(FakeThrottle("too many requests"))
    exc = FakeThrottle("boom")
    exc.status_code = 503
    assert is_throttle_error(exc)


def test_non_throttle_error_is_not_retryable():
    assert not is_throttle_error(ValueError("bad parameter"))


def test_call_with_retry_succeeds_first_try():
    calls = []

    def call():
        calls.append(1)
        return ["item"]

    ok, value, error = call_with_retry(call, sleep=lambda _s: None)
    assert (ok, value, error) == (True, ["item"], None)
    assert len(calls) == 1


def test_call_with_retry_recovers_from_throttle():
    calls = []

    def call():
        calls.append(1)
        if len(calls) < 2:
            raise FakeThrottle("ThrottlingException")
        return "ok"

    ok, value, error = call_with_retry(call, sleep=lambda _s: None)
    assert ok and value == "ok" and error is None
    assert len(calls) == 2


def test_call_with_retry_gives_up_after_max_retries():
    calls = []

    def call():
        calls.append(1)
        raise FakeThrottle("slow down")

    ok, value, error = call_with_retry(call, sleep=lambda _s: None)
    assert not ok and value is None and error is not None
    assert len(calls) == MAX_RETRIES + 1


def test_call_with_retry_does_not_retry_hard_errors():
    calls = []

    def call():
        calls.append(1)
        raise ValueError("AuthFailure")

    ok, _value, error = call_with_retry(call, sleep=lambda _s: None)
    assert not ok and isinstance(error, ValueError)
    assert len(calls) == 1


# --------------------------------------------------------------------------
# pagination
# --------------------------------------------------------------------------


def test_paginate_walks_every_page():
    pages = [
        {"Keys": [{"Id": "1"}, {"Id": "2"}], "NextToken": "t1"},
        {"Keys": [{"Id": "3"}]},
    ]

    def list_call(**kwargs):
        assert kwargs.get("NextToken") in (None, "t1")
        return pages[0] if not kwargs.get("NextToken") else pages[1]

    items, truncated = paginate(list_call, items_key="Keys", max_items=10)
    assert [i["Id"] for i in items] == ["1", "2", "3"]
    assert truncated is False


def test_paginate_records_truncation_at_cap():
    pages = [
        {"Keys": [{"Id": str(n)} for n in range(5)], "NextToken": "t1"},
        {"Keys": [{"Id": "9"}]},
    ]

    def list_call(**kwargs):
        return pages[0] if not kwargs.get("NextToken") else pages[1]

    items, truncated = paginate(list_call, items_key="Keys", max_items=3)
    assert len(items) == 3
    assert truncated is True


class PagedClient:
    """Fake boto3-style client paging an items key with NextToken."""

    def __init__(self, pages):
        self._pages = pages
        self.calls = 0

    def list_things(self, **kwargs):
        self.calls += 1
        token = kwargs.get("NextToken")
        if token is None:
            return self._pages[0]
        return self._pages[int(token)]


def test__list_walks_pages_and_stops_at_cap_with_truncation():
    pages = [
        {"Things": [{"Id": str(n)} for n in range(3)], "NextToken": "1"},
        {"Things": [{"Id": "3"}, {"Id": "4"}]},  # last page, but cap hits first
    ]
    client = PagedClient(pages)
    telemetry = ScanTelemetry(max_resources=4)
    items = _list(
        client,
        "list_things",
        items_key="Things",
        telemetry=telemetry,
        service="things",
        region="us-east-1",
    )
    assert len(items) == 4  # cap enforced
    assert telemetry.truncations == [
        {"provider": "AWS", "service": "things", "region": "us-east-1", "cap": "4"}
    ]
    assert telemetry.resources_scanned == 4
    assert telemetry.errors == []


def test__list_retries_throttled_first_call():
    class ThrottledClient(PagedClient):
        def list_things(self, **kwargs):
            if self.calls == 0:
                self.calls += 1
                raise FakeThrottle("Throttling: rate exceeded")
            return PagedClient.list_things(self, **kwargs)

    client = ThrottledClient([{"Things": [{"Id": "1"}]}])
    telemetry = ScanTelemetry()
    items = _list(
        client,
        "list_things",
        items_key="Things",
        telemetry=telemetry,
        service="things",
        region="us-east-1",
    )
    assert items == [{"Id": "1"}]
    assert telemetry.errors == []
    assert telemetry.status() in {"OK", "PARTIAL"}


def test__list_records_error_when_call_never_succeeds():
    class BrokenClient:
        def list_things(self, **kwargs):
            raise ValueError("AuthFailure")

    telemetry = ScanTelemetry()
    items = _list(
        BrokenClient(),
        "list_things",
        items_key="Things",
        telemetry=telemetry,
        service="things",
        region="us-east-1",
    )
    assert items == []
    assert len(telemetry.errors) == 1
    assert telemetry.errors[0]["code"] == "ValueError"


# --------------------------------------------------------------------------
# telemetry verdicts
# --------------------------------------------------------------------------


def _attempted(telemetry, resources=0, errors=0):
    telemetry.providers_attempted.add("AWS")
    telemetry.record_resources(resources)
    for index in range(errors):
        telemetry.record_error("AWS", "svc", "us-east-1", ValueError(f"e{index}"))
    return telemetry


def test_verdict_skipped_when_nothing_attempted():
    assert ScanTelemetry().status() == "SKIPPED"


def test_verdict_ok_when_clean_scan():
    assert _attempted(ScanTelemetry(), resources=3).status() == "OK"


def test_verdict_partial_when_some_errors_but_results():
    telemetry = _attempted(ScanTelemetry(), resources=3, errors=1)
    assert telemetry.status() == "PARTIAL"


def test_verdict_failed_when_configured_but_everything_errored():
    telemetry = _attempted(ScanTelemetry(), resources=0, errors=2)
    assert telemetry.status() == "FAILED"
    assert telemetry.total_failure is True


def test_summary_counts_beyond_display_cap():
    telemetry = ScanTelemetry()
    telemetry.providers_attempted.add("AWS")
    for index in range(60):
        telemetry.record_error("AWS", "svc", "us-east-1", ValueError(f"e{index}"))
    summary = telemetry.summary(enabled=True)
    assert len(summary["errors"]) == 50  # display cap
    assert summary["error_count"] == 60  # true count
    assert summary["status"] == "FAILED"


# --------------------------------------------------------------------------
# scan_live integration: telemetry surfaces in the result
# --------------------------------------------------------------------------


def test_scan_live_reports_failed_not_empty_success(monkeypatch):
    def boom(**kwargs):
        raise PermissionError("credentials rejected")

    monkeypatch.setattr(scanner_mod, "scan_aws", boom)
    result = CloudScanner(live=False).scan_live(providers=["AWS"])
    assert result["resources"] == 0
    live_scan = result["live_scan"]
    assert live_scan["status"] == "FAILED"
    assert live_scan["error_count"] >= 1
    assert live_scan["errors"][0]["provider"] == "AWS"
    assert live_scan["resources_scanned"] == 0


def test_scan_live_reports_partial_on_mixed_providers(monkeypatch):
    monkeypatch.setattr(
        scanner_mod,
        "scan_aws",
        lambda **kwargs: [{"algorithm": "AES", "metadata": {"cloud_provider": "AWS"}}],
    )

    def boom(**kwargs):
        raise PermissionError("no subscription")

    monkeypatch.setattr(scanner_mod, "scan_azure", boom)
    result = CloudScanner(live=False).scan_live(providers=["AWS", "AZURE"])
    assert result["resources"] == 1
    assert result["live_scan"]["status"] == "PARTIAL"
    assert result["live_scan"]["resources_scanned"] == 1
    assert result["live_scan"]["error_count"] == 1


def test_scan_live_reports_ok_on_clean_scan(monkeypatch):
    monkeypatch.setattr(
        scanner_mod,
        "scan_aws",
        lambda **kwargs: [{"algorithm": "AES", "metadata": {"cloud_provider": "AWS"}}],
    )
    monkeypatch.setattr(scanner_mod, "scan_azure", lambda **kwargs: [])
    monkeypatch.setattr(scanner_mod, "scan_gcp", lambda **kwargs: [])
    result = CloudScanner(live=False).scan_live()
    assert result["live_scan"]["status"] == "OK"


def test_scan_live_max_resources_env_override(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_CLOUD_MAX_RESOURCES", "123")
    monkeypatch.setattr(scanner_mod, "scan_aws", lambda **kwargs: [])
    monkeypatch.setattr(scanner_mod, "scan_azure", lambda **kwargs: [])
    monkeypatch.setattr(scanner_mod, "scan_gcp", lambda **kwargs: [])
    result = CloudScanner(live=False).scan_live()
    assert result["live_scan"]["resources_scanned"] == 0  # cap flowed through cleanly

    monkeypatch.setenv("CRYPTOSCAN_CLOUD_MAX_RESOURCES", "not-a-number")
    assert scanner_mod._max_resources() == 500  # garbage falls back to default


# --------------------------------------------------------------------------
# production configuration gate
# --------------------------------------------------------------------------


def test_production_live_scan_requires_credentials(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CRYPTOSCAN_CLOUD_LIVE", "1")
    for name in (
        "AWS_ACCESS_KEY_ID",
        "AWS_PROFILE",
        "AWS_ROLE_ARN",
        "CRYPTOSCAN_AWS_ROLE_ARN",
        "AZURE_SUBSCRIPTION_ID",
        "CRYPTOSCAN_AZURE_SUBSCRIPTION",
        "GOOGLE_CLOUD_PROJECT",
        "GCP_PROJECT",
    ):
        monkeypatch.delenv(name, raising=False)
    settings = load_settings()
    assert settings.live is True
    with pytest.raises(Exception) as excinfo:
        settings.validate_for_production()
    assert "credential" in str(excinfo.value).lower()


def test_production_live_scan_passes_with_credentials(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("CRYPTOSCAN_CLOUD_LIVE", "1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIATEST")
    settings = load_settings()
    settings.validate_for_production()  # must not raise


def test_non_production_never_gated(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("CRYPTOSCAN_CLOUD_LIVE", "1")
    for name in ("AWS_ACCESS_KEY_ID", "AZURE_SUBSCRIPTION_ID", "GOOGLE_CLOUD_PROJECT"):
        monkeypatch.delenv(name, raising=False)
    load_settings().validate_for_production()  # must not raise


# --------------------------------------------------------------------------
# cap_items + region truncation + filesystem telemetry propagation
# --------------------------------------------------------------------------


def test_cap_items_records_truncation_only_when_dropped():
    telemetry = ScanTelemetry(max_resources=3)
    kept = cap_items([1, 2, 3], telemetry=telemetry, provider="AWS", service="s3", region="r")
    assert kept == [1, 2, 3]
    assert telemetry.truncations == []
    trimmed = cap_items([1, 2, 3, 4, 5], telemetry=telemetry, provider="AWS", service="s3", region="r")
    assert trimmed == [1, 2, 3]
    assert telemetry.truncations == [{"provider": "AWS", "service": "s3", "region": "r", "cap": "3"}]


def test_cap_items_without_telemetry_uses_default():
    items = list(range(10))
    assert cap_items(items, telemetry=None, provider="AWS", service="s3", region="r", default=4) == items[:4]


def test_discovered_region_cap_records_truncation(monkeypatch):
    from cloud_scanner.aws.live import _regions

    class Session:
        @staticmethod
        def get_available_regions(service):
            return [f"us-fake-{i}" for i in range(10)]

    telemetry = ScanTelemetry()
    regions = _regions(Session(), None, telemetry=telemetry)
    assert len(regions) == 8  # default discovered cap
    assert telemetry.truncations == [{"provider": "AWS", "service": "regions", "region": "discovered", "cap": "8"}]

    monkeypatch.setenv("CRYPTOSCAN_CLOUD_MAX_REGIONS", "12")
    telemetry2 = ScanTelemetry()
    assert len(_regions(Session(), None, telemetry2)) == 10  # all regions fit
    assert telemetry2.truncations == []


def test_requested_region_cap_records_truncation(monkeypatch):
    from cloud_scanner.aws.live import _regions

    requested = [f"eu-fake-{i}" for i in range(20)]
    telemetry = ScanTelemetry()
    regions = _regions(None, requested, telemetry=telemetry)
    assert len(regions) == 16  # default requested cap
    assert telemetry.truncations == [{"provider": "AWS", "service": "regions", "region": "requested", "cap": "16"}]


def test_scan_filesystem_propagates_live_scan_telemetry(monkeypatch, tmp_path):
    monkeypatch.setattr(
        CloudScanner,
        "scan_live",
        lambda self, **kwargs: {
            "findings": [{"algorithm": "AES", "metadata": {"cloud_provider": "AWS"}}],
            "resources": 1,
            "live_scan": {"enabled": True, "status": "PARTIAL", "resources_scanned": 1, "errors": [], "truncations": [], "error_count": 0, "truncation_count": 0},
        },
    )
    result = CloudScanner(live=True).scan_filesystem(tmp_path)
    assert result["live"] is True
    assert result["live_scan"]["status"] == "PARTIAL"
    assert result["resources"] == 1


def test_scan_filesystem_offline_has_no_live_scan_block(tmp_path):
    result = CloudScanner(live=False).scan_filesystem(tmp_path)
    assert result["live"] is False
    assert "live_scan" not in result
