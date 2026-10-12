"""Threat-intel feed sync (deep/30 feeds layer, round 35)."""

from __future__ import annotations

from vendor_intel.threat_intel import build_advisory_bundle, sync_feed, sync_feeds

SECRET = "feed-secret-for-tests"

ADVISORIES = [{
    "advisory_id": "ORG-2026-001",
    "source": "org-feed",
    "advisory_type": "DEPRECATION",
    "algorithm": "RSA-2048",
    "severity": "HIGH",
    "title": "RSA-2048 deprecation schedule",
    "published_at": "2026-09-01T00:00:00Z",
}]


class _Response:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


def _bundle():
    return build_advisory_bundle(ADVISORIES, secret=SECRET)


def test_sync_feed_verifies_and_extracts():
    result = sync_feed("https://feed.example/bundle", secret=SECRET,
                       fetch=lambda url, timeout: _Response(body=_bundle()))
    assert result["ok"] is True
    assert len(result["entries"]) == 1
    assert result["entries"][0]["advisory_id"] == "ORG-2026-001"


def test_sync_feed_rejects_tampered_bundle():
    bundle = _bundle()
    bundle["package"]["advisories"][0]["advisory_id"] = "TAMPERED-001"  # hash now wrong
    result = sync_feed("https://feed.example/bundle", secret=SECRET,
                       fetch=lambda url, timeout: _Response(body=bundle))
    assert result["ok"] is False
    assert "bundle rejected" in result["error"]


def test_sync_feed_reports_transport_failures():
    # wrong secret -> rejected, nothing extracted
    result = sync_feed("https://feed.example/bundle", secret="wrong",
                       fetch=lambda url, timeout: _Response(body=_bundle()))
    assert result["ok"] is False and "rejected" in result["error"]
    # non-200
    result = sync_feed("https://feed.example/x", secret=SECRET,
                       fetch=lambda url, timeout: _Response(status_code=503, body={}))
    assert result["ok"] is False and "503" in result["error"]
    # not JSON
    result = sync_feed("https://feed.example/x", secret=SECRET,
                       fetch=lambda url, timeout: _Response())
    assert result["ok"] is False and "not JSON" in result["error"]
    # fetch raises
    def _boom(url, timeout):
        raise ConnectionError("no route")
    result = sync_feed("https://feed.example/x", secret=SECRET, fetch=_boom)
    assert result["ok"] is False and "fetch failed" in result["error"]
    # unconfigured
    assert sync_feed("", secret=SECRET)["ok"] is False
    assert sync_feed("https://x", secret="")["ok"] is False


def test_sync_feeds_one_bad_feed_never_blocks_the_others():
    feeds = [{"name": "good", "url": "https://good.example"},
             {"name": "bad", "url": "https://bad.example"}]

    def _fetch(url, timeout):
        if "good" in url:
            return _Response(body=_bundle())
        return _Response(status_code=500, body={})

    result = sync_feeds(feeds, secret=SECRET, fetch=_fetch)
    assert result["feeds_total"] == 2 and result["feeds_ok"] == 1
    assert result["results"][0] == {"feed": "good", "ok": True, "entries": 1}
    assert result["results"][1]["ok"] is False
    assert len(result["entries"]) == 1
