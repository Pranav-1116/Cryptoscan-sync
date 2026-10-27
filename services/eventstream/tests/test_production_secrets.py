"""The event journal and CBOM signer must not use development keys in prod."""

from __future__ import annotations

import pytest

from eventstream.bus import StreamBus
from eventstream.livecbom import LiveCbomService


def test_stream_bus_rejects_implicit_development_secret_in_production(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("STREAM_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="STREAM_SECRET"):
        StreamBus(tmp_path / "events")


def test_live_cbom_rejects_implicit_development_secret_in_production(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CBOM_SIGNING_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="CBOM_SIGNING_SECRET"):
        LiveCbomService(tmp_path / "cbom")
