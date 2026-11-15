"""Rotation-staleness watch — the half of report 75's rotation story this
side owns.

Rotation happens on the vault side; what CryptoScan can see is how long
since each reference last VERIFIED. A long-running process keeps the value
it resolved at boot — a rotated-out credential is invisible until it
breaks. These tests pin the watch: policy windows per credential class,
the stale flag, the honest never-verified case, and no value leakage.
"""
from __future__ import annotations

import importlib

vault = importlib.import_module("api.security.vault")


class TestClassification:
    def test_the_three_spec_classes_and_the_default(self):
        assert vault.classify_reference("COLLECTOR_API_TOKEN") == "collector_creds"
        assert vault.classify_reference("AGENT_PASSWORD") == "collector_creds"
        assert vault.classify_reference("POSTGRES_PASSWORD") == "database"
        assert vault.classify_reference("REDIS_URL") == "database"
        assert vault.classify_reference("JWS_SIGNING_KEY") == "signing"
        assert vault.classify_reference("SMTP_PASSWORD") == "other"

    def test_policy_windows_cover_every_class(self):
        assert set(vault.ROTATION_POLICY) == {
            "collector_creds", "database", "signing", "other"}
        assert vault.ROTATION_POLICY["collector_creds"] <= 30
        assert vault.ROTATION_POLICY["signing"] <= 30


class TestStaleness:
    def setup_method(self):
        vault.RESOLUTION_LOG.records.clear()

    def test_a_reference_verified_against_its_window_is_fresh(self):
        vault.RESOLUTION_LOG.add("env", "env:TOKEN", "OK")
        last = vault.RESOLUTION_LOG.last_ok("env:TOKEN")
        assert last is not None
        # freshly verified: age 0, window 30+ -> not stale (computed by
        # secret_status; the log is the source of the age)
        from datetime import datetime, timezone

        age = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() / 86400
        assert age < 1 / 24  # verified within the last hour

    def test_the_log_remembers_only_successes_for_the_age(self):
        vault.RESOLUTION_LOG.add("env", "env:X", "FAILED")
        assert vault.RESOLUTION_LOG.last_ok("env:X") is None

    def test_never_verified_is_at_least_as_bad_as_stale(self):
        # the honest case: a reference with no successful verification has
        # no age at all — it must never read as fresh
        assert vault.RESOLUTION_LOG.last_ok("env:never") is None


class TestStatusSurface:
    def setup_method(self):
        vault.RESOLUTION_LOG.records.clear()

    def _fake_settings(self, monkeypatch, value="env:STALE_TEST_TOKEN"):
        from pydantic import BaseModel

        class FakeSettings(BaseModel):
            VAULT_PROVIDERS_DISABLED: bool = False
            VAULT_ADDR: str = ""
            VAULT_TOKEN: str = ""
            COLLECTOR_API_TOKEN: str = value

        import api.config.settings as settings_mod

        monkeypatch.setattr(settings_mod, "get_settings", lambda: FakeSettings())
        return FakeSettings

    def test_status_flags_stale_and_leaks_no_values(self, monkeypatch):
        from datetime import datetime, timedelta, timezone

        self._fake_settings(monkeypatch)
        monkeypatch.setenv("STALE_TEST_TOKEN", "super-secret-value")
        # the process has HELD its boot value for 40 days (collector window
        # is 30). Today's status probe re-reads the vault and succeeds —
        # that must NOT clear the flag: the running process still holds the
        # 40-day-old value. That is the whole point of the watch.
        old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
        vault.RESOLUTION_LOG.records.append(vault.ResolutionRecord(
            provider="env", reference="env:STALE_TEST_TOKEN",
            resolved_at=old, outcome="OK", kind="held"))

        status = vault.secret_status()
        entry = status["references"][0]
        assert entry["resolves"] is True          # the probe just succeeded
        assert entry["stale"] is True             # the HELD value is 40 days old
        assert entry["class"] == "collector_creds"
        assert entry["max_age_days"] == 30
        assert entry["value_age_days"] > 39
        assert "COLLECTOR_API_TOKEN" in status["stale_references"]
        assert status["rotation_policy"]["signing"] == 30
        # no values anywhere
        assert "super-secret-value" not in str(status)
        assert entry["reference"] == "env:STALE_TEST_TOKEN"

    def test_a_freshly_held_value_is_not_stale(self, monkeypatch):
        self._fake_settings(monkeypatch)
        monkeypatch.setenv("STALE_TEST_TOKEN", "v")
        vault.RESOLUTION_LOG.add("env", "env:STALE_TEST_TOKEN", "OK", kind="held")
        status = vault.secret_status()
        entry = status["references"][0]
        assert entry["stale"] is False
        assert status["stale_references"] == []
