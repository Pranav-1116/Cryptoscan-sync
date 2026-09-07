"""Tests for deterministic key derivation/provisioning and the scheduled backup
sweep (worker-tick). Deterministic; no network, no real DB server."""
import datetime as dt
import os

import pytest

from governance import keys, backup_jobs as bj, backup_schedule as bs
from governance import backup as bk


class FakeSettings:
    def __init__(self, values=None):
        self._d = dict(values or {})
        self.sets = []

    def get(self, key, default=None):
        return self._d.get(key, default)

    def set(self, key, value, updated_by=None):
        self._d[key] = value
        self.sets.append((key, updated_by))


class FakeRunner:
    def __call__(self, argv, stdin=None):
        tool = argv[0].split("/")[-1]
        if "dump" in tool or "backup" in argv:
            return bj.CommandResult(0, b"DUMP-BYTES", b"")
        return bj.CommandResult(0, b"", b"")


def test_signing_key_derived_deterministically_from_master(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "a-fixed-platform-master-secret")
    monkeypatch.delenv("GOVERNANCE_SIGNING_KEY_REF", raising=False)
    a = keys.signing_secret()
    b = keys.signing_secret()
    assert a == b and len(a) == 64  # hex sha256
    # different master -> different key
    monkeypatch.setenv("SECRET_KEY", "a-different-master-secret")
    assert keys.signing_secret() != a


def test_fernet_key_is_valid_and_stable(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("SECRET_KEY", "stable-master")
    k1 = keys.backup_fernet_key(); k2 = keys.backup_fernet_key()
    assert k1 == k2
    Fernet(k1)  # raises if invalid


def test_vault_ref_used_when_present(monkeypatch):
    monkeypatch.setenv("GOVERNANCE_SIGNING_KEY_REF", "vault://resilience/signing")
    monkeypatch.setenv("VAULT_SECRET_RESILIENCE_SIGNING", "vault-loaded-secret")
    assert keys.signing_secret() == "vault-loaded-secret"


def test_missing_master_fails_closed(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("GOVERNANCE_MASTER_KEY", raising=False)
    monkeypatch.delenv("GOVERNANCE_SIGNING_KEY_REF", raising=False)
    with pytest.raises(RuntimeError):
        keys.signing_secret()


def test_provision_keys_persists_and_idempotent(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "m")
    s = FakeSettings()
    first = keys.provision_keys(s, created_by="admin")
    assert first["signing"] is True and first["encryption"] is True
    second = keys.provision_keys(s, created_by="admin")
    assert second["signing"] is False and second["encryption"] is False
    # persisted key is then preferred over derivation
    assert keys.signing_secret(settings_repo=s) == s.get("governance.signing_secret")


def test_backup_sweep_runs_due_persists_schedule_and_retention(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "sweep-master")
    settings = FakeSettings({bs.SETTING_KEY: [
        {"database_id": "proddb", "engine": "postgres", "interval_hours": 24},
        {"database_id": "graphdb", "engine": "neo4j", "interval_hours": 24},
    ]})
    storage = bj.InMemoryBackupStorage()

    def backend_for(engine):
        return bj.Neo4jBackend(runner=FakeRunner()) if engine == "neo4j" else bj.PgDumpBackend(runner=FakeRunner())

    now = dt.datetime(2026, 9, 7, tzinfo=dt.timezone.utc)
    out = bs.run_due_backups_sweep(settings_repo=settings, backend_for=backend_for,
                                   storage=storage, encryption_key=keys.backup_fernet_key(),
                                   signing_secret=keys.signing_secret(), now=now)
    assert out["backed_up"] == 2 and out["failed"] == 0
    assert len(storage.list_manifests()) == 2
    # schedule persisted with last_run_at -> second sweep skips
    saved = settings.get(bs.SETTING_KEY)
    assert all(c["last_run_at"] for c in saved)
    out2 = bs.run_due_backups_sweep(settings_repo=settings, backend_for=backend_for,
                                    storage=storage, encryption_key=keys.backup_fernet_key(),
                                    signing_secret=keys.signing_secret(),
                                    now=now + dt.timedelta(hours=1))
    assert all(o["status"] == "SKIPPED_NOT_DUE" for o in out2["outcomes"])
    # after interval elapses, runs again
    out3 = bs.run_due_backups_sweep(settings_repo=settings, backend_for=backend_for,
                                    storage=storage, encryption_key=keys.backup_fernet_key(),
                                    signing_secret=keys.signing_secret(),
                                    now=now + dt.timedelta(hours=25))
    assert out3["backed_up"] == 2


def test_backup_sweep_isolates_failure(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "m")
    settings = FakeSettings({bs.SETTING_KEY: [
        {"database_id": "good", "engine": "postgres"},
        {"database_id": "bad", "engine": "postgres"},
    ]})
    storage = bj.InMemoryBackupStorage()

    def backend_for(engine):
        be = bj.PgDumpBackend(runner=FakeRunner())
        return be

    # make one backup fail by giving the 'bad' db an unsafe name -> BackupError
    settings._d[bs.SETTING_KEY][1]["database_id"] = "bad db;"

    out = bs.run_due_backups_sweep(settings_repo=settings, backend_for=backend_for,
                                   storage=storage, encryption_key=bk.generate_encryption_key(),
                                   signing_secret="s")
    assert out["backed_up"] == 1 and out["failed"] == 1
