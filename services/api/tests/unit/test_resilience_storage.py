"""Production governance backups must use stable keys and a mounted store."""
from __future__ import annotations

import tempfile

import pytest
from fastapi import HTTPException

from api.config.settings import get_settings
from api.routers import resilience
from governance import keys


@pytest.fixture(autouse=True)
def _fresh_settings():
    """The API reads one cached settings object; a per-test production flip needs a
    fresh read, or these refusals would be asserted against a stale environment."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_production_report_refuses_unsigned_operator_assertions(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(HTTPException) as unverified:
        resilience.compliance_report(
            resilience.ReportRequest(framework="PCI_DSS_4", evidence={
                "tls": [{"id": "test-only", "status": "PASS"}],
            }, format="json"), user="admin",
        )
    assert unverified.value.status_code == 422


def test_production_backup_refuses_supplied_dump_and_unknown_engine(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    with pytest.raises(HTTPException) as offline:
        resilience.backup_create(
            resilience.BackupCreateRequest(database_id="test-only", engine="postgres", dump_b64="dGVzdA=="),
            db=None, user="admin",
        )
    assert offline.value.status_code == 403
    with pytest.raises(HTTPException) as unknown:
        resilience._real_backend("reference")
    assert unknown.value.status_code == 422


def test_production_restore_requires_a_named_recovery_target(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("CRYPTOSCAN_RESTORE_TARGET_DB", raising=False)
    with pytest.raises(HTTPException) as refused:
        resilience.backup_restore(resilience.BackupRestoreRequest(database_id="live-db"),
                                  db=None, user="admin")
    assert refused.value.status_code == 403
    monkeypatch.setenv("CRYPTOSCAN_RESTORE_TARGET_DB", "isolated-recovery-db")
    with pytest.raises(HTTPException) as different:
        resilience.backup_restore(resilience.BackupRestoreRequest(database_id="live-db"),
                                  db=None, user="admin")
    assert different.value.status_code == 403


def test_production_refuses_ephemeral_governance_keys(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")

    def unavailable(**_kwargs):
        raise RuntimeError("test-only unavailable vault and master key")

    monkeypatch.setattr(keys, "signing_secret", unavailable)
    monkeypatch.setattr(keys, "backup_fernet_key", unavailable)
    with pytest.raises(HTTPException) as signing:
        resilience._signing_secret()
    with pytest.raises(HTTPException) as encryption:
        resilience._fernet_key()
    assert signing.value.status_code == 503
    assert encryption.value.status_code == 503
    assert "unavailable vault" not in signing.value.detail
    assert "unavailable vault" not in encryption.value.detail


def test_production_backup_requires_explicit_live_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("BACKUP_STORAGE_DIR", raising=False)
    with pytest.raises(HTTPException, match="not provisioned"):
        resilience._backup_storage()

    missing = tmp_path / "missing"
    monkeypatch.setenv("BACKUP_STORAGE_DIR", str(missing))
    with pytest.raises(HTTPException, match="not provisioned"):
        resilience._backup_storage()
    assert not missing.exists(), "the API must not create a replacement for a missing mount"

    target = tmp_path / "backups"
    target.mkdir()
    monkeypatch.setenv("BACKUP_STORAGE_DIR", str(target))
    store = resilience._backup_storage()
    store.put("postgres/test-only/backup", b"test-only-ciphertext")
    assert resilience._backup_storage().get("postgres/test-only/backup") == b"test-only-ciphertext"


def test_production_refuses_failed_backup_readback(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("BACKUP_STORAGE_DIR", str(tmp_path))

    def unavailable(*_args, **_kwargs):
        raise OSError("test-only mount write failure")

    monkeypatch.setattr(tempfile, "TemporaryFile", unavailable)
    with pytest.raises(HTTPException, match="failed exact-byte readback"):
        resilience._backup_storage()


def test_explicit_development_backup_path_never_falls_back(tmp_path, monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "development")
    file = tmp_path / "not-a-directory"
    file.write_text("test-only")
    monkeypatch.setenv("BACKUP_STORAGE_DIR", str(file))
    with pytest.raises(HTTPException, match="configured backup directory is unavailable"):
        resilience._backup_storage()
