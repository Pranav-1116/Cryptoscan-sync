"""Database encryption: tenant-bound ciphertext at rest, TLS in transit."""

from __future__ import annotations

import base64
import os

import pytest

from db import encryption
from db.encryption import DecryptionError, protect, unprotect

KEY1 = base64.b64encode(bytes(range(32))).decode()
KEY2 = base64.b64encode(bytes(range(32, 64))).decode()


@pytest.fixture(autouse=True)
def ring(monkeypatch):
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS", raising=False)
    encryption.reset_ring()
    yield
    monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS", raising=False)
    encryption.reset_ring()


def _set_keys(monkeypatch, value):
    monkeypatch.setenv("EVIDENCE_ENCRYPTION_KEYS", value)
    encryption.reset_ring()


class TestEnvelope:

    def test_round_trip_and_the_row_is_ciphertext(self, monkeypatch):
        _set_keys(monkeypatch, f"2026q1:{KEY1}")
        stored = protect(b"artifact-bytes", tenant_id="tenant_001")
        assert stored.startswith(b"enc1:"), "stored rows are self-describing"
        assert b"artifact-bytes" not in stored
        assert unprotect(stored, tenant_id="tenant_001") == b"artifact-bytes"

    def test_ciphertext_is_tenant_bound(self, monkeypatch):
        _set_keys(monkeypatch, f"2026q1:{KEY1}")
        stored = protect(b"artifact-bytes", tenant_id="tenant_001")
        with pytest.raises(DecryptionError, match="wrong tenant"):
            unprotect(stored, tenant_id="tenant_002")

    def test_tampered_bytes_never_reach_a_pipeline(self, monkeypatch):
        _set_keys(monkeypatch, f"2026q1:{KEY1}")
        stored = protect(b"artifact-bytes", tenant_id="t")
        payload = stored[:len(stored) - 2] + b"00" if not stored.endswith(b"00") \
            else stored[:len(stored) - 2] + b"ff"
        with pytest.raises(DecryptionError):
            unprotect(payload, tenant_id="t")

    def test_a_wrong_key_id_is_refused_not_guessed(self, monkeypatch):
        _set_keys(monkeypatch, f"2026q1:{KEY1}")
        stored = protect(b"artifact-bytes", tenant_id="t")
        _set_keys(monkeypatch, f"2026q2:{KEY2}")  # old key gone
        with pytest.raises(DecryptionError):
            unprotect(stored, tenant_id="t")

    def test_rotation_keeps_old_rows_readable(self, monkeypatch):
        _set_keys(monkeypatch, f"2026q1:{KEY1}")
        old = protect(b"artifact-bytes", tenant_id="t")
        _set_keys(monkeypatch, f"2026q2:{KEY2},2026q1:{KEY1}")  # new primary
        fresh = protect(b"artifact-bytes", tenant_id="t")
        assert unprotect(old, tenant_id="t") == b"artifact-bytes"
        assert unprotect(fresh, tenant_id="t") == b"artifact-bytes"
        assert b"2026q2" in fresh, "the primary encrypts; the ring decrypts"


class TestFailClosed:

    def test_development_without_keys_stores_plaintext_and_says_so(self, monkeypatch):
        monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS", raising=False)
        encryption.reset_ring()
        stored = protect(b"artifact-bytes", tenant_id="t")
        assert stored == b"artifact-bytes"
        status = encryption.encryption_status()
        assert status["configured"] is False
        assert "UNENCRYPTED" in status["note"]

    def test_production_without_keys_refuses_to_store(self, monkeypatch):
        monkeypatch.delenv("EVIDENCE_ENCRYPTION_KEYS", raising=False)
        encryption.reset_ring()
        with pytest.raises(ValueError, match="UNENCRYPTED in production"):
            protect(b"artifact-bytes", tenant_id="t", is_production=True)

    def test_a_malformed_key_ring_fails_loudly(self, monkeypatch):
        short = base64.b64encode(b"tiny").decode()  # valid base64, wrong size
        _set_keys(monkeypatch, f"kid:{short}")
        with pytest.raises(ValueError, match="32 bytes"):
            encryption.get_ring()
        _set_keys(monkeypatch, "kid:not-base64-at-all!!")
        with pytest.raises(ValueError, match="unparsable"):
            encryption.get_ring()


class TestTransit:

    def test_production_refuses_unencrypted_database_hops(self, monkeypatch):
        from db.connection.engine import create_db_engine

        monkeypatch.setenv("ENVIRONMENT", "production")
        with pytest.raises(ValueError, match="encrypted in transit"):
            create_db_engine(
                "postgresql+psycopg2://u:p@db:5432/cryptoscan?sslmode=prefer")
        engine = create_db_engine(
            "postgresql+psycopg2://u:p@db:5432/cryptoscan?sslmode=require")
        engine.dispose()  # TLS-required hop builds

    def test_development_keeps_libpq_default(self, monkeypatch):
        from db.connection.engine import create_db_engine

        monkeypatch.setenv("ENVIRONMENT", "development")
        engine = create_db_engine("sqlite://")
        engine.dispose()
