"""Backup encryption: AES-256-GCM + scrypt, manifest keeps plaintext digest (audits 15/16).

Covers scripts/backup_crypto.py helpers directly plus an end-to-end
backup -> encrypt -> restore round trip through the real script mains.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS = REPO_ROOT / "scripts"


def _load(name: str):
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))  # scripts import _bootstrap / each other
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def backup_crypto():
    return _load("backup_crypto")


@pytest.fixture(scope="module")
def seed_db(tmp_path_factory):
    """A small real SQLite store the backup script can copy."""
    path = tmp_path_factory.mktemp("backup-enc") / "cryptoscan.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT);
        CREATE TABLE scans (id TEXT PRIMARY KEY, status TEXT);
        CREATE TABLE evidence_records (id TEXT PRIMARY KEY, content_hash TEXT);
        CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT);
        CREATE TABLE system_assets (id INTEGER PRIMARY KEY);
        CREATE TABLE jobs (id INTEGER PRIMARY KEY);
        INSERT INTO evidence_records VALUES ('e-1', 'aa');
        """
    )
    conn.commit()
    conn.close()
    return path


def test_round_trip_encrypt_decrypt(backup_crypto):
    key = b"x" * 32
    blob = backup_crypto.encrypt_bytes(b"evidence-bytes", key)
    assert blob[:5] == b"CSBC1"
    assert backup_crypto.decrypt_bytes(blob, key) == b"evidence-bytes"


def test_fresh_salt_means_fresh_ciphertext(backup_crypto):
    key = b"x" * 32
    a = backup_crypto.encrypt_bytes(b"same", key)
    b = backup_crypto.encrypt_bytes(b"same", key)
    assert a != b, "random salt+nonce must make ciphertexts differ"
    assert backup_crypto.decrypt_bytes(a, key) == backup_crypto.decrypt_bytes(b, key) == b"same"


def test_wrong_key_or_tamper_fails_closed(backup_crypto):
    from cryptography.exceptions import InvalidTag

    key = b"x" * 32
    blob = bytearray(backup_crypto.encrypt_bytes(b"evidence", key))
    with pytest.raises(InvalidTag):
        backup_crypto.decrypt_bytes(bytes(blob), b"y" * 32)  # wrong key
    blob[40] ^= 0xFF  # flip a ciphertext bit
    with pytest.raises(InvalidTag):
        backup_crypto.decrypt_bytes(bytes(blob), key)  # tampered
    with pytest.raises(ValueError):
        backup_crypto.decrypt_bytes(b"NOT-A-BACKUP", key)  # bad header


def test_key_policy(backup_crypto, monkeypatch):
    monkeypatch.delenv(backup_crypto.ENV_KEY, raising=False)
    with pytest.raises(backup_crypto.BackupKeyError) as excinfo:
        backup_crypto.load_key()
    assert backup_crypto.ENV_KEY in str(excinfo.value)
    monkeypatch.setenv(backup_crypto.ENV_KEY, "short")
    with pytest.raises(backup_crypto.BackupKeyError) as excinfo:
        backup_crypto.load_key()
    assert "too short" in str(excinfo.value)
    monkeypatch.setenv(backup_crypto.ENV_KEY, "a-long-enough-operator-secret")
    assert backup_crypto.load_key() == b"a-long-enough-operator-secret"


def test_is_encrypted_file_sniff(backup_crypto, tmp_path):
    plain = tmp_path / "p.db"
    plain.write_bytes(b"SQLite format 3\x00...")
    assert not backup_crypto.is_encrypted_file(plain)
    enc = tmp_path / "p.db.enc"
    enc.write_bytes(backup_crypto.encrypt_bytes(b"data", b"k" * 24))
    assert backup_crypto.is_encrypted_file(enc)


def test_backup_and_restore_round_trip_through_scripts(seed_db, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "round17-backup-encryption-test-secret")
    out_dir = tmp_path / "backups"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{seed_db}")

    backup = _load("backup_evidence")
    rc = _run_main(backup, ["--out", str(out_dir), "--encrypt"])
    assert rc == 0
    enc_files = sorted(out_dir.glob("cryptoscan-*.db.enc"))
    assert len(enc_files) == 1, "encrypted backup file expected"
    enc = enc_files[0]
    # no plaintext backup left behind
    assert list(out_dir.glob("cryptoscan-*.db")) == []
    manifest = json.loads(enc.with_suffix(enc.suffix + ".manifest.json").read_text())
    assert manifest["encrypted"] is True
    assert manifest["kdf"].startswith("scrypt-")
    assert manifest["file"] == enc.name

    # restore into a fresh target
    restore = _load("restore_evidence")
    target = tmp_path / "restored" / "cryptoscan.db"
    rc = _run_main(restore, [str(enc), "--db", f"sqlite:///{target}"])
    assert rc == 0
    assert target.exists()
    conn = sqlite3.connect(target)
    try:
        rows = conn.execute("SELECT id FROM evidence_records").fetchall()
    finally:
        conn.close()
    assert rows == [("e-1",)]
    # decrypted plaintext cleaned up after restore
    assert not (enc.parent / enc.stem).exists()


def test_restore_rejects_wrong_key(seed_db, tmp_path, monkeypatch):
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "round17-backup-encryption-test-secret")
    out_dir = tmp_path / "backups"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{seed_db}")
    backup = _load("backup_evidence")
    assert _run_main(backup, ["--out", str(out_dir), "--encrypt"]) == 0
    enc = sorted(out_dir.glob("cryptoscan-*.db.enc"))[0]

    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "totally-different-operator-secret")
    restore = _load("restore_evidence")
    target = tmp_path / "restored" / "cryptoscan.db"
    with pytest.raises(SystemExit) as excinfo:
        _run_main(restore, [str(enc), "--db", f"sqlite:///{target}"])
    assert "DECRYPTION FAILED" in str(excinfo.value)
    assert not target.exists(), "nothing may be restored on wrong key"


def _run_main(module, argv):
    sys.argv = [module.__name__] + argv
    try:
        return module.main()
    finally:
        sys.argv = ["pytest"]


def test_restore_never_overwrites_adjacent_plaintext_and_cleans_malformed_manifest(tmp_path, monkeypatch, backup_crypto):
    import tempfile
    monkeypatch.setenv("BACKUP_ENCRYPTION_KEY", "synthetic-historical-backup-key")
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    encrypted = tmp_path / "historical.sql.enc"
    encrypted.write_bytes(backup_crypto.encrypt_bytes(b"sensitive synthetic plaintext", backup_crypto.load_key()))
    adjacent = encrypted.with_suffix("")
    adjacent.write_bytes(b"pre-existing-file-must-survive")
    encrypted.with_suffix(".enc.manifest.json").write_text("{")
    with pytest.raises(json.JSONDecodeError):
        _run_main(_load("restore_evidence"), [str(encrypted), "--db", "postgresql://unused"])
    assert adjacent.read_bytes() == b"pre-existing-file-must-survive"
    assert not list(tmp_path.glob("cryptoscan-restore-*")), "Private plaintext staging must be cleaned on every exception"
