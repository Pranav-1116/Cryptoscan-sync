"""Runtime evidence ingestion: ICSF / RACF / payShield / JSSE / openssl / nginx / sshd / AT-TLS logs."""
from pathlib import Path

import pytest

from scanner.core.file_discovery import FileDiscovery
from scanner.parsers.runtime_log_parser import parse_runtime_log_file
from scanner.registry.language_scanners import scan_file

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "runtime_logs"


def _algos(name):
    fs = scan_file(FIX / name, FIX)
    assert all(f.source.type == "RUNTIME_LOG" for f in fs), name
    return {f.crypto.algorithm for f in fs}, fs


@pytest.mark.parametrize("name,expected", [
    ("icsf.log", {"AES", "3DES", "SHA-1", "RSA"}),
    ("racdcert.log", {"RSA", "SHA-256", "SHA-1"}),
    ("payshield.audit", {"3DES", "AES", "RSA"}),
    ("jsse.log", {"TLS", "AES", "SHA-384", "ECDH", "RSA", "3DES", "SHA-1"}),
    ("sclient.log", {"TLS", "X25519", "SHA-256", "RSA", "AES", "SHA-384"}),
    ("nginx-access.log", {"TLS", "AES", "SHA-256", "ECDH", "RSA", "3DES", "SHA-1"}),
    ("sshd.log", {"X25519", "ED25519", "AES", "ChaCha20", "RSA"}),
    ("attls.log", {"3DES", "SHA-1", "RSA", "AES", "SHA-384", "ECDH"}),
])
def test_runtime_sources(name, expected):
    got, _ = _algos(name)
    got.discard("TLS-CIPHERS")
    assert expected <= got, (name, got)


def test_plain_application_log_is_silent():
    assert parse_runtime_log_file(FIX / "app.log", FIX) == []


def test_aggregation_counts_occurrences_and_key_sizes():
    _, fs = _algos("icsf.log")
    aes = [f for f in fs if f.crypto.raw_transformation == "CSNBSYE"][0]
    assert aes.occurrences == 2 and aes.metadata.confidence_reason.endswith("2 occurrence(s)")
    _, fs = _algos("racdcert.log")
    sizes = sorted(f.crypto.key_size for f in fs if f.crypto.api_type == "KEY_PAIR_GENERATOR")
    assert sizes == [1024, 2048]


def test_logs_are_opt_in_for_discovery(monkeypatch):
    monkeypatch.delenv("CRYPTOSCAN_RUNTIME_LOGS", raising=False)
    assert not [p for p in FileDiscovery().discover(FIX) if p.suffix == ".log"]
    monkeypatch.setenv("CRYPTOSCAN_RUNTIME_LOGS", "1")
    assert len([p for p in FileDiscovery().discover(FIX) if p.suffix in (".log", ".audit")]) == 9
