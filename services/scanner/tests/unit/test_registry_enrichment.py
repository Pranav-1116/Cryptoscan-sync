"""Algorithm registry enrichment — findings leave with key sizes."""

from __future__ import annotations

from scanner.parsers.finding_factory import make_finding


def _make(tmp_path, *, algorithm, raw_transformation=None, key_size=None, mode=None):
    src = tmp_path / "Svc.java"
    src.write_text('Cipher c = Cipher.getInstance("AES");\n')
    return make_finding(
        file_path=src,
        repo_root=tmp_path,
        line_number=1,
        language="Java",
        api_type="CIPHER_INIT",
        algorithm=algorithm,
        raw_transformation=raw_transformation,
        key_size=key_size,
        mode=mode,
        purpose="ENCRYPTION",
        library="javax.crypto",
        scanner_id="test",
    )


def test_key_size_filled_from_registry(tmp_path):
    finding = _make(tmp_path, algorithm="DES")
    assert finding.crypto.key_size == 56


def test_key_size_from_transformation_string(tmp_path):
    finding = _make(tmp_path, algorithm="AES", raw_transformation="AES-256/GCM/NoPadding")
    assert finding.crypto.key_size == 256
    assert finding.crypto.mode == "GCM"


def test_explicit_key_size_not_overridden(tmp_path):
    finding = _make(tmp_path, algorithm="RSA", key_size=4096)
    assert finding.crypto.key_size == 4096


def test_unknown_algorithm_leaves_key_size_empty(tmp_path):
    finding = _make(tmp_path, algorithm="scratchpad")
    assert finding.crypto.key_size is None
