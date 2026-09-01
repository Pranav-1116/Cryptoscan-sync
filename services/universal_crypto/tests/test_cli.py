"""§36 CLI tests — scan command + accuracy command, both deterministic."""

from __future__ import annotations

import json

from universal_crypto.cli import build_parser, main


def test_scan_source_file(capsys, tmp_path):
    code = "import hashlib\nh = hashlib.sha256(data)"
    request = json.dumps({
        "source_code": [{"language": "python", "text": code,
                         "asset_id": "svc", "location": "svc/main.py"}],
        "policy": "NIST",
    })
    request_file = tmp_path / "request.json"
    request_file.write_text(request)
    rc = main(["scan", "--request", str(request_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "observations:" in out
    assert "SHA-256" in out
    assert "findings:" in out


def test_accuracy_command(capsys):
    rc = main(["accuracy", "--dataset", "known_noncrypto"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "known_noncrypto" in out
    assert "f1=1.000" in out
    assert "fpr=0.000" in out


def test_accuracy_all_datasets(capsys):
    rc = main(["accuracy"])
    assert rc == 0
    out = capsys.readouterr().out
    for name in ("known_crypto", "known_noncrypto", "obfuscated",
                 "custom_crypto", "real_world"):
        assert name in out
    assert "MEAN" in out
    assert "f1=1.000" in out


def test_scan_missing_input_fails():
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["scan"])
    assert exc.value.code == 1


def test_parser_exposes_policy_flag():
    parser = build_parser()
    args = parser.parse_args(["--policy", "FIPS", "scan", "x.py"])
    assert args.policy == "FIPS"


def test_accuracy_covers_policy_and_pqc_datasets(capsys):
    rc = main(["accuracy", "--dataset", "weak_crypto"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "weak_crypto" in out
    assert "f1=1.000" in out

    rc = main(["accuracy", "--dataset", "pqc_classification"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pqc_classification" in out
    assert "f1=1.000" in out


def test_simulate_command(capsys):
    rc = main(["simulate", "--current", "RSA", "--target", "ML-KEM-768",
               "--protocol", "TLS", "--library", "OpenSSL", "--hardware", "HSM"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "ML-KEM-768" in out
    assert "READY" in out
    assert "HIGH reduction" in out
