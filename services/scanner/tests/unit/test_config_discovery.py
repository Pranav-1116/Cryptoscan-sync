"""Repo scans must reach config files: Dockerfile, sshd_config, *.yml, *.properties, .env.*"""
from pathlib import Path

from scanner.core.file_discovery import FileDiscovery, is_named_config_file
from scanner.core.scanner import Scanner


def test_named_config_files_recognised():
    assert is_named_config_file("Dockerfile")
    assert is_named_config_file("api.Dockerfile")
    assert is_named_config_file(".env.production")
    assert is_named_config_file("sshd_config")
    assert not is_named_config_file("README.md")
    assert not is_named_config_file("main.go")


def test_discovery_yields_config_files(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("ENV NODE_TLS_REJECT_UNAUTHORIZED=0\n")
    (tmp_path / "app.yml").write_text("server:\n  ssl:\n    enabled-protocols: TLSv1\n")
    (tmp_path / "sshd_config").write_text("Ciphers 3des-cbc\n")
    (tmp_path / "notes.md").write_text("MD5 is mentioned here but markdown is not scanned\n")
    names = {p.name for p in FileDiscovery().discover(tmp_path)}
    assert {"Dockerfile", "app.yml", "sshd_config"} <= names
    assert "notes.md" not in names


def test_scanner_reports_config_crypto(tmp_path: Path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\nENV NODE_TLS_REJECT_UNAUTHORIZED=0\nENV JWT_ALGORITHM=HS256\n")
    (tmp_path / "sshd_config").write_text("Ciphers 3des-cbc,aes128-ctr\nMACs hmac-md5\n")
    result = Scanner().scan(tmp_path)
    algos = {f.crypto.algorithm for f in result.findings}
    assert "TLS-CERT-NONE" in algos
    assert "JWT" in algos
    assert {"3DES", "AES", "HMAC", "MD5"} <= algos
