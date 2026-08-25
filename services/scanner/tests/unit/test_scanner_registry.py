from pathlib import Path

from scanner.models.enums import Purpose
from scanner.registry.multi_language_runner import run_all_scanners
from scanner.registry.scanner_registry import get_scanner_for_language, language_for_path, parse_path


def test_purpose_enum_covers_network_and_cloud():
    assert Purpose.NETWORK_ENCRYPTION.value == "NETWORK_ENCRYPTION"
    assert Purpose.PASSWORD_HASHING.value == "PASSWORD_HASHING"
    assert Purpose.KEY_MANAGEMENT.value == "KEY_MANAGEMENT"
    assert Purpose.DATA_AT_REST_ENCRYPTION.value == "DATA_AT_REST_ENCRYPTION"


def test_registry_maps_extensions_and_parsers(tmp_path: Path):
    java = tmp_path / "A.java"
    java.write_text(
        "import javax.crypto.Cipher;\n"
        "class A { void encrypt() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }\n"
    )
    assert language_for_path(java) == "JAVA"
    assert get_scanner_for_language("JAVA") is not None
    findings = parse_path(java, tmp_path)
    assert any(item.crypto.algorithm == "AES" for item in findings)


def test_multi_language_runner_scans_go_and_python(tmp_path: Path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "a.go").write_text("package p\nfunc f() { aes.NewGCM(block) }\n")
    findings = run_all_scanners(tmp_path)
    languages = {item.source.language for item in findings}
    assert "PYTHON" in languages
    assert "GO" in languages
