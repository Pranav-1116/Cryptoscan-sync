import zipfile
from pathlib import Path

from scanner.detectors.java.jar_string_scanner import scan_jar


def test_scan_jar_finds_cipher_string(tmp_path: Path):
    jar = tmp_path / "lib.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.writestr("com/example/Crypto.class", b"\x00Cipher.getInstance\x00AES/ECB\x00")
    findings = scan_jar(jar, tmp_path)
    assert findings
    assert findings[0].crypto.algorithm == "AES"
    assert "lib.jar!" in findings[0].source.file_path
