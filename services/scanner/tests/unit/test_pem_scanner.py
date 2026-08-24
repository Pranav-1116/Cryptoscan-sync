from pathlib import Path

from scanner.detectors.materials.pem_scanner import join_materials_to_source, scan_materials

CERT = """-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUTestCert000000000000000000000wDQYJKoZIhvcNAQEL
BQAwADAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMAAwXDANBgkqhkiG
9w0BAQEFAANLADBIAkEAtoK3n+testonlynotarealkeyjustpaddingxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
IDAQMA4GA1UdDwEB/wQEAwIFoDANBgkqhkiG9w0BAQsFAANBAAaBbCcDdEeFfGgH
hIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789abcdefghijklmno=
-----END CERTIFICATE-----
"""

KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKplaceholderNotARealKeyMaterialxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END RSA PRIVATE KEY-----
"""


def test_scan_materials_classifies_pem(tmp_path: Path):
    (tmp_path / "tls.pem").write_text(CERT + "\n" + KEY)
    (tmp_path / "app.java").write_text("Cipher.getInstance(\"AES\");\n")
    findings = scan_materials(tmp_path, repo_root=tmp_path)
    purposes = {f.crypto.purpose for f in findings}
    assert "CERTIFICATE" in purposes
    assert "KEY_STORAGE" in purposes
    banners = {f.crypto.raw_transformation for f in findings}
    assert "CERTIFICATE" in banners
    assert "RSA PRIVATE KEY" in banners


def test_join_materials_to_source():
    materials = [{"file_path": "src/tls.pem", "algorithm": "RSA", "purpose": "CERTIFICATE"}]
    source = [
        {"evidence_id": "e1", "file_path": "src/tls.py", "line_number": 4, "algorithm": "AES", "purpose": "ENCRYPTION"},
        {"evidence_id": "e2", "file_path": "other/x.py", "line_number": 1, "algorithm": "MD5", "purpose": "HASHING"},
    ]
    joined = join_materials_to_source(materials, source)
    assert joined[0]["linked_source"]
    assert joined[0]["linked_source"][0]["evidence_id"] == "e1"
