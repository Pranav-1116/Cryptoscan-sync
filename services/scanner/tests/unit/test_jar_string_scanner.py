import struct
import zipfile
from pathlib import Path

from scanner.detectors.java.jar_string_scanner import analyse_class, scan_class_file, scan_jar


def _class_file(class_refs: list[str], strings: list[str]) -> bytes:
    """Build a minimal, valid class-file prefix: magic, version, constant pool with Utf8/Class/String entries."""
    pool: list[bytes] = []
    for name in class_refs:
        pool.append(b"\x01" + struct.pack(">H", len(name)) + name.encode())        # Utf8
        pool.append(b"\x07" + struct.pack(">H", len(pool)))                        # Class -> previous Utf8 (1-based index)
    for s in strings:
        pool.append(b"\x01" + struct.pack(">H", len(s)) + s.encode())
        pool.append(b"\x08" + struct.pack(">H", len(pool)))                        # String -> previous Utf8
    return b"\xca\xfe\xba\xbe" + struct.pack(">HH", 0, 52) + struct.pack(">H", len(pool) + 1) + b"".join(pool) + b"\x00" * 8


def test_constant_pool_transformation_and_api_class(tmp_path: Path):
    jar = tmp_path / "lib.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.writestr("META-INF/maven/com.example/lib/pom.properties", "groupId=com.example\nartifactId=lib\nversion=1.2\n")
        archive.writestr("com/example/Crypto.class", _class_file(["javax/crypto/Cipher", "java/security/MessageDigest"], ["AES/CBC/PKCS5Padding", "MD5", "HmacSHA256"]))
    findings = scan_jar(jar, tmp_path)
    algos = {f.crypto.algorithm for f in findings}
    assert {"AES", "MD5", "HMAC-SHA-256"} <= algos or {"AES", "MD5"} <= algos and any(a.startswith("HMAC") for a in algos)
    assert all("lib.jar!com/example/Crypto.class" == f.source.file_path for f in findings)
    assert all("com.example:lib:1.2" in f.metadata.confidence_reason for f in findings)


def test_plain_strings_without_crypto_api_are_ignored():
    # "MD5" and "SHA" appear in log formats, column names, enum labels ... no API class => nothing
    assert analyse_class(_class_file(["java/lang/Object", "java/util/HashMap"], ["MD5", "SHA-256", "RSA", "none"])) == []
    # a JCE transformation with '/' is unambiguous even without the API reference
    out = analyse_class(_class_file(["java/lang/Object"], ["DESede/CBC/NoPadding"]))
    assert [o[0] for o in out] == ["3DES"]


def test_bouncycastle_engine_class_names_and_nested_jar(tmp_path: Path):
    inner = tmp_path / "inner.jar"
    with zipfile.ZipFile(inner, "w") as a:
        a.writestr("x/Y.class", _class_file(["org/bouncycastle/crypto/engines/DESedeEngine", "org/bouncycastle/crypto/digests/SHA1Digest"], []))
    war = tmp_path / "app.war"
    with zipfile.ZipFile(war, "w") as a:
        a.write(inner, "WEB-INF/lib/inner.jar")
    findings = scan_jar(war, tmp_path)
    assert {f.crypto.algorithm for f in findings} == {"3DES", "SHA-1"}
    assert findings[0].source.file_path.startswith("app.war!WEB-INF/lib/inner.jar!x/Y.class")


def test_loose_class_file_and_hsm_provider(tmp_path: Path):
    cls = tmp_path / "Hsm.class"
    cls.write_bytes(_class_file(["java/security/KeyStore", "sun/security/pkcs11/SunPKCS11"], ["PKCS11", "SunPKCS11", "SHA256withRSA", "TLSv1"]))
    algos = {f.crypto.algorithm for f in scan_class_file(cls, tmp_path)}
    assert {"UNKNOWN", "RSA", "SHA-256", "TLS1.0", "X509"} <= algos


def test_garbage_is_not_a_class_file(tmp_path: Path):
    jar = tmp_path / "bad.jar"
    with zipfile.ZipFile(jar, "w") as archive:
        archive.writestr("a/B.class", b"\x00Cipher.getInstance\x00AES/ECB\x00")
        archive.writestr("a/C.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34\xff\xff\x01")
    assert scan_jar(jar, tmp_path) == []


def test_full_pipeline_scans_each_archive_once(tmp_path):
    import io
    import zipfile

    from scanner.core.scanner import Scanner

    (tmp_path / "lib").mkdir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("com/x/A.class", _class_file(["javax/crypto/Cipher"], ["AES/GCM/NoPadding"]))
    (tmp_path / "lib" / "a.jar").write_bytes(buf.getvalue())
    result = Scanner().scan(root_path=tmp_path, target_type="LOCAL_DIRECTORY", target_location=str(tmp_path))
    keys = [(f.source.file_path, f.crypto.algorithm) for f in result.findings]
    assert keys == [("lib/a.jar!com/x/A.class", "AES")]
