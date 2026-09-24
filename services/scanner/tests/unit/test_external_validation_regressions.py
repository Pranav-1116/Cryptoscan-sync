"""Regressions found by scanning real third-party packages (docs/accuracy/EXTERNAL-VALIDATION.md)."""
from pathlib import Path

import pytest

from scanner.parsers.go_parser import parse_go_file
from scanner.parsers.javascript_parser import parse_javascript_file
from scanner.core.file_discovery import FileDiscovery


def _algos(findings):
    return sorted({f.crypto.algorithm for f in findings})


def _write(tmp_path: Path, name: str, code: str) -> Path:
    p = tmp_path / name
    p.write_text(code)
    return p


def test_js_chained_create_hmac_across_lines_is_hmac(tmp_path):
    # cookie-signature/index.js
    p = _write(tmp_path, "a.js", "const crypto = require('crypto');\nexports.sign = (val, secret) => crypto\n    .createHmac('sha256', secret)\n    .update(val).digest('base64');\n")
    assert "HMAC-SHA-256" in _algos(parse_javascript_file(p, tmp_path))


def test_js_cookie_parser_inside_error_string_is_not_a_finding(tmp_path):
    # express/lib/response.js
    p = _write(tmp_path, "b.js", "if (signed && !secret) {\n  throw new Error('cookieParser(\"secret\") required for signed cookies');\n}\n")
    assert parse_javascript_file(p, tmp_path) == []


def test_js_jws_library_is_jwt(tmp_path):
    p = _write(tmp_path, "c.js", "const jws = require('jws');\nmodule.exports = (t) => jws.decode(t, {json: true});\n")
    assert "JWT" in _algos(parse_javascript_file(p, tmp_path))


def test_go_math_rand_outside_security_context_is_ignored(tmp_path):
    p = _write(tmp_path, "shuffle.go", 'package x\nimport "math/rand"\nfunc pick(items []string) string {\n\treturn items[rand.Intn(len(items))]\n}\n')
    assert "PRNG" not in _algos(parse_go_file(p, tmp_path))


def test_go_math_rand_for_token_is_reported(tmp_path):
    p = _write(tmp_path, "tok.go", 'package x\nimport "math/rand"\nfunc newSessionToken() int64 {\n\treturn rand.Int63()\n}\n')
    assert "PRNG" in _algos(parse_go_file(p, tmp_path))


def test_build_dir_that_is_a_python_package_is_scanned(tmp_path):
    (tmp_path / "ops" / "build").mkdir(parents=True)
    (tmp_path / "ops" / "build" / "__init__.py").write_text("")
    (tmp_path / "ops" / "build" / "tracker.py").write_text("import hashlib\nh = hashlib.sha224(b'x')\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.py").write_text("import hashlib\n")
    found = {p.relative_to(tmp_path).as_posix() for p in FileDiscovery().discover(tmp_path)}
    assert "ops/build/tracker.py" in found
    assert "build/out.py" not in found


def test_ruby_digest_sha256_hexdigest_is_sha256(tmp_path):
    from scanner.parsers.ruby_parser import parse_ruby_file
    # ruby-jwt lib/jwt/jwk/thumbprint.rb
    p = _write(tmp_path, "t.rb", "require 'digest'\ndef thumbprint(jwk)\n  Digest::SHA256.hexdigest(jwk.to_json)\nend\n")
    algos = _algos(parse_ruby_file(p, tmp_path))
    assert "SHA-256" in algos and "UNKNOWN" not in algos


def test_ruby_jwt_decode_algorithms_option(tmp_path):
    from scanner.parsers.ruby_parser import parse_ruby_file
    p = _write(tmp_path, "d.rb", "JWT.decode(token, nil, true, { algorithms: ['RS512'] })\n")
    assert "RS512" in _algos(parse_ruby_file(p, tmp_path))


def test_java_dynamic_jca_name_never_yields_none_algorithm(tmp_path):
    from scanner.parsers.java_parser import parse_java_file
    # jjwt JcaTemplate / SigningKeyResolverAdapter
    p = _write(tmp_path, "J.java", "import javax.crypto.*;\nimport javax.crypto.spec.SecretKeySpec;\nclass J {\n  Cipher c(String jcaName) throws Exception { return Cipher.getInstance(jcaName); }\n  SecretKeySpec k(byte[] b, String n) { return new SecretKeySpec(b, n); }\n}\n")
    findings = parse_java_file(p, tmp_path)
    assert findings
    assert all(f.crypto.algorithm for f in findings)


def test_java_hmac_transformation_uses_hmac_prefix():
    from scanner.extractors.algorithm_extractor import parse_transformation
    assert parse_transformation("HmacSHA256").algorithm == "HMAC-SHA-256"


def test_python_stored_hash_constructor_and_dynamic_hmac_digest(tmp_path):
    from scanner.parsers.python_parser import parse_python_file
    # django/utils/crypto.py + contrib/auth/hashers.py
    p = _write(tmp_path, "c.py", "import hashlib, hmac\n\nclass PBKDF2SHA1PasswordHasher:\n    digest = hashlib.sha1\n\ndef salted_hmac(key, value, hasher):\n    return hmac.new(key, msg=value, digestmod=hasher)\n")
    algos = _algos(parse_python_file(p, tmp_path))
    assert "SHA-1" in algos
    assert "HMAC" in algos
    assert not any(a.startswith("HMAC-") for a in algos)


def test_constant_time_compare_is_not_an_inventory_item(tmp_path):
    from scanner.parsers.php_parser import parse_php_file
    p = _write(tmp_path, "e.php", "<?php\nif (!hash_equals($expected, $given)) { die(); }\n")
    assert parse_php_file(p, tmp_path) == []
    q = _write(tmp_path, "e.go", 'package x\nimport "crypto/subtle"\nfunc eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }\n')
    assert parse_go_file(q, tmp_path) == []


def test_java_util_random_for_test_data_is_ignored(tmp_path):
    from scanner.parsers.java_parser import parse_java_file
    # commons-codec BaseNStrictDecodingTest
    p = _write(tmp_path, "T.java", "import java.util.Random;\nclass T {\n  void testCanonicalStreams() {\n    final byte[] input = new byte[67];\n    new Random(23456).nextBytes(input);\n  }\n}\n")
    assert "PRNG" not in _algos(parse_java_file(p, tmp_path))


def test_java_util_random_for_key_material_is_reported(tmp_path):
    from scanner.parsers.java_parser import parse_java_file
    p = _write(tmp_path, "K.java", "import java.util.Random;\nclass K {\n  byte[] newSessionKey() {\n    byte[] key = new byte[16];\n    new Random().nextBytes(key);\n    return key;\n  }\n}\n")
    assert "PRNG" in _algos(parse_java_file(p, tmp_path))


def test_c_project_local_digest_wrappers(tmp_path):
    from scanner.parsers.c_parser import parse_c_file
    # curl lib/vauth/digest.c, lib/curl_ntlm_core.c
    p = _write(tmp_path, "d.c", "static void f(void) {\n  ctxt = Curl_MD5_init(&Curl_DIGEST_MD5);\n  Curl_MD5_update(ctxt, userp, 3);\n  result = Curl_hmacit(&Curl_HMAC_MD5, hash, 16, id, len, out);\n  Curl_HMAC_init(&Curl_HMAC_SHA256, key, 32);\n}\n")
    algos = _algos(parse_c_file(p, tmp_path))
    assert {"MD5", "HMAC", "SHA-256"} <= set(algos)


def test_csharp_cancellation_token_is_not_security_context(tmp_path):
    from scanner.parsers.csharp_parser import parse_csharp_file
    # YARP HttpForwarderCancellationTests.cs
    p = _write(tmp_path, "C.cs", "class C {\n  async Task Run(CancellationToken cancellationToken)\n  {\n    var delay = new Random().Next(10, 50);\n  }\n}\n")
    assert "PRNG" not in _algos(parse_csharp_file(p, tmp_path))


def test_python2_file_falls_back_to_regex(tmp_path):
    # Python 2 print statement → ast.parse fails; crypto must still be found
    p = _write(tmp_path, "legacy.py", "import hashlib, ssl\nprint 'hashing'\nh = hashlib.md5(data).hexdigest()\nctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n")
    from scanner.parsers.python_parser import parse_python_file
    algos = _algos(parse_python_file(p, tmp_path))
    assert "MD5" in algos and "TLS1.0" in algos


def test_kotlin_char_literal_braces_do_not_drop_the_file(tmp_path):
    from scanner.parsers.kotlin_parser import parse_kotlin_file
    # okhttp CertificatePinner.kt / HttpUrl.kt: '{' char literals unbalance the shallow brace check
    p = _write(tmp_path, "Pinner.kt", "package okhttp3\nimport java.security.MessageDigest\nclass Pinner {\n  fun f(c: Char) { if (c == '{') return }\n  fun sha256(b: ByteArray) = MessageDigest.getInstance(\"SHA-256\").digest(b)\n  fun pin(bs: okio.ByteString) = bs.sha1()\n}\n")
    algos = _algos(parse_kotlin_file(p, tmp_path))
    assert "SHA-256" in algos and "SHA-1" in algos


def test_webcrypto_multiline_algorithm_object(tmp_path):
    # panva/jose src/lib/content_encryption.ts
    p = _write(tmp_path, "enc.ts", "const encKey = await crypto.subtle.importKey(\n  'raw',\n  cek,\n  'AES-CBC',\n  false,\n  ['encrypt'],\n)\nconst ct = await crypto.subtle.encrypt(\n  {\n    iv,\n    name: 'AES-GCM',\n  },\n  encKey,\n  plaintext,\n)\n")
    algos = _algos(parse_javascript_file(p, tmp_path))
    assert "AES" in algos and "UNKNOWN" not in algos


def test_shell_openssl_behind_variable_and_checksum_negative(tmp_path):
    from scanner.parsers.shell_parser import parse_shell_file
    # acmesh-official/acme.sh reaches openssl through ${ACME_OPENSSL_BIN:-openssl}
    p = _write(tmp_path, "acme.sh", '#!/bin/sh\n${ACME_OPENSSL_BIN:-openssl} genrsa 2048\n"$OPENSSL_BIN" dgst -sha256 -sign k.pem\nsha256sum f > f.sha256\napt-get install -y openssl\n')
    algos = set(_algos(parse_shell_file(p, tmp_path)))
    assert {"RSA", "SHA-256"} <= algos
    assert not algos - {"RSA", "SHA-256", "UNKNOWN"}


def test_shell_combined_htpasswd_flags(tmp_path):
    from scanner.parsers.shell_parser import parse_shell_file
    p = _write(tmp_path, "users.sh", 'htpasswd -cbB /etc/nginx/.htpasswd admin "$PW"\n')
    assert "BCRYPT" in _algos(parse_shell_file(p, tmp_path))


def test_swift_cryptoswift_sha2_variant_and_alamofire_disabled_trust(tmp_path):
    from scanner.parsers.swift_parser import parse_swift_file
    p = _write(tmp_path, "A.swift", 'import CryptoSwift\nlet t = try HMAC(key: k, variant: .sha2(.sha256)).authenticate(m)\nlet e = DisabledTrustEvaluator()\nlet r = SecKeyCreateEncryptedData(pub, .rsaEncryptionOAEPSHA256AESGCM, d as CFData, &err)\n')
    algos = set(_algos(parse_swift_file(p, tmp_path)))
    assert {"HMAC", "SHA-256", "TRUST-ALL", "RSA"} <= algos


def test_swift_multipart_boundary_random_is_not_a_finding(tmp_path):
    from scanner.parsers.swift_parser import parse_swift_file
    # Alamofire MultipartFormData: UInt32.random(in:) for a boundary string
    p = _write(tmp_path, "M.swift", 'let first = UInt32.random(in: UInt32.min...UInt32.max)\nlet boundary = String(format: "%08x", first)\n')
    assert parse_swift_file(p, tmp_path) == []


def test_xml_csproj_reference_and_tomcat_cipher_expansion(tmp_path):
    from scanner.registry.language_scanners import scan_file
    # dotnet/aspnetcore BasicApi.csproj uses <Reference Include=...>, not <PackageReference>
    p = _write(tmp_path, "BasicApi.csproj", '<Project><ItemGroup><Reference Include="Microsoft.AspNetCore.Authentication.JwtBearer" /></ItemGroup></Project>\n')
    assert "JWT" in _algos(scan_file(p, tmp_path))
    q = _write(tmp_path, "server.xml", '<Connector port="8443" SSLEnabled="true" ciphers="TLS_RSA_WITH_RC4_128_SHA" sslEnabledProtocols="TLSv1,TLSv1.2"/>\n')
    algos = set(_algos(scan_file(q, tmp_path)))
    assert {"RC4", "TLS1.0", "TLS1.2", "TLS-CIPHERS"} <= algos


def test_xml_comments_and_prose_are_silent(tmp_path):
    from scanner.parsers.xml_parser import parse_xml_file
    p = _write(tmp_path, "web.config", '<configuration>\n<!-- <machineKey validation="MD5" decryption="DES"/> -->\n<appSettings><add key="Theme" value="dark"/></appSettings>\n</configuration>\n')
    assert parse_xml_file(p, tmp_path) == []


def test_wave7_blind_fixes(tmp_path):
    from scanner.parsers.csharp_parser import parse_csharp_file
    from scanner.parsers.php_parser import parse_php_file
    cs = _write(tmp_path, "K.cs", 'using System.Security.Cryptography;\nvar e = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);\nusing var m = IncrementalHash.CreateHMAC(HashAlgorithmName.MD5, key);\n')
    algos = set(_algos(parse_csharp_file(cs, tmp_path)))
    assert {"ECDH", "HMAC", "MD5"} <= algos and "ECDSA" not in algos
    php = _write(tmp_path, "p.php", "<?php\n$h = password_hash($pw, PASSWORD_ARGON2ID);\n")
    algos = set(_algos(parse_php_file(php, tmp_path)))
    assert "ARGON2" in algos and "BCRYPT" not in algos


def test_wave8_payments_hsm(tmp_path):
    """Bank-proxy round 11 (jPOS, Fineract): payments/HSM vocabulary + SecretKeySpec vocabulary gate."""
    from scanner.parsers.java_parser import parse_java_file
    jpos = _write(tmp_path, "Pin.java", (
        "import org.jpos.security.*;\n"
        "class P { SecureDESKey k; EncryptedPIN t(SMAdapter sm, EncryptedPIN p, SecureDESKey a, SecureDESKey b) throws SMException {\n"
        "  return sm.translatePIN(p, a, b, SMAdapter.FORMAT01); }\n"
        "  SecureKey kb(SMAdapter sm, byte[] blob, SecureDESKey kbpk) throws SMException { return sm.importKey(0, SMAdapter.TYPE_ZMK, blob, kbpk, KeyScheme.R, true); } }\n"))
    algos = set(_algos(parse_java_file(jpos, tmp_path)))
    assert {"3DES", "AES"} <= algos
    # SecretKeySpec with a non-algorithm string must not leak the string as an algorithm name
    junk = _write(tmp_path, "T.java", 'import javax.crypto.spec.SecretKeySpec;\nclass T { void f(byte[] b){ new SecretKeySpec(b, "testJCEHandlerParam2"); new SecretKeySpec(b, "DESde"); } }\n')
    algos = set(_algos(parse_java_file(junk, tmp_path)))
    assert "testJCEHandlerParam2" not in algos and "DESde" not in algos
    # PKCS#11 mechanisms resolve per family
    p11 = _write(tmp_path, "P11.java", "class X { long a = PKCS11Constants.CKM_AES_CBC_PAD, b = PKCS11Constants.CKM_DES3_ECB, c = PKCS11Constants.CKM_SHA256_RSA_PKCS; }\n")
    algos = set(_algos(parse_java_file(p11, tmp_path)))
    assert {"AES", "3DES", "RSA"} <= algos
    # throws SMException on its own is not an inventory item
    neg = _write(tmp_path, "N.java", "class N { void f() throws SMException { String pan = mask(pan); } }\n")
    assert not _algos(parse_java_file(neg, tmp_path))


def test_wave9_sql_and_cobol(tmp_path):
    """Database + mainframe parsers (external round 12: sql-server-samples, utPLSQL, CardDemo)."""
    from scanner.parsers.sql_parser import parse_sql_file
    from scanner.parsers.cobol_parser import parse_cobol_file
    tsql = _write(tmp_path, "a.sql", "UPDATE u SET h = HASHBYTES(N'SHA2_256', @p);\nCREATE SYMMETRIC KEY k WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE c;\n")
    assert {"SHA-256", "AES"} <= set(_algos(parse_sql_file(tsql, tmp_path)))
    # hash indexes / hash partitioning / comments are not crypto
    neg = _write(tmp_path, "b.sql", "CREATE TABLE t (id INT, INDEX ix HASH (id) WITH (BUCKET_COUNT = 3));\n-- HASHBYTES('MD5', x) was here\nSELECT ORA_HASH(id) FROM t PARTITION BY HASH (id);\n")
    assert not _algos(parse_sql_file(neg, tmp_path))
    ora = _write(tmp_path, "c.pkb", "FUNCTION gen_otp RETURN VARCHAR2 IS BEGIN\nl := DBMS_CRYPTO.ENCRYPT(r, DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC, k);\nRETURN LPAD(DBMS_RANDOM.VALUE(0,999999), 6, '0'); -- otp\n")
    algos = set(_algos(parse_sql_file(ora, tmp_path)))
    assert "AES" in algos and "PRNG" in algos
    cbl = _write(tmp_path, "p.cbl", "       01  RULE-ARRAY PIC X(8) VALUE 'SHA-256 '.\n           CALL 'CSNBOWH' USING RC RS.\n           CALL 'CSNBPVR' USING RC RS PIN-BLOCK.\n           CALL 'CSNDDSG' USING RC RS.\n")
    algos = set(_algos(parse_cobol_file(cbl, tmp_path)))
    assert {"SHA-256", "3DES", "RSA"} <= algos
    # fixed-format comment lines (col 7 '*') and floating '*>' comments are blanked; VSAM keys ignored
    negc = _write(tmp_path, "n.cbl", "      * CALL 'CSNBENC' FOR DES\n           RECORD KEY IS CUST-ID  *> CSNBOWH\n           COMPUTE X = FUNCTION RANDOM * 10.\n")
    assert not _algos(parse_cobol_file(negc, tmp_path))


# ---- Round 13: repositories published by bank GitHub orgs -------------------


def test_go_ethereum_keccak256_is_sha3_not_ecdsa(tmp_path):
    # jpmorganchase/quorum: crypto.Keccak256Hash was double-reported as ECDSA
    from scanner.registry.language_scanners import scan_file

    p = _write(tmp_path, "topics.go", 'package x\nimport "github.com/ethereum/go-ethereum/crypto"\nfunc f() { _ = crypto.Keccak256Hash([]byte{1}) }\n')
    algos = _algos(scan_file(p, tmp_path))
    assert "SHA3-256" in algos and "ECDSA" not in algos


def test_scala_interpolated_transformation_is_unknown_with_mode(tmp_path):
    # ing-bank/baker: Cipher.getInstance(s"$algorithmName/ECB/PKCS5Padding") leaked "$algorithmName"
    from scanner.registry.language_scanners import scan_file

    p = _write(tmp_path, "Encryption.scala", 'object E {\n  val c = javax.crypto.Cipher.getInstance(s"$algorithmName/ECB/PKCS5Padding")\n}\n')
    fs = scan_file(p, tmp_path)
    assert fs and all(not (f.crypto.algorithm or "").startswith("$") for f in fs)
    assert any(f.crypto.algorithm == "UNKNOWN" and f.crypto.mode == "ECB" for f in fs)


def test_java_security_disabled_algorithms_are_not_reported_as_in_use(tmp_path):
    from scanner.registry.language_scanners import scan_file

    p = _write(tmp_path, "java.security", "jdk.tls.disabledAlgorithms=SSLv3, TLSv1, RC4, DES, MD5withRSA, 3DES_EDE_CBC\n")
    algos = _algos(scan_file(p, tmp_path))
    assert set(algos) & {"RC4", "DES", "MD5", "3DES"} == set()
    assert any(a.startswith("TLS") for a in algos)
