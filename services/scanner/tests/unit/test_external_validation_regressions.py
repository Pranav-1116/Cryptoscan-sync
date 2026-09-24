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
