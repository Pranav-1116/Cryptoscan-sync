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
