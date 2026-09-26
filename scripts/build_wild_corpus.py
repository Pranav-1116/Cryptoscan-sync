#!/usr/bin/env python3
"""Build ``tests/accuracy/corpus_wave4_wild.py`` from excerpts of real open-source projects.

The excerpts are short (a function or a handful of lines), attributed, and were reviewed by
hand while running the scanner over the full projects (docs/accuracy/EXTERNAL-VALIDATION.md).
Unlike waves 1-3 these are not written for the scanner — they are the idioms real code uses.

Usage (needs the checkouts used for external validation under /tmp/ext):

    python scripts/build_wild_corpus.py            # regenerate the corpus file
    python scripts/build_wild_corpus.py --check    # verify committed corpus matches sources

The generated file is committed so the accuracy gate stays hermetic.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

EXT = Path("/tmp/ext")
OUT = Path(__file__).resolve().parents[1] / "services/scanner/tests/accuracy/corpus_wave4_wild.py"

# (language, corpus file name, source path, (first, last) line range(s), expected families, category, license)
ENTRIES = [
    # ---------------------------------------------------------------- Python (Django, BSD-3)
    ("python", "wild_django_salted_hmac.py", "gh/django/django/utils/crypto.py", [(1, 12), (23, 61)], {"HMAC", "SHA-1"}, "wild-positive", "Django BSD-3-Clause"),
    ("python", "wild_django_pbkdf2.py", "gh/django/django/utils/crypto.py", [(1, 12), (86, 93)], {"PBKDF2", "SHA-256"}, "wild-positive", "Django BSD-3-Clause"),
    ("python", "wild_django_bcrypt_hasher.py", "gh/django/django/contrib/auth/hashers.py", [(1, 20), (487, 520)], {"BCRYPT", "SHA-256"}, "wild-positive", "Django BSD-3-Clause"),
    ("python", "wild_django_scrypt_hasher.py", "gh/django/django/contrib/auth/hashers.py", [(1, 20), (578, 602)], {"SCRYPT"}, "wild-positive", "Django BSD-3-Clause"),
    ("python", "wild_django_md5_hasher.py", "gh/django/django/contrib/auth/hashers.py", [(1, 20), (656, 667)], {"MD5"}, "wild-positive", "Django BSD-3-Clause"),
    ("python", "wild_django_smtp_tls.py", "gh/django/django/core/mail/backends/smtp.py", [(1, 12), (100, 113)], {"TLS"}, "wild-positive", "Django BSD-3-Clause"),
    ("python", "wild_django_sqlite_md5.py", "gh/django/django/db/backends/sqlite3/_functions.py", [(1, 20), (411, 416)], {"MD5"}, "wild-positive", "Django BSD-3-Clause"),
    # ---------------------------------------------------------------- Python negatives (pydantic MIT, click BSD-3)
    ("python", "wild_click_termui.py", "/home/user/CryproScan/.venv/lib/python3.11/site-packages/click/termui.py", (1, 60), set(), "wild-negative", "click BSD-3-Clause"),
    # ---------------------------------------------------------------- JavaScript (MIT)
    ("javascript", "wild_cookie_signature.js", "npm/cookie-signature/index.js", (1, 25), {"HMAC", "SHA-256"}, "wild-positive", "cookie-signature MIT"),
    ("javascript", "wild_express_session_hash.js", "npm/express-session/index.js", (611, 630), {"SHA-1"}, "wild-positive", "express-session MIT"),
    ("javascript", "wild_jsonwebtoken_decode.js", "npm/jsonwebtoken/decode.js", (1, 12), {"JWT"}, "wild-positive", "jsonwebtoken MIT"),
    ("javascript", "wild_bcryptjs_random.js", "npm/bcryptjs/index.js", (40, 60), {"RNG"}, "wild-positive", "bcryptjs MIT"),
    ("javascript", "wild_express_cookie_error.js", "npm/express/lib/response.js", (750, 760), set(), "wild-negative", "express MIT"),
    # ---------------------------------------------------------------- Go (MIT / Apache-2.0)
    ("go", "wild_gin_insecure_skip.go", "gh/gin/gin_test.go", (170, 182), {"TLS"}, "wild-positive", "gin MIT"),
    ("go", "wild_caddy_mask_key.go", "gh/caddy/modules/caddyhttp/reverseproxy/streaming.go", [(15, 40), (585, 590)], {"RNG"}, "wild-positive", "caddy Apache-2.0"),
    ("go", "wild_caddy_tls_versions.go", "gh/caddy/modules/caddytls/values.go", (118, 132), {"TLS"}, "wild-positive", "caddy Apache-2.0"),
    ("go", "wild_golang_jwt_hmac.go", "gh/jwt/hmac.go", (60, 80), {"HMAC"}, "wild-positive", "golang-jwt MIT"),
    ("go", "wild_golang_jwt_ecdsa.go", "gh/jwt/ecdsa.go", (100, 118), {"ECDSA", "RNG"}, "wild-positive", "golang-jwt MIT"),
    ("go", "wild_gin_test_random.go", "gh/gin/githubapi_test.go", (400, 420), set(), "wild-negative", "gin MIT"),
    # ---------------------------------------------------------------- Ruby (MIT)
    ("ruby", "wild_ruby_jwt_thumbprint.rb", "gh/ruby-jwt/lib/jwt/jwk/thumbprint.rb", (1, 25), {"SHA-256", "JWT"}, "wild-positive", "ruby-jwt MIT"),
    ("ruby", "wild_ruby_jwt_hmac.rb", "gh/ruby-jwt/lib/jwt/jwa/hmac.rb", (20, 34), {"HMAC"}, "wild-positive", "ruby-jwt MIT"),
    # ---------------------------------------------------------------- PHP (BSD-3 / MIT)
    ("php", "wild_php_jwt_sign.php", "gh/php-jwt/src/JWT.php", (261, 306), {"HMAC", "RSA", "ED25519"}, "wild-positive", "php-jwt BSD-3-Clause"),
    ("php", "wild_laravel_encrypter.php", "gh/framework/src/Illuminate/Encryption/Encrypter.php", [(1, 12), (38, 50), (100, 130)], {"AES", "RNG"}, "wild-positive", "Laravel MIT"),
    ("php", "wild_laravel_bcrypt.php", "gh/framework/src/Illuminate/Hashing/BcryptHasher.php", (55, 70), {"BCRYPT"}, "wild-positive", "Laravel MIT"),
    ("php", "wild_laravel_sql_hash_index.php", "gh/framework/tests/Database/DatabasePostgresSchemaGrammarTest.php", (370, 380), set(), "wild-negative", "Laravel MIT"),
    # ---------------------------------------------------------------- Java (Apache-2.0)
    ("java", "wild_jjwt_jca_template.java", "gh/jjwt/impl/src/main/java/io/jsonwebtoken/impl/security/JcaTemplate.java", (430, 445), set(), "wild-negative-dynamic", "jjwt Apache-2.0"),
    ("java", "wild_jjwt_keys_hmac.java", "gh/jjwt/api/src/main/java/io/jsonwebtoken/security/Keys.java", (60, 78), {"HMAC", "SHA-512", "SHA-384", "SHA-256"}, "wild-positive", "jjwt Apache-2.0"),
    ("java", "wild_commons_digestutils.java", "gh/commons-codec/src/main/java/org/apache/commons/codec/digest/DigestUtils.java", (190, 235), {"MD2", "MD5", "SHA-1"}, "wild-positive", "commons-codec Apache-2.0"),
    ("java", "wild_commons_base64_test.java", "gh/commons-codec/src/test/java/org/apache/commons/codec/binary/Base64Test.java", [(1, 5), (170, 180)], set(), "wild-negative", "commons-codec Apache-2.0"),
    # ---------------------------------------------------------------- Rust (MIT)
    ("rust", "wild_rust_jsonwebtoken_hmac.rs", "gh/jsonwebtoken/src/crypto/rust_crypto/hmac.rs", (1, 14), {"HMAC", "SHA-256", "SHA-384", "SHA-512"}, "wild-positive", "jsonwebtoken (Keats) MIT"),
    ("rust", "wild_rust_jsonwebtoken_dispatch.rs", "gh/jsonwebtoken/src/crypto/rust_crypto/mod.rs", (85, 100), {"SHA-256", "SHA-384", "SHA-512", "JWT", "RSA", "ECDSA"}, "wild-positive", "jsonwebtoken (Keats) MIT"),
    # ---------------------------------------------------------------- C# (MIT)
    ("csharp", "wild_jwt_dotnet_hs256.cs", "gh/jwt-dotnet/src/JWT/Algorithms/HMACSHA256Algorithm.cs", (1, 20), {"HMAC", "SHA-256"}, "wild-positive", "jwt-dotnet MIT"),
    ("csharp", "wild_yarp_ssl2_test.cs", "gh/reverse-proxy/test/ReverseProxy.Tests/Utilities/TlsFrameHelperTests.cs", (188, 198), {"TLS"}, "wild-positive", "YARP MIT"),
    # ---------------------------------------------------------------- C (curl license)
    ("c", "wild_curl_ntlm_hmac_md5.c", "gh/curl/lib/curl_ntlm_core.c", (520, 530), {"HMAC", "MD5"}, "wild-positive", "curl MIT/X"),
    ("c", "wild_curl_pop3_apop.c", "gh/curl/lib/pop3.c", (570, 585), {"MD5"}, "wild-positive", "curl MIT/X"),
    ("c", "wild_curl_cram_md5.c", "gh/curl/lib/vauth/cram.c", (55, 70), {"HMAC", "MD5"}, "wild-positive", "curl MIT/X"),
    ("c", "wild_curl_rustls.c", "gh/curl/lib/vtls/rustls.c", (630, 640), {"TLS"}, "wild-positive", "curl MIT/X"),
    # ---------------------------------------------------------------- config (Apache-2.0)
    ("nginx", "wild_ingress_nginx.tmpl", "gh/ingress-nginx/rootfs/etc/nginx/template/nginx.tmpl", (452, 490), {"TLS", "DH", "ECDH"}, "wild-positive", "ingress-nginx Apache-2.0"),
]


def _excerpt(rel: str, ranges) -> str:
    """``ranges`` is ``(start, end)`` or a list of them (e.g. the import block + a function)."""
    path = Path(rel) if rel.startswith("/") else (EXT / rel).resolve()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if isinstance(ranges, tuple):
        ranges = [ranges]
    chunks = ["\n".join(lines[a - 1 : b]).rstrip() for a, b in ranges]
    return "\n\n".join(chunks) + "\n"


def render() -> str:
    out = [
        '"""Wave 4 — excerpts of real open-source code (generated by scripts/build_wild_corpus.py).',
        "",
        "Each excerpt is attributed to its project and license below; excerpts are short and used",
        "solely as test fixtures for the crypto-discovery accuracy gate. Labels were assigned while",
        "reviewing the scanner against the full projects (docs/accuracy/EXTERNAL-VALIDATION.md).",
        '"""',
        "",
        "",
        "def register(_c):",
    ]
    for lang, fname, rel, ranges, expected, category, lic in ENTRIES:
        code = _excerpt(rel, ranges)
        span = ranges if isinstance(ranges, list) else [ranges]
        where = ", ".join(f"L{a}-L{b}" for a, b in span)
        exp = "set()" if not expected else "{" + ", ".join(f'"{e}"' for e in sorted(expected)) + "}"
        shown = rel.rsplit("site-packages/", 1)[-1] if rel.startswith("/") else rel.split("/", 1)[-1]
        out.append(f"    # {lic} — {shown} {where}")
        out.append(f'    _c("{lang}", "{fname}", {code!r}, {exp}, "{category}")')
    out.append("")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    text = render()
    if args.check:
        if OUT.read_text() != text:
            print("corpus_wave4_wild.py is out of date", file=sys.stderr)
            return 1
        print("ok")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(ENTRIES)} excerpts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
