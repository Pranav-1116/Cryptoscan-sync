"""PHP crypto detector (openssl, hash, mcrypt, password_hash, libsodium)."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import re
from pathlib import Path

from scanner.models.raw_finding import RawFinding
from scanner.parsers.finding_factory import make_finding

SCANNER_ID = "static-php-scanner-v1.0"

_OPENSSL = re.compile(
    r"openssl_(?:encrypt|decrypt)\s*\(\s*[^,]+,\s*['\"]([A-Za-z0-9_-]+)['\"]",
    re.IGNORECASE,
)
_HASH = re.compile(r"\bhash\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_HASH_HMAC = re.compile(r"\bhash_hmac\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_HASH_PBKDF2 = re.compile(r"\bhash_pbkdf2\s*\(\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_OPENSSL_DIGEST = re.compile(r"\bopenssl_digest\s*\(\s*[^,]+,\s*['\"]([A-Za-z0-9_-]+)['\"]", re.IGNORECASE)
_OPENSSL_PKEY = re.compile(
    r"openssl_pkey_new\s*\(\s*(?:\[[^\]]*['\"]private_key_bits['\"]\s*=>\s*(\d+))?",
    re.IGNORECASE | re.DOTALL,
)
_MCRYPT = re.compile(r"\bmcrypt_encrypt\s*\(\s*['\"]?([A-Za-z0-9_-]+)", re.IGNORECASE)
_PASSWORD = re.compile(r"\bpassword_hash\s*\(\s*[^,]+,\s*(PASSWORD_[A-Z0-9_]+)", re.IGNORECASE)
_SIMPLE = [
    (re.compile(r"\bmd5\s*\("), "MD5", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bsha1\s*\("), "SHA-1", "MESSAGE_DIGEST", "HASHING", "php-hash"),
    (re.compile(r"\bmcrypt_", re.IGNORECASE), "UNKNOWN", "CIPHER_INSTANCE", "ENCRYPTION", "mcrypt"),
    (re.compile(r"\bpassword_hash\s*\((?![^;]*\bPASSWORD_ARGON2)(?![^;]*['\"]argon2)"), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "password_hash"),
    (re.compile(r"\bopenssl_pkey_new\s*\("), "RSA", "KEY_PAIR_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"\bopenssl_sign\s*\("), "RSA", "SIGNATURE", "SIGNING", "openssl"),
    (re.compile(r"\bopenssl_verify\s*\("), "RSA", "SIGNATURE", "VERIFICATION", "openssl"),
    (re.compile(r"\bopenssl_random_pseudo_bytes\s*\("), "CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "openssl"),
    (re.compile(r"\brandom_bytes\s*\("), "CSPRNG", "KEY_GENERATOR", "KEY_GENERATION", "php-random"),
    (re.compile(r"\bsodium_crypto_secretbox"), "XSalsa20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_aead_xchacha20poly1305"), "XChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_aead_chacha20poly1305"), "ChaCha20-Poly1305", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_box"), "X25519", "CIPHER_INSTANCE", "ENCRYPTION", "libsodium"),
    (re.compile(r"\bsodium_crypto_sign"), "Ed25519", "SIGNATURE", "SIGNING", "libsodium"),
    (re.compile(r"\bsodium_crypto_pwhash"), "ARGON2", "KEY_GENERATOR", "PASSWORD_HASHING", "libsodium"),
    (re.compile(r"\bsodium_crypto_generichash"), "BLAKE2b", "MESSAGE_DIGEST", "HASHING", "libsodium"),
    (re.compile(r"\bhash_hmac\s*\("), "HMAC", "MAC", "MAC_GENERATION", "php-hash"),
    (re.compile(r"\bcrypt\s*\("), "BCRYPT", "KEY_GENERATOR", "PASSWORD_HASHING", "php-crypt"),
]


def _split_openssl(name: str) -> tuple[str, str | None, int | None]:
    upper = name.upper().replace("_", "-")
    mode = None
    for token in ("GCM", "CCM", "CTR", "CBC", "ECB", "CFB", "OFB"):
        if token in upper:
            mode = token
            break
    key_size = None
    bits = re.search(r"(\d{3,4})", upper)
    if bits:
        key_size = int(bits.group(1))
    if "AES" in upper:
        return "AES", mode, key_size
    if "DES-EDE" in upper or "DES3" in upper or "3DES" in upper:
        return "3DES", mode, key_size
    if upper.startswith("DES") or "-DES" in upper:
        return "DES", mode, key_size
    if "RC4" in upper:
        return "RC4", mode, key_size
    if "CHACHA" in upper:
        return "ChaCha20", mode, key_size
    if "BF" in upper or "BLOWFISH" in upper:
        return "Blowfish", mode, key_size
    if "CAMELLIA" in upper:
        return "Camellia", mode, key_size
    return upper, mode, key_size


_NON_CRYPTO_HASHES = {"CRC32", "CRC32B", "CRC32C", "ADLER32", "JOAAT", "MURMUR3A", "MURMUR3C", "MURMUR3F", "XXH32", "XXH64", "XXH3", "XXH128"}
_NON_CRYPTO_PREFIXES = ("FNV", "MURMUR", "XXH", "CRC")


def _map_hash(raw: str) -> str | None:
    """Map a PHP ``hash()`` algorithm name to the scanner vocabulary.

    Returns ``None`` for checksums / non-cryptographic hashes (crc32, xxh128, fnv…)
    and for strings that are not hash algorithms at all (``hash ("foo", "bar")`` in an
    SQL index DDL) — those are not cryptographic assets and must not be reported."""
    key = raw.upper().replace("_", "-")
    if key in _NON_CRYPTO_HASHES or key.startswith(_NON_CRYPTO_PREFIXES):
        return None
    known = {
        "MD2": "MD2", "MD4": "MD4", "MD5": "MD5",
        "SHA1": "SHA-1", "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
        "SHA512/224": "SHA-512", "SHA512/256": "SHA-512",
        "SHA3-224": "SHA3-224", "SHA3-256": "SHA3-256", "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512",
        "WHIRLPOOL": "WHIRLPOOL", "RIPEMD128": "RIPEMD-128", "RIPEMD160": "RIPEMD-160", "RIPEMD256": "RIPEMD-256", "RIPEMD320": "RIPEMD-320",
        "TIGER128-3": "TIGER", "TIGER160-3": "TIGER", "TIGER192-3": "TIGER", "TIGER128-4": "TIGER", "TIGER160-4": "TIGER", "TIGER192-4": "TIGER",
        "SNEFRU": "SNEFRU", "SNEFRU256": "SNEFRU", "GOST": "GOST", "GOST-CRYPTO": "GOST",
        "HAVAL128-3": "HAVAL", "HAVAL160-3": "HAVAL", "HAVAL192-3": "HAVAL", "HAVAL224-3": "HAVAL", "HAVAL256-3": "HAVAL",
        "HAVAL128-4": "HAVAL", "HAVAL160-4": "HAVAL", "HAVAL192-4": "HAVAL", "HAVAL224-4": "HAVAL", "HAVAL256-4": "HAVAL",
        "HAVAL128-5": "HAVAL", "HAVAL160-5": "HAVAL", "HAVAL192-5": "HAVAL", "HAVAL224-5": "HAVAL", "HAVAL256-5": "HAVAL",
    }
    return known.get(key)


def parse_php_file(file_path: Path, repo_root: Path | None = None) -> list[RawFinding]:
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    from scanner.parsers.c_like import strip_php_comments

    text = _desugar_php(strip_php_comments(raw))
    findings: list[RawFinding] = []
    claimed: set[tuple[int, str]] = set()

    def add(line: int, **kwargs) -> None:
        key = (line, str(kwargs.get("algorithm")))
        if key in claimed:
            return
        claimed.add(key)
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language="PHP",
                scanner_id=SCANNER_ID,
                confidence=kwargs.pop("confidence", "HIGH"),
                confidence_reason=kwargs.pop("confidence_reason", "php-crypto-api"),
                **kwargs,
            )
        )

    for match in _OPENSSL.finditer(text):
        algo, mode, key_size = _split_openssl(match.group(1))
        purpose = "DECRYPTION" if "decrypt" in match.group(0).lower() else "ENCRYPTION"
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            key_size=key_size,
            purpose=purpose,
            library="openssl",
            raw_transformation=match.group(1),
        )
    for match in _HASH.finditer(text):
        mapped = _map_hash(match.group(1))
        if mapped is None:
            continue
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MESSAGE_DIGEST",
            algorithm=mapped,
            purpose="HASHING",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for match in _HASH_HMAC.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MAC",
            algorithm=f"HMAC-{_map_hash(match.group(1))}" if _map_hash(match.group(1)) else "HMAC",
            purpose="MAC_GENERATION",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for match in _HASH_PBKDF2.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_GENERATOR",
            algorithm="PBKDF2",
            purpose="PASSWORD_HASHING",
            library="php-hash",
            raw_transformation=match.group(1),
        )
    for match in _OPENSSL_DIGEST.finditer(text):
        add(
            text[: match.start()].count("\n") + 1,
            api_type="MESSAGE_DIGEST",
            algorithm=_map_hash(match.group(1)) or "UNKNOWN",
            purpose="HASHING",
            library="openssl",
        )
    for match in _OPENSSL_PKEY.finditer(text):
        bits = None
        if match.lastindex and match.group(1):
            try:
                bits = int(match.group(1))
            except ValueError:
                bits = None
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_PAIR_GENERATOR",
            algorithm="RSA",
            purpose="KEY_GENERATION",
            library="openssl",
            key_size=bits,
        )
    for match in _MCRYPT.finditer(text):
        raw_name = match.group(1)
        if raw_name.upper().startswith("MCRYPT_"):
            # constants are resolved by php_rules (MCRYPT_RIJNDAEL_128 -> AES ...)
            continue
        algo, mode, _ = _split_openssl(raw_name)
        add(
            text[: match.start()].count("\n") + 1,
            api_type="CIPHER_INSTANCE",
            algorithm=algo,
            mode=mode,
            purpose="ENCRYPTION",
            library="mcrypt",
        )
    for match in _PASSWORD.finditer(text):
        algo = "ARGON2" if "ARGON" in match.group(1).upper() else "BCRYPT"
        add(
            text[: match.start()].count("\n") + 1,
            api_type="KEY_GENERATOR",
            algorithm=algo,
            purpose="PASSWORD_HASHING",
            library="password_hash",
        )
    for pattern, algo, api_type, purpose, library in _SIMPLE:
        for match in pattern.finditer(text):
            add(
                text[: match.start()].count("\n") + 1,
                api_type=api_type,
                algorithm=algo,
                purpose=purpose,
                library=library,
            )
    findings.extend(_resolved_php_calls(file_path, repo_root, text, claimed))
    try:
        from scanner.parsers.php_rules import run_php_rules

        seen = {(f.source.line_number, (f.crypto.algorithm or "").upper()) for f in findings}
        findings.extend(run_php_rules(file_path, repo_root, text, SCANNER_ID, seen=seen))
    except Exception as _handler_exc:  # pragma: no cover - supplementary pass must never break the parser
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        pass
    return findings


_PHP_CONCAT = re.compile(r"""(['"])([^'"\n]*)\1\s*\.\s*(['"])([^'"\n]*)\3""")
_PHP_STR_VAR = re.compile(r"""\$(\w+)\s*=\s*(['"])([^'"\n]{1,80})\2\s*;""")
_PHP_PREFIX_VAR = re.compile(r"""(\$(\w+)\s*=\s*)(['"])([A-Za-z0-9_-]{2,40})\3\s*\.\s*\$\w+[^;\n]*;""")
_PHP_KNOWN = re.compile(r"(?i)\b(?:aes|des|des-ede|des3|3des|rc4|rc2|bf|blowfish|camellia|chacha|aria|seed|sm4|sha|md5|md4|ripemd|whirlpool|rijndael)")
_PHP_INTERP = re.compile(r"\{?\$(\w+)\}?")


def _desugar_php(source: str) -> str:
    """Fold literal string constructions so variable-function calls and
    concatenated algorithm names are visible to the pattern layer:

    * ``"md" . "5"``                     -> ``"md5"``
    * ``$fn = "md5"; $fn($x)``           -> ``md5($x)``
    * ``$c = "aes-256-" . $mode``        -> ``$c = "aes-256-"`` (prefix carries the family)
    * ``"{$alg}-cbc"`` / ``"$alg-cbc"``  -> substituted from single-file string constants
    Line-preserving.
    """
    for _ in range(4):
        new = _PHP_CONCAT.sub(lambda m: '"' + m.group(2) + m.group(4) + '"', source)
        if new == source:
            break
        source = new

    def _prefix(m: re.Match) -> str:
        if _PHP_KNOWN.search(m.group(4)):
            return f'{m.group(1)}"{m.group(4)}";'
        return m.group(0)

    source = _PHP_PREFIX_VAR.sub(_prefix, source)
    consts = {m.group(1): m.group(3) for m in _PHP_STR_VAR.finditer(source)}
    if not consts:
        return source
    func_like = {k: v for k, v in consts.items() if re.fullmatch(r"[A-Za-z_]\w*", v)}
    for var, fn in func_like.items():
        # Function replacement: `fn` comes from the scanned file, and re.sub()
        # would read a backslash sequence in it as an escape reference.
        source = re.sub(rf"(?<![\w$])\${re.escape(var)}\s*\(",
                        lambda _m, _f=fn: _f + "(", source)

    def _interp(m: re.Match) -> str:
        body = m.group(0)
        if "$" not in body:
            return body
        return _PHP_INTERP.sub(lambda mm: consts.get(mm.group(1), mm.group(0)), body)

    return re.sub(r'"(?:[^"\\\n]|\\.)*"', _interp, source)


def _resolved_php_calls(
    file_path: Path,
    repo_root: Path | None,
    source: str,
    claimed: set[tuple[int, str]],
) -> list[RawFinding]:
    """openssl_encrypt($data, $cipher) / hash($name) when the name is a local string."""
    try:
        from scanner.parsers.java_ast import extract_calls, tokenize
    except Exception:
        return []
    calls, locals_map = extract_calls(tokenize(source))
    extra: list[RawFinding] = []
    specs = {
        "openssl_encrypt": ("CIPHER_INSTANCE", "ENCRYPTION", True, "openssl"),
        "openssl_decrypt": ("CIPHER_INSTANCE", "DECRYPTION", True, "openssl"),
        "hash": ("MESSAGE_DIGEST", "HASHING", False, "php-hash"),
        "hash_hmac": ("MAC", "MAC_GENERATION", False, "php-hash"),
    }
    for call in calls:
        spec = specs.get(call.name.lower())
        if spec is None or not call.args:
            continue
        api_type, purpose, cipher, library = spec
        arg = call.args[1] if cipher and len(call.args) > 1 else call.args[0]
        if not isinstance(arg, dict):
            continue
        raw = None
        if arg.get("strings"):
            raw = str(arg["strings"][0])
        else:
            for ident in arg.get("idents") or []:
                if ident in locals_map:
                    raw = locals_map[ident]
                    break
        if not raw:
            continue
        if cipher:
            algo, mode, key_size = _split_openssl(raw)
        else:
            mapped = _map_hash(raw)
            if mapped is None and api_type != "MAC":
                continue
            algo, mode, key_size = ((f"HMAC-{mapped}" if mapped else "HMAC") if api_type == "MAC" else mapped), None, None
        line = source[: int(arg.get("offset") or call.offset)].count("\n") + 1
        key = (line, str(algo))
        if key in claimed:
            continue
        claimed.add(key)
        extra.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language="PHP",
                scanner_id=SCANNER_ID,
                api_type=api_type,
                algorithm=algo,
                mode=mode,
                key_size=key_size,
                purpose=purpose,
                library=library,
                raw_transformation=raw,
            )
        )
    return extra
