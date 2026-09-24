"""Shared regex rule engine for the regex-backed language parsers.

A *rule* is ``(compiled_pattern, spec)`` where ``spec`` is a dict with at least
``algorithm``, ``api_type``, ``purpose`` and ``library``.  Optional keys:

* ``mode`` / ``padding``           - static cipher mode / padding.
* ``confidence``                   - default HIGH.
* ``key_from_group``               - regex group index holding the key size.
* ``algo_from_group`` + ``algo_map``- resolve the algorithm from a captured
                                     token through a mapping table (case-
                                     insensitive) instead of a fixed name.
* ``emit_digest_group``            - additionally emit a MESSAGE_DIGEST finding
                                     for a captured digest name (e.g. the
                                     ``EVP_sha256()`` argument of ``HMAC``).

The engine strips ``//`` and ``/* */`` comments while preserving line numbers,
de-duplicates ``(line, algorithm)`` pairs and returns :class:`RawFinding`s.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from scanner.models.raw_finding import RawFinding
from scanner.parsers.c_like import strip_c_like_comments
from scanner.parsers.finding_factory import make_finding

Rule = tuple[re.Pattern[str], dict]

# Canonical spellings of digest names as they appear inside API tokens.
DIGEST_TOKENS: dict[str, str] = {
    "md2": "MD2",
    "md4": "MD4",
    "md5": "MD5",
    "sha": "SHA-1",
    "sha1": "SHA-1",
    "sha1_for_legacy_use_only": "SHA-1",
    "sha-1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha-256": "SHA-256",
    "sha384": "SHA-384",
    "sha-384": "SHA-384",
    "sha512": "SHA-512",
    "sha-512": "SHA-512",
    "sha512_256": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3-256": "SHA3-256",
    "sha3_384": "SHA3-384",
    "sha3_512": "SHA3-512",
    "sha3-512": "SHA3-512",
    "blake2b": "BLAKE2b",
    "blake2s": "BLAKE2s",
    "blake2b512": "BLAKE2b",
    "blake2s256": "BLAKE2s",
    "ripemd160": "RIPEMD-160",
    "whirlpool": "WHIRLPOOL",
}

# Canonical spellings of cipher names as they appear inside API tokens.
CIPHER_TOKENS: dict[str, str] = {
    "aes": "AES",
    "aes128": "AES",
    "aes192": "AES",
    "aes256": "AES",
    "aes-128": "AES",
    "aes-256": "AES",
    "rijndael": "AES",
    "rijndael128": "AES",
    "rijndael-128": "AES",
    "des": "DES",
    "des-ede": "3DES",
    "des-ede3": "3DES",
    "des_ede": "3DES",
    "des_ede3": "3DES",
    "des3": "3DES",
    "3des": "3DES",
    "tripledes": "3DES",
    "desede": "3DES",
    "rc2": "RC2",
    "rc4": "RC4",
    "arc4": "RC4",
    "arcfour": "RC4",
    "rc5": "RC5",
    "bf": "Blowfish",
    "blowfish": "Blowfish",
    "cast": "CAST5",
    "cast5": "CAST5",
    "cast-128": "CAST5",
    "idea": "IDEA",
    "seed": "SEED",
    "camellia": "Camellia",
    "camellia128": "Camellia",
    "camellia256": "Camellia",
    "aria": "ARIA",
    "sm4": "SM4",
    "twofish": "Twofish",
    "serpent": "Serpent",
    "chacha20": "ChaCha20",
    "chacha20-poly1305": "ChaCha20-Poly1305",
    "chacha20_poly1305": "ChaCha20-Poly1305",
    "xchacha20": "XChaCha20-Poly1305",
    "salsa20": "Salsa20",
    "xsalsa20": "XSalsa20-Poly1305",
}

MODE_TOKENS = {"ecb", "cbc", "cfb", "cfb1", "cfb8", "cfb128", "ofb", "ctr", "gcm", "ccm", "xts", "ocb", "wrap", "siv", "cts"}


def resolve_token(token: str, table: dict[str, str]) -> str | None:
    """Look a captured API token up in ``table`` (case-insensitive, ``_``/``-`` tolerant)."""
    if not token:
        return None
    t = token.lower()
    for candidate in (t, t.replace("_", "-"), t.replace("-", "_"), t.replace("_", ""), t.replace("-", "")):
        if candidate in table:
            return table[candidate]
    return None


def split_cipher_token(token: str) -> tuple[str | None, str | None, int | None]:
    """``aes_256_cbc`` -> (AES, CBC, 256); ``des_ede3_cbc`` -> (3DES, CBC, None)."""
    parts = [p for p in re.split(r"[-_]", token.lower()) if p]
    if not parts:
        return None, None, None
    mode = None
    size = None
    for p in parts[1:]:
        if p in MODE_TOKENS:
            mode = p.upper()
        elif p.isdigit() and int(p) in (40, 56, 64, 112, 128, 168, 192, 256, 512):
            size = int(p)
    head = parts[0]
    algo = None
    if head == "des" and len(parts) > 1 and parts[1] in ("ede", "ede3"):
        algo = "3DES"
    elif head == "chacha20" and "poly1305" in parts:
        algo = "ChaCha20-Poly1305"
    elif head == "aes" and "gcm" in parts and "siv" in parts:
        algo = "AES"
        mode = "GCM-SIV"
    else:
        algo = CIPHER_TOKENS.get(head) or CIPHER_TOKENS.get(f"{head}{parts[1]}" if len(parts) > 1 else head)
    return algo, mode, size


def expand_macros(text: str) -> str:
    """Inline simple object-like / function-like ``#define`` bodies so that
    ``#define CIPHER() EVP_des_ede3_cbc()`` followed by ``CIPHER()`` is seen as
    the real call.  Only single-line macros are handled; the define line itself
    is kept so the finding can also attribute to it."""
    macros: dict[str, str] = {}
    for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)(\([^)]*\))?[ \t]+(.+?)[ \t]*$", text, re.M):
        name, params, body = m.group(1), m.group(2), m.group(3)
        if "\\" in body or len(body) > 200:
            continue
        macros[name] = (params, body)
    if not macros:
        return text
    out_lines = []
    for line in text.split("\n"):
        if re.match(r"^[ \t]*#[ \t]*define\b", line):
            out_lines.append(line)
            continue
        for name, (params, body) in macros.items():
            if name not in line:
                continue
            if params is None:
                line = re.sub(rf"\b{re.escape(name)}\b", body, line)
            else:
                line = re.sub(rf"\b{re.escape(name)}\s*\([^)]*\)", body.replace("\\", "\\\\"), line)
        out_lines.append(line)
    return "\n".join(out_lines)


def run_rules(
    *,
    file_path: Path,
    repo_root: Path | None,
    text: str,
    rules: Iterable[Rule],
    language: str,
    scanner_id: str,
    confidence_reason: str,
    strip_comments: bool = True,
    macros: bool = False,
    seen: set[tuple[int, str]] | None = None,
) -> list[RawFinding]:
    if strip_comments:
        text = strip_c_like_comments(text)
    if macros:
        text = expand_macros(text)
    findings: list[RawFinding] = []
    seen = seen if seen is not None else set()

    def emit(line: int, algorithm: str, spec: dict, match: re.Match, *, mode=None, key_size=None, api_type=None, purpose=None):
        key = (line, algorithm.upper())
        if key in seen:
            return
        seen.add(key)
        findings.append(
            make_finding(
                file_path=file_path,
                repo_root=repo_root,
                line_number=line,
                language=language,
                scanner_id=scanner_id,
                api_type=api_type or spec["api_type"],
                algorithm=algorithm,
                purpose=purpose or spec["purpose"],
                library=spec["library"],
                mode=mode if mode is not None else spec.get("mode"),
                padding=spec.get("padding"),
                key_size=key_size if key_size is not None else spec.get("key_size"),
                confidence=spec.get("confidence", "HIGH"),
                confidence_reason=spec.get("confidence_reason", confidence_reason),
                raw_transformation=match.group(0)[:80],
            )
        )

    for pattern, spec in rules:
        for match in pattern.finditer(text):
            line = text[: match.start()].count("\n") + 1
            algorithm = spec.get("algorithm")
            mode = None
            key_size = None
            if spec.get("key_from_group"):
                try:
                    key_size = int(match.group(spec["key_from_group"]))
                except (IndexError, TypeError, ValueError):
                    key_size = None
            if spec.get("transformation_group"):
                # JCA-style "ALG/MODE/PADDING" string → registry parser
                token = match.group(spec["transformation_group"]) or ""
                try:
                    from scanner.extractors.algorithm_extractor import parse_transformation

                    parsed = parse_transformation(token)
                    algorithm = parsed.algorithm or token
                    mode = parsed.mode
                except Exception:  # pragma: no cover - defensive
                    algorithm = token
                if not algorithm:
                    continue
            elif spec.get("algo_from_group"):
                token = match.group(spec["algo_from_group"]) or ""
                if spec.get("algo_map") is CIPHER_TOKENS or spec.get("split_cipher"):
                    algorithm, mode, size = split_cipher_token(token)
                    key_size = key_size or size
                else:
                    algorithm = resolve_token(token, spec["algo_map"])
                if not algorithm:
                    continue
            if algorithm:
                emit(line, algorithm, spec, match, mode=mode, key_size=key_size)
            if spec.get("emit_digest_group"):
                try:
                    dtoken = match.group(spec["emit_digest_group"]) or ""
                except IndexError:
                    dtoken = ""
                digest = resolve_token(dtoken, DIGEST_TOKENS)
                if digest:
                    emit(line, digest, spec, match, api_type="MESSAGE_DIGEST", purpose="HASHING")
    return findings
