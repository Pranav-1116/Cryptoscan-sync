"""Shared regex rule engine for the regex-backed language parsers.

A *rule* is ``(compiled_pattern, spec)`` where ``spec`` is a dict with at least
``algorithm``, ``api_type``, ``purpose`` and ``library``.  Optional keys:

* ``mode`` / ``padding``           - static cipher mode / padding.
* ``confidence``                   - default HIGH.
* ``key_from_group``               - regex group index holding the key size.
* ``algo_from_group`` + ``algo_map``- resolve the algorithm from a captured
                                     token through a mapping table (case-
                                     insensitive) instead of a fixed name.
* ``mode_from_group``              - regex group index holding the cipher mode.
* ``file_context``                 - regex the whole file must match before the rule is tried
* ``line_group``                   - regex group whose start position gives the reported line
* ``raw_group``                    - regex group whose text becomes raw_transformation
                                     (cipher lists are expanded per algorithm downstream).
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
            # Both arms take the macro `body` literally. A function replacement
            # is template-free by construction, so a backslash in the body
            # cannot be misread as a group reference -- the parameterised arm
            # below already hand-escaped for this, the bare arm did not.
            if params is None:
                line = re.sub(rf"\b{re.escape(name)}\b", lambda _m, _b=body: _b, line)
            else:
                line = re.sub(rf"\b{re.escape(name)}\s*\([^)]*\)", lambda _m, _b=body: _b, line)
        out_lines.append(line)
    return "\n".join(out_lines)


_LITERAL_CACHE: dict[int, tuple[frozenset[str], ...] | None] = {}
_LITERAL_WORD = re.compile(r"[a-z0-9_]{4,}")


def _split_top_level(pattern: str) -> list[str]:
    """Split a regex on ``|`` at nesting depth 0 (outside groups and classes)."""
    parts, depth, in_class, buf, i = [], 0, False, [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            buf.append(pattern[i : i + 2]); i += 2; continue
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            parts.append("".join(buf)); buf = []; i += 1; continue
        buf.append(ch); i += 1
    parts.append("".join(buf))
    return parts


def _required_literals(alternative: str) -> frozenset[str]:
    """Lower-cased literal words that *must* appear in any match of ``alternative``.

    Conservative: only depth-0 text is considered (anything inside a group may be
    optional or one of several branches), and a literal immediately followed by a
    quantifier that allows zero repetitions (``?``, ``*``, ``{0,``) is dropped.
    Returns an empty set when nothing can be proven, which disables the prefilter."""
    out, depth, in_class, i, cur = [], 0, False, 0, []
    def flush(next_ch: str):
        word = "".join(cur)
        cur.clear()
        if not word:
            return
        if next_ch and next_ch in "?*{":
            word = word[:-1]  # last char is optional
        out.append(word)
    while i < len(alternative):
        ch = alternative[i]
        if ch == "\\":
            flush(""); i += 2; continue  # a quantifier after an escape binds to the escape
        if in_class:
            if ch == "]":
                in_class = False
            i += 1; continue
        if ch == "[":
            flush(""); in_class = True; i += 1; continue
        if ch == "(":
            flush(""); depth += 1; i += 1; continue
        if ch == ")":
            depth -= 1; i += 1; continue
        if depth > 0:
            i += 1; continue
        if ch.isalnum() or ch == "_":
            cur.append(ch.lower())
        else:
            flush(ch if ch in "?*{" else "")
        i += 1
    flush("")
    words = set()
    for w in out:
        for m in _LITERAL_WORD.finditer(w):
            words.add(m.group(0))
    return frozenset(words)


def _prefilter(pattern: "re.Pattern[str]") -> tuple[frozenset[str], ...] | None:
    key = id(pattern)
    if key in _LITERAL_CACHE:
        return _LITERAL_CACHE[key]
    alts = []
    for alt in _split_top_level(pattern.pattern):
        lits = _required_literals(alt)
        if not lits:
            _LITERAL_CACHE[key] = None  # one alternative has no provable literal → never skip
            return None
        alts.append(lits)
    result = tuple(alts)
    _LITERAL_CACHE[key] = result
    return result


def _may_match(pattern: "re.Pattern[str]", lower_text: str) -> bool:
    """Cheap literal prefilter: a rule can only match if, for at least one of its
    top-level alternatives, every required literal word occurs in the text."""
    alts = _prefilter(pattern)
    if alts is None:
        return True
    for lits in alts:
        if all(lit in lower_text for lit in lits):
            return True
    return False


_STRING_LITERAL = re.compile(
    r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*\"""",
    re.S,
)


def _string_literal_spans(text: str) -> list[tuple[int, int]]:
    """Ordered, non-overlapping (start, end) spans of quoted string literals.

    Single- and double-quoted, backslash escapes honoured, unterminated quotes
    ignored (the regex requires a closing quote on the same line). Backticks
    are deliberately excluded: JS templates routinely wrap real interpolated
    code, and the desugaring pass already folds the static ones.
    """
    return [m.span() for m in _STRING_LITERAL.finditer(text)]


def _raw_of(match: re.Match, spec: dict) -> str:
    """``raw_group`` lets a rule expose the *value* (e.g. a cipher list) instead of the whole match."""
    g = spec.get("raw_group")
    if g == "any":  # first populated capture (alternations with one value group each)
        val = next((x for x in match.groups() if x), None)
        if val:
            return val[:200]
    elif g:
        try:
            val = match.group(g)
        except IndexError:
            val = None
        if val:
            return val[:200]
    return match.group(0)[:80]


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
                raw_transformation=_raw_of(match, spec),
            )
        )

    lower_text = text.lower()
    _string_spans_cache: list[tuple[int, int]] | None = None

    def _in_string_literal(pos: int) -> bool:
        """True when ``pos`` falls inside a quoted string literal.

        Only consulted for *invocation* matches (see below). Algorithm names
        are legitimately string literals ("AES/GCM/NoPadding"), so this must
        never be applied to them.
        """
        nonlocal _string_spans_cache
        if _string_spans_cache is None:
            _string_spans_cache = _string_literal_spans(text)
        spans = _string_spans_cache
        lo, hi = 0, len(spans)
        while lo < hi:  # binary search: spans are ordered and non-overlapping
            mid = (lo + hi) // 2
            start, end = spans[mid]
            if pos < start:
                hi = mid
            elif pos >= end:
                lo = mid + 1
            else:
                return True
        return False

    for pattern, spec in rules:
        if not _may_match(pattern, lower_text):
            continue
        if spec.get("file_context") and not re.search(spec["file_context"], text):
            continue  # rule only applies to files that establish a context (e.g. a Thales HSM client class)
        for match in pattern.finditer(text):
            whole = match.group(0)
            # An invocation (the match ends at a "(") that begins inside a
            # string literal is text about code, not code. Data files carry
            # these: caniuse-lite lists the feature name "crypto.getRandomValues()"
            # as a plain string, which was reported as a live CSPRNG call site.
            if whole.rstrip().endswith("(") and _in_string_literal(match.start()):
                continue
            # ``(?m)^\s*x`` can start on the previous blank line; report where the text starts
            line = text[: match.start() + len(whole) - len(whole.lstrip())].count("\n") + 1
            if spec.get("line_group"):
                # context rules that start on an earlier line (``token ... \n ... random()``) report the API line
                try:
                    gstart = match.start(spec["line_group"])
                    if gstart >= 0:
                        line = text[:gstart].count("\n") + 1
                except IndexError:
                    pass
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
                    # PBEWithHmacSHA512AndAES_256 / SHA256withRSA / PBKDF2WithHmacSHA1:
                    # the PRF / digest is a second algorithm in use on this line.
                    extra_digest = getattr(parsed, "hash_algorithm", None)
                    if extra_digest and extra_digest.upper() != algorithm.upper():
                        emit(line, extra_digest, spec, match, api_type="MESSAGE_DIGEST", purpose="HASHING")
                    if re.search(r"(?i)with\s*hmac|hmac", token) and algorithm.upper() != "HMAC":
                        emit(line, "HMAC", spec, match, api_type="MAC", purpose="MAC_GENERATION")
                except Exception:  # pragma: no cover - defensive
                    algorithm = token
                if not algorithm:
                    continue
            elif spec.get("algo_from_group"):
                token = match.group(spec["algo_from_group"]) or ""
                if not token:  # alternation: take the first populated capture
                    token = next((g for g in match.groups() if g), "")
                if spec.get("algo_map") is CIPHER_TOKENS or spec.get("split_cipher"):
                    algorithm, mode, size = split_cipher_token(token)
                    key_size = key_size or size
                else:
                    algorithm = resolve_token(token, spec["algo_map"])
                if not algorithm:
                    continue
            if spec.get("mode_from_group") and mode is None:
                try:
                    mode = (match.group(spec["mode_from_group"]) or "").upper() or None
                except IndexError:
                    mode = None
            if algorithm:
                emit(line, algorithm, spec, match, mode=mode, key_size=key_size)
            if spec.get("emit_digest_group"):
                try:
                    dtoken = match.group(spec["emit_digest_group"]) or ""
                except IndexError:
                    dtoken = ""
                if not dtoken and spec["emit_digest_group"] != spec.get("algo_from_group"):
                    dtoken = next((g for g in match.groups() if g and resolve_token(g, DIGEST_TOKENS)), "")
                digest = resolve_token(dtoken, DIGEST_TOKENS)
                if digest:
                    emit(line, digest, spec, match, api_type="MESSAGE_DIGEST", purpose="HASHING")
    return findings


_CLASS_DECL = re.compile(r"\b(?:class|struct|interface|type)\s+\w+")
_SECURITY_CONTEXT = re.compile(
    r"key|(?<!cancellation)token|secret|nonce|salt|passw|session|otp|csrf|\biv\b|seed|entropy|"
    r"cred|auth|sign|cookie|challenge|verif|uuid|(?<![a-z])id\b",
    re.IGNORECASE,
)


def filter_prng_context(findings: list[RawFinding], text: str, func_decl: "re.Pattern[str]") -> list[RawFinding]:
    """math/rand is everywhere (shuffling test data, jitter, sampling). Only report
    it as a weak *cryptographic* RNG when the call sits in a security-flavoured
    context: the statement itself or the enclosing function name mentions keys,
    tokens, secrets, sessions, ids... Everything else is not a crypto asset."""
    if not any(f.crypto.algorithm == "PRNG" for f in findings):
        return findings
    lines = text.splitlines()
    kept: list[RawFinding] = []
    for f in findings:
        if f.crypto.algorithm != "PRNG":
            kept.append(f)
            continue
        ln = (f.source.line_number or 1) - 1
        window = lines[ln] if ln < len(lines) else ""
        found_func = found_class = False
        for back in range(ln, max(-1, ln - 120), -1):
            if back >= len(lines):
                continue
            if not found_func and func_decl.search(lines[back]):
                window += "\n" + lines[back]
                found_func = True
            elif not found_class and _CLASS_DECL.search(lines[back]):
                window += "\n" + lines[back]
                found_class = True
            if found_func and found_class:
                break
        if _SECURITY_CONTEXT.search(window):
            kept.append(f)
    return kept
