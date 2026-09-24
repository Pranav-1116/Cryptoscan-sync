"""Decompose TLS cipher-suite spellings into algorithm families.

Handles both IANA names (``TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256``) and
OpenSSL cipher strings (``ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:!aNULL``).
Tokens excluded with ``!`` or ``-`` are ignored; keyword groups (HIGH,
MEDIUM, DEFAULT, kRSA ...) contribute nothing because they name policies,
not algorithms.

    >>> sorted(a for a, _ in suite_components("RC4-SHA:DES-CBC3-SHA:!aNULL"))
    ['3DES', 'RC4', 'SHA-1']
"""
from __future__ import annotations

import re
from typing import Iterable

_IANA = re.compile(r"\b(?:TLS|SSL)_[A-Z0-9_]+?_WITH_[A-Z0-9_]+|\bTLS_(?:AES_(?:128|256)_(?:GCM|CCM(?:_8)?)_SHA(?:256|384)|CHACHA20_POLY1305_SHA256)\b")
_OPENSSL_TOKEN = re.compile(r"[A-Za-z0-9+\-]+")
_KEYWORDS = {
    "HIGH", "MEDIUM", "LOW", "DEFAULT", "COMPLEMENTOFDEFAULT", "ALL", "COMPLEMENTOFALL", "FIPS", "SUITEB128",
    "SUITEB192", "STRENGTH", "SECURE128", "SECURE256", "PFS", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.2", "TLSV1.3",
    "ANULL", "ENULL", "AECDH", "ADH", "KRSA", "KEDH", "KDHE", "KEECDH", "KECDHE", "KPSK", "PSK", "SRP", "AGCM",
    "AESGCM", "SHA", "AECDSA", "ARSA", "ADSS",
}

# (regex on the upper-cased token, family, api_type). Order matters: 3DES
# before DES, SHA256 before SHA, ECDHE before DH/RSA.
_COMPONENTS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"3DES|DES-CBC3|DES_EDE3|DES-EDE3"), "3DES", "CIPHER_INSTANCE"),
    (re.compile(r"(?<![A-Z0-9])DES(?:[_-](?:CBC|40|64)|$)(?![A-Z0-9]*3)|EXP-DES|DES-CBC-SHA"), "DES", "CIPHER_INSTANCE"),
    (re.compile(r"RC4|ARCFOUR"), "RC4", "CIPHER_INSTANCE"),
    (re.compile(r"RC2"), "RC2", "CIPHER_INSTANCE"),
    (re.compile(r"IDEA"), "IDEA", "CIPHER_INSTANCE"),
    (re.compile(r"SEED"), "SEED", "CIPHER_INSTANCE"),
    (re.compile(r"CAMELLIA"), "Camellia", "CIPHER_INSTANCE"),
    (re.compile(r"ARIA"), "ARIA", "CIPHER_INSTANCE"),
    (re.compile(r"AES(?:[_-]?(?:128|256))?"), "AES", "CIPHER_INSTANCE"),
    (re.compile(r"CHACHA20"), "ChaCha20-Poly1305", "CIPHER_INSTANCE"),
    (re.compile(r"(?:^|[_-])(?:E)?NULL(?:[_-]|$)"), "NULL-CIPHER", "CIPHER_INSTANCE"),
    (re.compile(r"(?:^|[_-])EXP(?:ORT)?(?:1024|40|56)?(?:[_-]|$)"), "EXPORT-CIPHER", "CIPHER_INSTANCE"),
    (re.compile(r"MD5"), "MD5", "MESSAGE_DIGEST"),
    (re.compile(r"SHA256"), "SHA-256", "MESSAGE_DIGEST"),
    (re.compile(r"SHA384"), "SHA-384", "MESSAGE_DIGEST"),
    (re.compile(r"SHA512"), "SHA-512", "MESSAGE_DIGEST"),
    (re.compile(r"(?:^|[_-])SHA1?(?:[_-]|$)"), "SHA-1", "MESSAGE_DIGEST"),
    (re.compile(r"ECDHE?(?:[_-]|$)|(?:^|[_-])ECDH(?:[_-]|$)"), "ECDH", "KEY_AGREEMENT"),
    (re.compile(r"(?:^|[_-])(?:DHE|EDH|DH)(?:[_-]|$)|DHE-"), "DH", "KEY_AGREEMENT"),
    (re.compile(r"ECDSA"), "ECDSA", "SIGNATURE"),
    (re.compile(r"(?:^|[_-])(?:DSS|DSA)(?:[_-]|$)"), "DSA", "SIGNATURE"),
    (re.compile(r"(?:^|[_-])RSA(?:[_-]|$)|^RSA"), "RSA", "KEY_AGREEMENT"),
    (re.compile(r"(?:^|[_-])PSK(?:[_-]|$)"), "PSK", "KEY_AGREEMENT"),
    (re.compile(r"(?:^|[_-])SRP(?:[_-]|$)"), "SRP", "KEY_AGREEMENT"),
    (re.compile(r"GOST"), "GOST", "CIPHER_INSTANCE"),
]

_SUITE_HINT = re.compile(
    r"(?i)(?:\bTLS_[A-Z0-9_]*WITH_|\bTLS_AES_|\bTLS_CHACHA20|ECDHE|\bDHE\b|EDH|AES(?:128|256)|DES-CBC3|3DES|RC4|CHACHA20|"
    r"\bNULL\b|aNULL|eNULL|kRSA|\bEXP(?:ORT)?\b|-SHA(?:256|384)?(?::|$|\b)|\bHIGH\b|\bMEDIUM\b|\bLOW\b)"
)


def looks_like_cipher_string(text: str | None) -> bool:
    """True when ``text`` is plausibly a TLS cipher list / suite name."""
    if not text:
        return False
    return bool(_SUITE_HINT.search(text))


def _tokens(text: str) -> Iterable[str]:
    # IANA names first (they contain underscores, keep whole)
    consumed: list[tuple[int, int]] = []
    for m in _IANA.finditer(text):
        consumed.append(m.span())
        yield m.group(0).upper()
    # OpenSSL colon/space/comma separated tokens
    for m in _OPENSSL_TOKEN.finditer(text):
        if any(s <= m.start() < e for s, e in consumed):
            continue
        tok = m.group(0)
        yield tok.upper()


def suite_components(text: str | None) -> list[tuple[str, str]]:
    """Return unique ``(family, api_type)`` pairs named by a cipher string."""
    if not text:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    # split on separators that carry inclusion semantics
    for raw_tok in re.split(r"[:,\s]+", text.strip()):
        if not raw_tok:
            continue
        if raw_tok.startswith(("!", "-")):
            continue  # excluded from the list: not in use
        tok = raw_tok.lstrip("+@").upper()
        if not tok or tok in _KEYWORDS or "=" in tok:
            continue
        for sub in _tokens(tok):
            if sub in _KEYWORDS:
                continue
            for rx, family, api_type in _COMPONENTS:
                if family in seen:
                    continue
                if rx.search(sub):
                    seen.add(family)
                    out.append((family, api_type))
    return out
