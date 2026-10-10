"""Alias canonicalization for algorithm names (report 53's collision
catalogue, deep/23 §1 — round 25).

The catalogue documents variant spellings that normalized to *themselves*
instead of one canonical identity — ``AES256``/``AES_256`` stayed
``AES256`` while ``RSA2048`` became ``RSA-2048``; ``secp256r1`` and
``prime256v1`` never became ``P-256``; ``HMACSHA256`` never became
``HMAC-SHA256``. The consequence was real: the same algorithm discovered
under two spellings produced two graph nodes and two CBOM components.

This module is a *rescue layer*, not a rewrite: the processor only
consults it when the raw string does not already exact-match a rule, so
every working normalization path is untouched. Two families of rescue:

* compound spellings — the catalogue's un-hyphenated / underscored
  variants mapped to their canonical hyphenated forms;
* case — a lowercase input (``aes-256``) is retried uppercased.

Deliberately NOT aliased: ``P-256`` → some ECDSA/ECDH name. A curve is a
curve; whether it is used for signatures or key agreement is a purpose
decision the engine makes from context, and the catalogue's own §5 treats
curve names as curve identities. All spellings of one curve collapse to
one canonical curve name — nothing more is fabricated.
"""

from __future__ import annotations

import re

# Report 53 §2.2 + §5.1 — verified-colliding variants -> canonical form.
# Keys are UPPERCASED at lookup; values are exact-match rule inputs.
_ALIASES: dict[str, str] = {
    # symmetric compound spellings
    "AES128": "AES-128",
    "AES_128": "AES-128",
    "AES192": "AES-192",
    "AES_192": "AES-192",
    "AES256": "AES-256",
    "AES_256": "AES-256",
    # asymmetric compound spellings (RSA2048 already pattern-matches;
    # the underscore forms did not)
    "RSA_1024": "RSA-1024",
    "RSA_2048": "RSA-2048",
    "RSA_3072": "RSA-3072",
    "RSA_4096": "RSA-4096",
    # signature compound spellings
    "ECDSA_P256": "ECDSA-P256",
    "ECDSA_P384": "ECDSA-P384",
    "ECDSA_P521": "ECDSA-P521",
    # hash underscore spellings (SHA_384 previously pattern-extracted a
    # bogus key_size=384 — the digest size — from the name)
    "SHA_224": "SHA-224",
    "SHA_256": "SHA-256",
    "SHA_384": "SHA-384",
    "SHA_512": "SHA-512",
    # MAC run-together spellings
    "HMACSHA1": "HMAC-SHA1",
    "HMACSHA256": "HMAC-SHA256",
    "HMACSHA384": "HMAC-SHA384",
    "HMACSHA512": "HMAC-SHA512",
    # curve aliases — one canonical spelling per curve (§5.1)
    "SECP256R1": "P-256",
    "PRIME256V1": "P-256",
    "SECP384R1": "P-384",
    "SECP521R1": "P-521",
    "CURVE25519": "X25519",
}

# inputs that are pure noise for case-rescue (already upper, no letters)
_UPPER_RE = re.compile(r"[a-z]")


def canonicalize(raw: str) -> str:
    """The canonical spelling for a raw algorithm string, or the input
    unchanged when no alias applies. Never raises, never guesses."""
    if not raw:
        return raw
    stripped = raw.strip()
    upper = stripped.upper()
    mapped = _ALIASES.get(upper)
    if mapped is not None:
        return mapped
    if _UPPER_RE.search(stripped):
        return upper  # lowercase variant of a canonical spelling
    return stripped
