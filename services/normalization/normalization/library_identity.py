"""Library identity normalization (audit 70, round 29).

The same crypto library arrives under many names: ``OpenSSL`` from a
questionnaire, ``libssl.so.1.1`` from a runtime process listing,
``openssl 1.1.1k`` from a version string, ``bcprov`` from a JVM classpath.
Nothing canonicalized those to one identity, so the same library stayed
multiple things across assets and sources (audit 70's open item).

This module maps free-form library names onto the platform's library
registry (``universal_crypto.library_fingerprints.LIBRARIES`` — the same
canonical identities the fingerprinter confirms against artifact
evidence), with deterministic matching:

* soname / packaging noise is stripped (``libssl.so.1.1``, ``py-openssl``,
  ``python-cryptography``, ``.dylib`` / ``.dll`` suffixes);
* matching is case/punctuation-insensitive over the registry's names,
  markers and provider tokens — the marker set is exactly what the
  fingerprinter trusts, so the two surfaces cannot disagree;
* versions are normalized (``v``-prefix, OpenSSL letter suffixes like
  ``1.1.1k`` split into base + patch-letter, separator noise);
* an unmatched name is returned **unmatched** with its cleaned form —
  never forced onto the nearest registry entry.

Pure functions; no database, no clock, no network.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

try:  # the registry lives in universal_crypto; normalization must not
    # hard-require it at import time for unrelated consumers
    from universal_crypto.library_fingerprints import LIBRARIES
except Exception:  # pragma: no cover — registry always present in-tree
    LIBRARIES = []

#: packaging/soname prefixes and suffixes that carry no identity
_STRIP_PREFIXES = ("lib", "py-", "python-", "node-", "js-")
_STRIP_SUFFIXES = (".so", ".dylib", ".dll", ".jar", ".a")

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})([a-z])?(?:[-_+.]|$)")
_EPOCH_RE = re.compile(r"^\d+!")


def _base_clean(raw: str) -> str:
    """Lowercase, split version tails, strip soname/packaging suffixes —
    but KEEP ``lib``-style prefixes (``libssl`` is an identity, not noise)."""
    text = str(raw or "").strip().lower()
    # split off any version tail first: "openssl 1.1.1k", "botan-2.19"
    text = re.split(r"[\s]+", text)[0] if " " in text else text
    # strip trailing soname version groups BEFORE the library suffix:
    # libssl.so.1.1 -> libssl.so -> libssl
    text = re.sub(r"(\.\d+)+$", "", text)
    for suffix in _STRIP_SUFFIXES:
        if text.endswith(suffix):
            text = text[: -len(suffix)]
            break
    return re.sub(r"[^a-z0-9+]+", "", text)


def _clean_name(raw: str) -> str:
    """The stripped form: packaging prefixes removed when what remains
    is still a real identity (``libbotan`` -> ``botan``)."""
    text = _base_clean(raw)
    for prefix in _STRIP_PREFIXES:
        if text.startswith(prefix) and len(text) > len(prefix):
            stripped = text[len(prefix):]
            if stripped not in _GENERIC_TOKENS:
                return stripped
            break
    return text


def normalize_version(raw: Any) -> dict[str, Any]:
    """Normalize a version string; unknown shapes pass through cleaned.

    ``1.1.1k`` -> ``{version: "1.1.1", patch_letter: "k"}`` (the OpenSSL
    letter is a patch level, not part of the dotted triple); ``v3.2.0``
    -> ``{version: "3.2.0"}``; ``2!1.0`` -> epoch ``2``.
    """
    text = str(raw or "").strip().lower().lstrip("v")
    if not text:
        return {"version": None}
    epoch = None
    if _EPOCH_RE.match(text):
        epoch = int(text.split("!", 1)[0])
        text = text.split("!", 1)[1]
    match = _VERSION_RE.search(text)
    if not match:
        return {"version": text or None}
    out: dict[str, Any] = {"version": match.group(1)}
    if match.group(2):
        out["patch_letter"] = match.group(2)
    if epoch is not None:
        out["epoch"] = epoch
    return out


#: tokens too generic to match on (exact or containment): they name the
#: whole domain, not a library — an input that cleans to one of these
#: is honestly ambiguous and stays unmatched
_GENERIC_TOKENS = frozenset({"crypto", "ssl", "tls", "security"})


def _registry_index() -> list[tuple[str, set[str], dict[str, Any]]]:
    """(cleaned registry name, token set, registry entry) rows.

    Tokens include BOTH the full form (``libssl``) and the prefix-stripped
    form (``botan``) of every name/marker/provider, so sonames and package
    names both exact-match.
    """
    rows = []
    for entry in LIBRARIES:
        name = str(entry.get("name") or "")
        tokens = set()
        for token_source in [name, *(entry.get("markers") or []),
                             str(entry.get("provider") or "")]:
            for form in (_base_clean(token_source), _clean_name(token_source)):
                if form and form not in _GENERIC_TOKENS:
                    tokens.add(form)
        rows.append((_clean_name(name), tokens, entry))
    return rows


_INDEX = _registry_index()

#: well-known alias spellings that cleaning alone cannot reach
_ALIASES: dict[str, str] = {
    "bcprov": "BouncyCastle",
    "bouncycastlejava": "BouncyCastle",
    "bouncycastlecsharp": "BouncyCastle",
    "cryptopp": "Crypto++",
    "cryptoplusplus": "Crypto++",
    "mbedtls": "mbedTLS",
    "polarssl": "mbedTLS",
    "sodium": "libsodium",
    "nacl": "libsodium",
    "dotnetcryptography": ".NET cryptography",
    "netcryptography": ".NET cryptography",
    "gocrypto": "Go crypto/*",
    "nodecrypto": "Node crypto",
    "pycryptodome": "PyCryptodome",
    "pycryptodomex": "PyCryptodome",
    "pythoncryptography": "Python cryptography",
    "pythonhashlib": "Python hashlib",
    "jssecrypt": "JCA-JCE",
}


def canonical_library(name: str, version: Any = None) -> dict[str, Any]:
    """Canonicalize one free-form library identity.

    Returns ``{canonical_name, matched, provider, matched_on,
    raw_name, version_info}``. Unmatched names come back with
    ``matched: False`` and their cleaned form — never a guess.
    """
    raw_name = str(name or "").strip()
    base = _base_clean(raw_name)
    cleaned = _clean_name(raw_name)
    version_info = normalize_version(version)

    if not base or (base in _GENERIC_TOKENS and cleaned in _GENERIC_TOKENS):
        # a name that cleans to a domain word ("crypto", "ssl") names no
        # particular library — honestly unmatched, never guessed
        return {"canonical_name": raw_name or None, "matched": False, "provider": None,
                "matched_on": None, "raw_name": raw_name, "version_info": version_info}

    # 1. exact alias table
    alias_target = _ALIASES.get(cleaned)
    if alias_target:
        for _, tokens, entry in _INDEX:
            if str(entry.get("name")) == alias_target:
                return {"canonical_name": entry["name"], "matched": True,
                        "provider": entry.get("provider"), "matched_on": "alias",
                        "raw_name": raw_name, "version_info": version_info}

    # 2. exact cleaned-name / marker / provider match (full or stripped form)
    for reg_name, tokens, entry in _INDEX:
        if cleaned == reg_name or base in tokens or cleaned in tokens:
            return {"canonical_name": entry["name"], "matched": True,
                    "provider": entry.get("provider"),
                    "matched_on": "name" if cleaned == reg_name else "marker",
                    "raw_name": raw_name, "version_info": version_info}

    # 3. containment: the cleaned name contains a registry token
    # (or vice versa) — "opensslfips" contains "openssl"
    for reg_name, tokens, entry in _INDEX:
        if any(token and (token in base or token in cleaned
                          or base in token or cleaned in token)
               for token in tokens):
            return {"canonical_name": entry["name"], "matched": True,
                    "provider": entry.get("provider"), "matched_on": "contains",
                    "raw_name": raw_name, "version_info": version_info}

    return {"canonical_name": raw_name or None, "matched": False, "provider": None,
            "matched_on": None, "raw_name": raw_name, "version_info": version_info}


def merge_library_identities(entries: Iterable[Any]) -> dict[str, Any]:
    """Group raw library entries under their canonical identities.

    ``entries`` are anything stringifiable (names, or ``{"name": ...,
    "version": ...}`` dicts). Returns one group per canonical identity
    with its raw spellings — the dedup view audit 70 asked for.
    """
    groups: dict[str, dict[str, Any]] = {}
    for entry in entries or []:
        if isinstance(entry, dict):
            raw_name = str(entry.get("name") or entry.get("library") or "")
            version = entry.get("version")
        else:
            raw_name, version = str(entry), None
        if not raw_name:
            continue
        result = canonical_library(raw_name, version)
        key = result["canonical_name"] or f"UNMATCHED:{raw_name}"
        group = groups.setdefault(key, {
            "canonical_name": result["canonical_name"],
            "matched": result["matched"],
            "provider": result["provider"],
            "raw_names": set(),
            "versions": set(),
        })
        group["raw_names"].add(raw_name)
        version_value = (result["version_info"] or {}).get("version")
        if version_value:
            group["versions"].add(str(version_value))

    out = []
    for key in sorted(groups):
        group = groups[key]
        out.append({
            "canonical_name": group["canonical_name"],
            "matched": group["matched"],
            "provider": group["provider"],
            "raw_names": sorted(group["raw_names"]),
            "versions": sorted(group["versions"]),
            "alias_count": len(group["raw_names"]),
        })
    matched = sum(1 for g in out if g["matched"])
    return {
        "groups": out,
        "group_count": len(out),
        "matched_count": matched,
        "unmatched_count": len(out) - matched,
        "method": {
            "registry": "universal_crypto.library_fingerprints.LIBRARIES — the "
                        "same identities the artifact fingerprinter confirms",
            "matching": "soname/packaging noise stripped; case/punctuation-"
                       "insensitive match on names, markers and providers; "
                       "alias table for spellings cleaning cannot reach",
            "contract": "unmatched names stay unmatched — never forced onto "
                        "the nearest registry entry",
        },
    }
