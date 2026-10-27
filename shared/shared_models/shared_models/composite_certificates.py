"""Composite / hybrid cryptographic certificate detection (audit 59).

Composite certificates combine a post-quantum algorithm (ML-DSA, ML-KEM, ...)
with a classical one (RSA, ECDSA, ECDH, ...) inside a single X.509
signature / key-agreement algorithm identifier. They are increasingly common
in hybrid migration rollouts, and they matter for CBOM accuracy: a composite
cert is *two* crypto dependencies, not one, and its security is the security
of the weaker component.

Detection is deterministic and registry-based:

* **OID arcs** — the IANA-registered composite arcs under
  ``2.16.840.1.114027.80`` (Composite ML-DSA signatures),
  ``...114027.81`` (chameleon/legacy composite signatures) and
  ``...114027.82`` (composite KEMs). Arc-prefix matching is deliberate:
  individual scheme suffixes are still moving across draft revisions, the
  arcs are stable.
* **Names** — OpenSSL/`cryptography` render composite algorithms as names
  (``id-ML-DSA65-RSA2048-PSS-SHA256``, ``ML-KEM-768+ECDH-P384``,
  ``mldsa65_rsa2048_sha256``). A name is composite when it pairs a PQ marker
  with a classical marker, or carries an explicit composite/hybrid marker.

What this module does NOT do: it does not implement composite verification,
and it cannot detect schemes whose identifier carries neither a registered
composite arc nor a recognisable name (an unknown OID with no name mapping
returns ``None`` — honest absence, not a guess).
"""

from __future__ import annotations

import re
from typing import Any

#: Registered composite OID arcs (prefix match on dotted form).
#: 2.16.840.1.114027.80 — Composite ML-DSA signatures (LAMPS)
#: 2.16.840.1.114027.81 — chameleon composite signatures (pre-PQ hybrid)
#: 2.16.840.1.114027.82 — composite KEM schemes (LAMPS)
COMPOSITE_OID_ARCS: dict[str, str] = {
    "2.16.840.1.114027.80.": "composite-signature",
    "2.16.840.1.114027.81.": "composite-signature",
    "2.16.840.1.114027.82.": "composite-kem",
}

#: Component tokens we can extract from names, longest-first so that
#: ``ECDSA-P384`` wins over ``ECDSA`` and ``ML-DSA-65`` over ``DSA``.
_PQ_TOKENS = [
    "ML-DSA-87", "ML-DSA-65", "ML-DSA-44",
    "ML-DSA", "ML-KEM-1024", "ML-KEM-768", "ML-KEM-512", "ML-KEM",
    "FALCON-1024", "FALCON-512", "FALCON",
    "SPHINCS+-SHAKE-256s", "SPHINCS+-SHA2-256s", "SPHINCS+",
    "SLH-DSA", "DILITHIUM3", "DILITHIUM2", "DILITHIUM",
]
_CLASSICAL_TOKENS = [
    "RSA-PSS", "RSA-PKCS15", "RSA2048", "RSA3072", "RSA4096", "RSA",
    "ECDSA-P384", "ECDSA-P256", "ECDSA-P521", "ECDSA",
    "ED25519", "ED448", "ECDH-P384", "ECDH-P256", "ECDH",
    "X25519", "X448", "P-521", "P-384", "P-256",
]

#: Names that declare compositional intent outright.
_EXPLICIT_MARKERS = re.compile(r"composite|hybrid|chameleon", re.IGNORECASE)


def _normalize(value: str | None) -> str:
    return re.sub(r"[\s_-]+", "", (value or "").lower())


def _components_from_name(name: str) -> list[str]:
    """Extract the PQ + classical component names from an algorithm name."""
    found: list[str] = []
    for token in _PQ_TOKENS:
        if _normalize(token) in _normalize(name) and token not in found:
            found.append(token)
    for token in _CLASSICAL_TOKENS:
        if _normalize(token) in _normalize(name) and token not in found:
            found.append(token)
    return found


def _is_composite_name(name: str) -> bool:
    """Pairwise test: a PQ marker AND a classical marker, or an explicit marker."""
    normalized = _normalize(name)
    has_pq = any(_normalize(t) in normalized for t in _PQ_TOKENS)
    has_classical = any(_normalize(t) in normalized for t in _CLASSICAL_TOKENS)
    if has_pq and has_classical:
        return True
    if _EXPLICIT_MARKERS.search(name or ""):
        # explicit marker + at least two recognisable components
        return len(_components_from_name(name)) >= 2
    return False


def detect_composite(
    *,
    signature_algorithm: str | None = None,
    signature_algorithm_oid: str | None = None,
    public_key_algorithm: str | None = None,
) -> dict[str, Any] | None:
    """Detect a composite/hybrid certificate algorithm.

    Returns ``None`` for ordinary single-algorithm certificates. For a
    detected composite scheme, returns::

        {
            "scheme": "composite-signature" | "composite-kem",
            "identifier": "<the matched OID arc or algorithm name>",
            "components": ["ML-DSA-65", "ECDSA-P384"],   # best-effort
            "match": "oid-arc" | "name",
        }
    """
    oid = (signature_algorithm_oid or "").strip()
    if oid:
        for arc, scheme in COMPOSITE_OID_ARCS.items():
            if oid.startswith(arc):
                return {
                    "scheme": scheme,
                    "identifier": oid,
                    "components": _components_from_name(signature_algorithm or oid),
                    "match": "oid-arc",
                }
    for name in (signature_algorithm, public_key_algorithm):
        if not name:
            continue
        candidate = name.strip()
        if not candidate:
            continue
        if _is_composite_name(candidate):
            return {
                "scheme": "composite-kem" if "kem" in _normalize(candidate) else "composite-signature",
                "identifier": candidate,
                "components": _components_from_name(candidate),
                "match": "name",
            }
    return None


def composite_block(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """Convenience for repository ingest: detect from a certificate payload."""
    payload = payload or {}
    return detect_composite(
        signature_algorithm=payload.get("signature_algorithm"),
        signature_algorithm_oid=payload.get("signature_algorithm_oid"),
        public_key_algorithm=payload.get("public_key_algorithm"),
    )
