"""A cipher suite is four decisions, and sometimes a suite only names two of them.

Review item 8 is a complaint about shape, and it is right:

    `TLS_AES_256_GCM_SHA384` alone is not enough to describe TLS 1.3, because a TLS 1.3
    suite names only the AEAD and the hash. Key exchange and authentication come from
    the handshake — the group agreed, the signature algorithm used, the key in the
    certificate.

Flattening a suite into a list of algorithm names loses exactly the fields a migration
question needs: *is there forward secrecy*, *is this AEAD*, *which key size*, *what
signed it*. This module decomposes a handshake into the four dimensions the review names

    KEY_EXCHANGE · AUTHENTICATION · ENCRYPTION · HASH

and records, per dimension, **where the answer came from**:

* ``NAMED_IN_SUITE`` — the suite identifier itself names it (`ECDHE-RSA-AES128-GCM-SHA256`);
* ``NEGOTIATED`` — the handshake reported it (`group`, signature algorithm, certificate key);
* ``NOT_NAMED`` — the suite does not name it and no handshake context was supplied. The
  answer is *unknown*, and specifically **not** RSA: the commonest error in TLS 1.3
  inventories is reading "no key-exchange token" as the RSA key transport of TLS 1.2.

Parsing is not duplicated here — the token table and the longest-first matcher live in
:mod:`cbom.usage_collectors`, and this module organises their output.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from cbom import usage_collectors as uc

SCHEMA = "cryptoscan.cipher-suite/1"

DIMENSIONS: tuple[str, ...] = ("KEY_EXCHANGE", "AUTHENTICATION", "ENCRYPTION", "HASH")

EVIDENCE: tuple[str, ...] = ("NAMED_IN_SUITE", "NEGOTIATED", "NOT_NAMED")

RATINGS: tuple[str, ...] = ("STRONG", "ACCEPTABLE", "WEAK", "BROKEN", "UNKNOWN")

#: tokens that already make a suite unusable regardless of anything else
BROKEN_TOKENS: tuple[str, ...] = ("RC4", "DES_CBC3", "3DES", "DES-CBC3", "NULL", "EXPORT")

#: modes that are not authenticated encryption
NON_AEAD_MODES: tuple[str, ...] = ("CBC", "CTR", "STREAM")

#: negotiated groups, as the handshake names them, and the key-exchange method each is
GROUPS: dict[str, dict[str, Any]] = {
    "X25519": {"method": "ECDHE", "algorithm": "X25519", "parameters": {"curve": "X25519"}},
    "X448": {"method": "ECDHE", "algorithm": "X448", "parameters": {"curve": "X448"}},
    "SECP256R1": {"method": "ECDHE", "algorithm": "ECDH-P256",
                  "parameters": {"curve": "P-256"}},
    "P-256": {"method": "ECDHE", "algorithm": "ECDH-P256", "parameters": {"curve": "P-256"}},
    "SECP384R1": {"method": "ECDHE", "algorithm": "ECDH-P384",
                  "parameters": {"curve": "P-384"}},
    "P-384": {"method": "ECDHE", "algorithm": "ECDH-P384", "parameters": {"curve": "P-384"}},
    "SECP521R1": {"method": "ECDHE", "algorithm": "ECDH-P521",
                  "parameters": {"curve": "P-521"}},
    "FFDHE2048": {"method": "DHE", "algorithm": "DH-2048",
                  "parameters": {"key_size": 2048}},
    "FFDHE3072": {"method": "DHE", "algorithm": "DH-3072",
                  "parameters": {"key_size": 3072}},
    "FFDHE4096": {"method": "DHE", "algorithm": "DH-4096",
                  "parameters": {"key_size": 4096}},
}

#: legacy bulk ciphers the token table deliberately does not model as algorithms
LEGACY_BULK: dict[str, dict[str, Any]] = {
    "3DES": {"algorithm": "3DES-CBC", "role": "BULK",
             "parameters": {"key_size": 112, "mode": "CBC"}},
    "DES_CBC3": {"algorithm": "3DES-CBC", "role": "BULK",
                 "parameters": {"key_size": 112, "mode": "CBC"}},
    "RC4": {"algorithm": "RC4", "role": "BULK",
            "parameters": {"key_size": 128, "mode": "STREAM"}},
    "NULL": {"algorithm": "NULL", "role": "BULK", "parameters": {"mode": "NULL"}},
    "EXPORT": {"algorithm": "EXPORT", "role": "BULK", "parameters": {"mode": "EXPORT"}},
}

#: signature algorithms, as the handshake names them
SIGNATURES: dict[str, dict[str, Any]] = {
    "ECDSA_SECP256R1_SHA256": {"algorithm": "ECDSA-P256", "parameters": {"curve": "P-256"}},
    "ECDSA_SECP384R1_SHA384": {"algorithm": "ECDSA-P384", "parameters": {"curve": "P-384"}},
    "RSA_PSS_RSAE_SHA256": {"algorithm": "RSA-PSS", "parameters": {"hash": "SHA-256"}},
    "RSA_PSS_RSAE_SHA384": {"algorithm": "RSA-PSS", "parameters": {"hash": "SHA-384"}},
    "RSA_PKCS1_SHA256": {"algorithm": "RSA-PKCS1", "parameters": {"hash": "SHA-256"}},
    "ED25519": {"algorithm": "Ed25519", "parameters": {}},
}

NOT_PROVEN = [
    "that the suite is the only one the endpoint accepts: one negotiated suite is one "
    "handshake, not the endpoint's configured set",
    "that the named key exchange actually protected this session: forward secrecy is a "
    "property of the method, and implementation defects are outside this model",
    "that the bulk key size is the security level: a 128-bit AES key under a 1024-bit "
    "DH group is limited by the group",
    "that the certificate's issuer is trusted: this is one hop of a chain, and the "
    "chain is a separate model",
]

#: algorithms whose security depends on a hard problem a quantum computer breaks
_QUANTUM_RELEVANT = frozenset({
    "RSA", "RSA-PSS", "RSA-PKCS1", "ECDH-P256", "ECDH-P384", "ECDH-P521",
    "X25519", "X448", "DH-2048", "DH-3072", "DH-4096", "ECDSA-P256", "ECDSA-P384",
    "Ed25519", "ECDHE",
})


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _tls13(suite: str, version: str | None) -> bool:
    if version:
        return str(version).upper().replace("TLS", "").replace("V", "").strip(" .") \
            in {"1.3", "13"}
    return suite.upper().startswith("TLS_")


def _fact(facts: Iterable[Mapping[str, Any]], role: str) -> dict[str, Any] | None:
    for fact in facts:
        if fact.get("role") == role:
            return dict(fact)
    return None


def _unknown(dimension: str, note: str) -> dict[str, Any]:
    return {"dimension": dimension, "algorithm": None, "method": None,
            "parameters": None, "evidence": "NOT_NAMED", "note": note}


def _suite_facts(suite: str) -> list[dict[str, Any]]:
    """The token table's answer, plus the legacy identifiers it leaves alone."""
    facts = uc.algorithms_from_cipher_suite(suite)
    flat = suite.replace("-", "_")
    tokens = [token for token in flat.split("_") if token]
    for token, row in LEGACY_BULK.items():
        if token in flat and _fact(facts, "BULK") is None:
            facts = [*facts, {**row, "suite": suite}]
    # identifiers the token table does not model: a TLS 1.2 name may spell the bulk
    # cipher as `AES128`/`AES_128_CBC` and the PRF as a bare `SHA`
    if _fact(facts, "BULK") is None:
        modes = {"CBC", "GCM", "CCM", "CCM8", "CHACHA20", "POLY1305", "STREAM", "NULL"}
        present = modes & set(tokens)
        bits = (256 if "AES256" in tokens or ({"AES", "256"} <= set(tokens)) else
                128 if "AES128" in tokens or ({"AES", "128"} <= set(tokens)) else None)
        # only claim CBC when the identifier says CBC or says no mode at all; a mode
        # this table does not model stays unknown rather than becoming the nearest one
        if bits and present <= {"CBC"}:
            facts = [*facts, {"algorithm": f"AES-{bits}-CBC", "role": "BULK",
                              "parameters": {"key_size": bits, "mode": "CBC"},
                              "suite": suite}]
    if _fact(facts, "HASH") is None and "SHA" in tokens:
        facts = [*facts, {"algorithm": "SHA-1", "role": "HASH", "parameters": {},
                          "suite": suite}]
    return facts


def decompose(suite: str, *, tls_version: str | None = None,
              group: str | None = None, signature_algorithm: str | None = None,
              certificate_key: Mapping[str, Any] | None = None,
              evidence_id: str | None = None) -> dict[str, Any]:
    """One negotiated suite (and whatever the handshake reported) -> four dimensions."""
    suite = (_text(suite) or "").upper()
    if not suite:
        raise ValueError("a decomposition needs a cipher suite")
    facts = _suite_facts(suite)
    recognised = bool(facts)
    modern = _tls13(suite, tls_version)
    bulk = _fact(facts, "BULK")
    hashed = _fact(facts, "HASH")
    named_kex = _fact(facts, "KEY_EXCHANGE")
    named_auth = _fact(facts, "SIGNATURE")

    if modern:
        key_exchange = _unknown(
            "KEY_EXCHANGE",
            "a TLS 1.3 suite does not name key exchange; without the negotiated group "
            "the answer is unknown, not RSA")
        group_row = GROUPS.get((_text(group) or "").upper().replace("-", "_")
                               if group else "")
        if group_row:
            key_exchange = {"dimension": "KEY_EXCHANGE", "algorithm": group_row["algorithm"],
                            "method": group_row["method"],
                            "parameters": dict(group_row["parameters"]),
                            "evidence": "NEGOTIATED",
                            "note": f"the handshake agreed the group {group}"}
    elif named_kex:
        key_exchange = {"dimension": "KEY_EXCHANGE",
                        "algorithm": named_kex["algorithm"],
                        "method": named_kex["algorithm"],
                        "parameters": dict(named_kex.get("parameters") or {}),
                        "evidence": "NAMED_IN_SUITE",
                        "note": "the suite identifier names the key exchange"}
    elif named_auth and named_auth["algorithm"] == "RSA":
        key_exchange = {"dimension": "KEY_EXCHANGE", "algorithm": "RSA",
                        "method": "RSA_KEY_TRANSPORT", "parameters": {},
                        "evidence": "NAMED_IN_SUITE",
                        "note": ("the certificate key both signs and encrypts the "
                                 "premaster secret, so this session has no forward secrecy")}
    else:
        key_exchange = _unknown("KEY_EXCHANGE", "this suite does not name a key exchange")

    if modern:
        authentication = _unknown(
            "AUTHENTICATION",
            "a TLS 1.3 suite does not name authentication; without the signature "
            "algorithm or the certificate key the answer is unknown")
        signature = SIGNATURES.get((_text(signature_algorithm) or "").upper()
                                   .replace("-", "_"))
        if signature:
            authentication = {"dimension": "AUTHENTICATION",
                              "algorithm": signature["algorithm"], "method": "SIGNATURE",
                              "parameters": dict(signature["parameters"]),
                              "evidence": "NEGOTIATED",
                              "note": f"the handshake used {signature_algorithm}"}
        elif isinstance(certificate_key, Mapping) and certificate_key.get("algorithm"):
            authentication = {"dimension": "AUTHENTICATION",
                              "algorithm": str(certificate_key["algorithm"]).upper(),
                              "method": "CERTIFICATE_KEY",
                              "parameters": {"key_size": certificate_key.get("key_size")},
                              "evidence": "NEGOTIATED",
                              "note": ("taken from the certificate's public key, not "
                                       "from the suite and not from the signature "
                                       "algorithm")}
    elif named_auth:
        authentication = {"dimension": "AUTHENTICATION",
                          "algorithm": named_auth["algorithm"], "method": "SIGNATURE",
                          "parameters": dict(named_auth.get("parameters") or {}),
                          "evidence": "NAMED_IN_SUITE",
                          "note": "the suite identifier names the signature algorithm"}
    else:
        authentication = _unknown("AUTHENTICATION",
                                  "this suite does not name an authentication method")

    if bulk:
        parameters = dict(bulk.get("parameters") or {})
        encryption = {"dimension": "ENCRYPTION", "algorithm": bulk["algorithm"],
                      "method": "AEAD" if parameters.get("mode") not in NON_AEAD_MODES
                      else "ENCRYPT_THEN_MAC",
                      "parameters": parameters, "evidence": "NAMED_IN_SUITE",
                      "note": ("an AEAD mode authenticates the record itself"
                               if parameters.get("mode") not in NON_AEAD_MODES
                               else "a CBC-mode suite authenticates separately")}
    else:
        encryption = _unknown("ENCRYPTION",
                              "no bulk cipher was recognised in this suite")

    if hashed:
        note = ("in a TLS 1.2 AEAD suite the trailing hash is the PRF hash only; the "
                "record is authenticated by the AEAD") \
            if (not modern and bulk and encryption["method"] == "AEAD") \
            else "the suite names this hash"
        hash_dimension = {"dimension": "HASH", "algorithm": hashed["algorithm"],
                          "method": "PRF", "parameters": {},
                          "evidence": "NAMED_IN_SUITE", "note": note}
    else:
        hash_dimension = _unknown("HASH", "no hash was recognised in this suite")

    dimensions = {"KEY_EXCHANGE": key_exchange, "AUTHENTICATION": authentication,
                  "ENCRYPTION": encryption, "HASH": hash_dimension}
    unknown = [name for name, row in dimensions.items() if row["evidence"] == "NOT_NAMED"]
    strength = _strength(bulk, encryption, key_exchange, facts)
    return {
        "schema": SCHEMA,
        "suite": suite,
        "tls_version": _text(tls_version),
        "modern": modern,
        "recognised": recognised,
        "dimensions": dimensions,
        "not_named": unknown,
        "strength": strength,
        "evidence_ids": [value for value in [_text(evidence_id)] if value],
        "statement": _statement(suite, dimensions, strength),
    }


def _strength(bulk: Mapping[str, Any] | None, encryption: Mapping[str, Any],
              key_exchange: Mapping[str, Any],
              facts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    tokens = " ".join(str(fact.get("algorithm") or "").upper() for fact in facts)
    broken = sorted({token for token in BROKEN_TOKENS if token in tokens})
    parameters = (bulk or {}).get("parameters") or {}
    bulk_bits = parameters.get("key_size")
    mode = parameters.get("mode")
    aead = mode not in NON_AEAD_MODES and bool(bulk)
    forward_secrecy = str(key_exchange.get("method") or "") in {"ECDHE", "DHE"}
    if broken or not bulk:
        rating = "BROKEN" if broken else "UNKNOWN"
    elif (isinstance(bulk_bits, int) and bulk_bits < 128) or (mode in NON_AEAD_MODES):
        rating = "WEAK"
    elif aead and forward_secrecy:
        rating = "STRONG"
    else:
        rating = "ACCEPTABLE"
    return {"bulk_bits": bulk_bits, "mode": mode, "aead": aead,
            "forward_secrecy": forward_secrecy, "rating": rating,
            "broken_tokens": broken,
            "note": ("this suite is not in the token table, so its strength is unknown"
                     if rating == "UNKNOWN" and not bulk else
                     "an AEAD bulk cipher under an ephemeral key exchange"
                     if rating == "STRONG" else
                     "; ".join(broken) + " must not be enabled"
                     if broken else
                     "the certificate key protects the session: no forward secrecy"
                     if str(key_exchange.get("method") or "") == "RSA_KEY_TRANSPORT" else
                     "no forward secrecy was established by the named method"
                     if not forward_secrecy else
                     "see mode and key size")}


def _statement(suite: str, dimensions: Mapping[str, Any],
               strength: Mapping[str, Any]) -> str:
    def describe(name: str) -> str:
        row = dimensions[name]
        if row["evidence"] == "NOT_NAMED":
            return f"{name.lower()}=unknown"
        algorithm = row.get("algorithm") or row.get("method")
        return f"{name.lower()}={algorithm} ({row['evidence'].lower()})"

    return (f"{suite}: " + ", ".join(describe(name) for name in DIMENSIONS)
            + f"; {strength['rating'].lower()} — {strength['note']}")


def _values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return sorted({str(item).strip() for item in value if str(item).strip()})
    return []


def handshake(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """A batch of probes -> one decomposition per endpoint, with refusals listed."""
    decomposed: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in rows or ():
        if not isinstance(row, Mapping):
            refused.append({"row": row, "reason": "a handshake row must be an object"})
            continue
        certificate = row.get("certificate")
        certificate_key = row.get("certificate_key") or (
            certificate.get("public_key") if isinstance(certificate, Mapping) else None)
        try:
            result = decompose(
                row.get("cipher_suite") or "",
                tls_version=row.get("tls_version"),
                group=row.get("group"),
                signature_algorithm=row.get("signature_algorithm"),
                certificate_key=certificate_key,
                evidence_id=row.get("evidence_id"))
        except ValueError as exc:
            refused.append({"endpoint": row.get("endpoint"), "reason": str(exc)})
            continue
        result["endpoint"] = _text(row.get("endpoint"))
        result["evidence_ids"] = sorted({*(result["evidence_ids"]),
                                         *_values(row.get("evidence_id"))})
        decomposed.append(result)
    unobserved = [row for row in decomposed if row["not_named"]]
    return {
        "schema": SCHEMA,
        "handshakes": decomposed,
        "refused": refused,
        "endpoints": sorted({row["endpoint"] for row in decomposed if row["endpoint"]}),
        "ratings": {rating: sum(1 for row in decomposed
                                if row["strength"]["rating"] == rating)
                    for rating in RATINGS
                    if any(row["strength"]["rating"] == rating for row in decomposed)},
        "with_unknown_dimensions": len(unobserved),
        "statement": (
            f"{len(decomposed)} handshake(s) decomposed into four dimensions"
            + (f"; {len(unobserved)} carry at least one dimension the suite does not "
               "name and the handshake did not report" if unobserved else "")
            + (f"; {len(refused)} refused" if refused else "")),
    }


def to_algorithms(result: Mapping[str, Any]) -> dict[str, Any]:
    """The decomposition as algorithm facts the CBOM and the graph already understand.

    Roles match ``usage_collectors`` so nothing downstream needs a second vocabulary.
    A dimension the suite does not name and the handshake did not report produces **no
    fact**: absence is not RSA.
    """
    if not isinstance(result, Mapping) or result.get("schema") != SCHEMA:
        raise ValueError(f"not a {SCHEMA} document")
    facts: list[dict[str, Any]] = []
    role_by_dimension = {"KEY_EXCHANGE": "KEY_EXCHANGE", "AUTHENTICATION": "SIGNATURE",
                         "ENCRYPTION": "BULK", "HASH": "HASH"}
    for name, role in role_by_dimension.items():
        row = (result.get("dimensions") or {}).get(name) or {}
        if row.get("evidence") == "NOT_NAMED" or not row.get("algorithm"):
            continue
        facts.append({
            "algorithm": row["algorithm"],
            "role": role,
            "parameters": dict(row.get("parameters") or {}),
            "suite": result.get("suite"),
            "evidence": row["evidence"],
            "from_suite": row["evidence"] == "NAMED_IN_SUITE",
            "endpoint": result.get("endpoint"),
            "evidence_ids": list(result.get("evidence_ids") or []),
            "class": "NETWORK_OBSERVED",
        })
    return {
        "schema": SCHEMA,
        "facts": facts,
        "from_suite": sum(1 for fact in facts if fact["from_suite"]),
        "from_handshake": sum(1 for fact in facts if not fact["from_suite"]),
        "absent": list(result.get("not_named") or []),
        "statement": (
            f"{len(facts)} algorithm fact(s) from {result.get('suite')}: "
            f"{sum(1 for fact in facts if fact['from_suite'])} named by the suite, "
            f"{sum(1 for fact in facts if not fact['from_suite'])} reported by the "
            "handshake"
            + (f"; {len(result.get('not_named') or [])} dimension(s) left absent rather "
               "than assumed" if result.get("not_named") else "")),
    }


def frontier(result: Mapping[str, Any]) -> dict[str, Any]:
    """What a migration would have to change, per dimension, from one decomposition."""
    if not isinstance(result, Mapping) or result.get("schema") != SCHEMA:
        raise ValueError(f"not a {SCHEMA} document")
    dimensions = result.get("dimensions") or {}
    rows = []
    for name in DIMENSIONS:
        row = dimensions.get(name) or {}
        rows.append({
            "dimension": name,
            "algorithm": row.get("algorithm"),
            "evidence": row.get("evidence"),
            "quantum_relevant": row.get("algorithm") in _QUANTUM_RELEVANT,
            "next_action": (
                "replace or wrap this dimension with a post-quantum or hybrid option"
                if row.get("algorithm") in _QUANTUM_RELEVANT else
                "collect the handshake context before planning: this dimension is "
                "unknown, not absent" if not row.get("algorithm") else
                "no asymmetric replacement is needed for this dimension; review the "
                "key size and mode instead"),
        })
    return {"schema": SCHEMA, "suite": result.get("suite"), "dimensions": rows,
            "statement": (f"{sum(1 for row in rows if row['quantum_relevant'])} of "
                          f"{len(rows)} dimension(s) are quantum-relevant")}
