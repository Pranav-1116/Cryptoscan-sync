"""Collectors: turning what the platform already stores into CBOM evidence.

The usage model (:mod:`cbom.usage_evidence`) can say *network observed this
algorithm, here is the evidence id*. It cannot make the observation happen. This
module is the missing half: pure projections from rows this platform already
holds onto evidence events, so a CBOM asset's runtime/network rows stop being
permanently ``NOT_OBSERVED`` for the sources that do exist.

Three sources, and each is honest about what it can prove:

``network``
    A network-scanner probe that completed a handshake negotiated a cipher suite.
    That is a network observation of the bulk algorithm, its signature algorithm
    and its key exchange — and nothing about the application behind the
    terminator, which is why the hop keeps its endpoint.
``static``
    A crypto finding stored from a source scan, joined to its evidence rows. An
    asset whose evidence link is missing is **refused**: the row still exists in
    the inventory, but it cannot claim to have been statically observed.
``runtime``
    A recorded crypto operation. Only a row that carries an evidence id and an
    observation time becomes one; anything else is a claim about runtime, not a
    runtime observation.

Nothing here invents an evidence id. If a source row has no id, the row is
refused with the reason, and the refusal is reported rather than dropped.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from cbom import usage_evidence as ue

SCHEMA = "cryptoscan.cbom-usage-collectors/1"

#: What part of a negotiated connection an algorithm plays.
ALGORITHM_ROLES: tuple[str, ...] = ("BULK", "SIGNATURE", "KEY_EXCHANGE", "HASH", "MAC")

#: Cipher-suite tokens -> the algorithm they name. Deliberately explicit and
#: small: a suite this table does not know produces no fact, rather than a guess.
SUITE_TOKENS: dict[str, dict[str, Any]] = {
    "AES_256_GCM": {"algorithm": "AES-256-GCM", "role": "BULK",
                    "parameters": {"key_size": 256, "mode": "GCM"}},
    "AES_128_GCM": {"algorithm": "AES-128-GCM", "role": "BULK",
                    "parameters": {"key_size": 128, "mode": "GCM"}},
    "AES_256_CBC": {"algorithm": "AES-256-CBC", "role": "BULK",
                    "parameters": {"key_size": 256, "mode": "CBC"}},
    "AES_128_CBC": {"algorithm": "AES-128-CBC", "role": "BULK",
                    "parameters": {"key_size": 128, "mode": "CBC"}},
    "CHACHA20_POLY1305": {"algorithm": "CHACHA20-POLY1305", "role": "BULK",
                          "parameters": {"mode": "POLY1305"}},
    "3DES_EDE_CBC": {"algorithm": "3DES", "role": "BULK",
                     "parameters": {"key_size": 168, "mode": "CBC"}},
    "AES256GCM": {"algorithm": "AES-256-GCM", "role": "BULK",
                  "parameters": {"key_size": 256, "mode": "GCM"}},
    "AES128GCM": {"algorithm": "AES-128-GCM", "role": "BULK",
                  "parameters": {"key_size": 128, "mode": "GCM"}},
    "ECDHE": {"algorithm": "ECDHE", "role": "KEY_EXCHANGE", "parameters": {}},
    "ECDH": {"algorithm": "ECDH", "role": "KEY_EXCHANGE", "parameters": {}},
    "DHE": {"algorithm": "DH", "role": "KEY_EXCHANGE", "parameters": {}},
    "RSA": {"algorithm": "RSA", "role": "SIGNATURE", "parameters": {}},
    "ECDSA": {"algorithm": "ECDSA", "role": "SIGNATURE", "parameters": {}},
    "SHA384": {"algorithm": "SHA-384", "role": "HASH", "parameters": {}},
    "SHA256": {"algorithm": "SHA-256", "role": "HASH", "parameters": {}},
    "X25519": {"algorithm": "X25519", "role": "KEY_EXCHANGE", "parameters": {}},
    "SECP256R1": {"algorithm": "ECDH-P256", "role": "KEY_EXCHANGE",
                  "parameters": {"curve": "P-256"}},
}

#: Suite prefixes that name a TLS 1.3 suite (``TLS_AES_256_GCM_SHA384``).
_TLS13_PREFIX = "TLS_"

#: Probe statuses that mean a handshake completed. Same set the NBOM uses: a
#: refused or timed-out probe negotiated nothing and observes nothing.
OBSERVED_STATUSES: frozenset[str] = frozenset({"OK", "TLS_OK", "SUCCESS", "UP"})


def algorithms_from_cipher_suite(suite: str | Mapping[str, Any]) -> list[dict[str, Any]]:
    """The algorithms one negotiated cipher suite names, with their roles.

    ``TLS_AES_256_GCM_SHA384`` is AES-256-GCM (bulk) plus SHA-384 (hash);
    ``ECDHE-RSA-AES128-GCM-SHA256`` adds RSA as the signature and ECDHE as the key
    exchange. Tokens are matched longest-first so ``AES_256_GCM`` wins over a bare
    ``RSA``-style substring, and every fact keeps the suite it came from.
    """
    text = str(suite.get("cipher_suite") if isinstance(suite, Mapping) else suite or "")
    raw = text.strip().upper().replace("WITH", "_").replace("_WITH_", "_")
    tokens = [token for token in raw.replace("-", "_").replace(".", "_").split("_") if token]
    joined = "_".join(tokens)
    found: list[dict[str, Any]] = []
    seen: set[str] = set()
    for key in sorted(SUITE_TOKENS, key=len, reverse=True):
        if key in joined and SUITE_TOKENS[key]["algorithm"] not in seen:
            row = dict(SUITE_TOKENS[key])
            row["suite"] = text
            seen.add(row["algorithm"])
            found.append(row)
            joined = joined.replace(key, " ")
    if not found and text:
        return []
    return found


def _evidence_id(row: Mapping[str, Any], prefix: str) -> str:
    explicit = str(row.get("evidence_id") or "").strip()
    if explicit:
        return explicit
    scan = str(row.get("scan_run_id") or "").strip()
    endpoint = str(row.get("endpoint") or "").strip()
    if scan and endpoint:
        return f"{prefix}:{scan}:{endpoint}"
    return ""


def network_events_from_probes(probes: Iterable[Mapping[str, Any]], *,
                               scan_run_id: str | None = None,
                               observed_at: Any = None) -> dict[str, Any]:
    """Completed handshakes -> network evidence, certificate records and hops.

    An unobserved endpoint produces **no** event: an unprobed listener is
    unknown, and treating it as evidence of anything (including its absence) is
    the mistake the NBOM documentation already warns about.
    """
    events: list[dict[str, Any]] = []
    certificates: list[dict[str, Any]] = []
    hops: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for probe in probes:
        if not isinstance(probe, Mapping):
            refused.append({"probe": probe, "reason": "a probe must be an object"})
            continue
        endpoint = str(probe.get("endpoint") or "").strip()
        status = str(probe.get("status") or "").strip().upper()
        crypto = probe.get("crypto") or {}
        if status and status not in OBSERVED_STATUSES:
            refused.append({"endpoint": endpoint or None, "status": status,
                            "reason": "no handshake completed, so nothing was negotiated"})
            continue
        suite = probe.get("cipher_suite") or crypto.get("cipher_suite")
        if not suite:
            refused.append({"endpoint": endpoint or None,
                            "reason": "a completed handshake with no negotiated suite is not "
                                      "evidence of an algorithm"})
            continue
        row = {**dict(probe), "scan_run_id": probe.get("scan_run_id") or scan_run_id,
               "endpoint": endpoint}
        evidence_id = _evidence_id(row, "net")
        if not evidence_id:
            refused.append({"endpoint": endpoint or None,
                            "reason": "no scan run or evidence id to point at"})
            continue
        tls_version = probe.get("tls_version") or crypto.get("tls_version")
        for fact in algorithms_from_cipher_suite(str(suite)):
            events.append({
                "class": "NETWORK_OBSERVED",
                "evidence_id": evidence_id,
                "algorithm": fact["algorithm"],
                "role": fact["role"],
                "parameters": fact["parameters"],
                "purpose": "TLS",
                "layer": "network",
                "location": endpoint or None,
                "observed_at": probe.get("observed_at") or observed_at,
                "tls_version": tls_version,
                "cipher_suite": suite,
            })
        chain = probe.get("certificates") or []
        leaf = chain[0] if chain and isinstance(chain[0], Mapping) else {}
        if leaf:
            certificates.append(ue.certificate_evidence({
                "certificate_ref": leaf.get("serial_number") or leaf.get("fingerprint_sha256"),
                "public_key_algorithm": leaf.get("public_key_algorithm"),
                "key_size": leaf.get("public_key_size"),
                "signature_algorithm": leaf.get("signature_algorithm"),
                "issuer": leaf.get("issuer"), "subject": leaf.get("subject"),
                "not_after": leaf.get("not_after"),
                "endpoint": endpoint or None,
                "observed_on": probe.get("observed_on") or probe.get("device"),
                "evidence_id": evidence_id,
            }))
        hops.append({
            "from": probe.get("from") or "client",
            "to": probe.get("to") or probe.get("observed_on") or probe.get("device") or endpoint,
            "endpoint": endpoint or None,
            "observed_on": probe.get("observed_on") or probe.get("device"),
            "tls_version": tls_version,
            "cipher_suite": suite,
            "key_exchange": probe.get("key_exchange"),
            "certificate_ref": leaf.get("serial_number") if leaf else None,
            "evidence_id": evidence_id,
            "layer": "network",
        })
    return {
        "schema": SCHEMA,
        "source": "network",
        "events": events,
        "certificates": certificates,
        "hops": hops,
        "refused": refused,
        "statement": (
            f"{len(events)} algorithm fact(s) from {len(hops)} completed handshake(s)"
            + (f"; {len(refused)} probe(s) refused for having negotiated nothing" if refused else "")),
    }


def static_events_from_assets(assets: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Stored crypto findings -> static evidence, with their evidence rows.

    A finding with no evidence id is refused. That is the difference between
    "this file contains an AES call" and "this file contains an AES call and here
    is the record that says so"; the inventory keeps the row either way, but only
    the second becomes evidence.
    """
    events: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for asset in assets:
        if not isinstance(asset, Mapping):
            refused.append({"asset": asset, "reason": "an asset must be an object"})
            continue
        algorithm = str(asset.get("algorithm") or "").strip()
        if not algorithm:
            refused.append({"asset": dict(asset), "reason": "a finding with no algorithm"})
            continue
        ids = [str(value).strip() for value in (asset.get("evidence_ids") or []) if str(value).strip()]
        if not ids:
            refused.append({"algorithm": algorithm, "location": asset.get("file_path"),
                            "reason": "the finding has no evidence row, so it is an inventory "
                                      "entry and not an observation"})
            continue
        parameters: dict[str, Any] = {}
        if asset.get("key_size"):
            parameters["key_size"] = asset["key_size"]
        if asset.get("mode"):
            parameters["mode"] = asset["mode"]
        for evidence_id in ids:
            events.append({
                "class": "STATIC_OBSERVED",
                "evidence_id": evidence_id,
                "algorithm": algorithm,
                "parameters": parameters,
                "purpose": asset.get("purpose"),
                "layer": "static",
                "location": (f"{asset.get('file_path')}:{asset.get('line_number')}"
                             if asset.get("file_path") else None),
                "observed_at": asset.get("observed_at"),
            })
    return {
        "schema": SCHEMA,
        "source": "static",
        "events": events,
        "refused": refused,
        "statement": (
            f"{len(events)} static observation(s) from {len({e['evidence_id'] for e in events})} "
            f"evidence row(s)"
            + (f"; {len(refused)} finding(s) refused for carrying no evidence" if refused else "")),
    }


def runtime_events_from_operations(operations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Recorded crypto operations -> runtime evidence, or a refusal.

    A runtime row needs three things to be evidence: the operation (what was
    called), the algorithm it resolved to, and an evidence id **and** a timestamp
    saying when. A row that names a process but no operation is a claim about
    runtime; it stays out of the profile.
    """
    events: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for row in operations:
        if not isinstance(row, Mapping):
            refused.append({"operation": row, "reason": "an operation must be an object"})
            continue
        operation = str(row.get("operation") or "").strip()
        algorithm = str(row.get("algorithm") or "").strip()
        evidence_id = str(row.get("evidence_id") or "").strip()
        observed_at = row.get("observed_at")
        missing = [name for name, value in (("operation", operation),
                                            ("algorithm", algorithm),
                                            ("evidence_id", evidence_id),
                                            ("observed_at", observed_at)) if not value]
        if missing:
            refused.append({"operation": operation or None, "algorithm": algorithm or None,
                            "reason": f"a runtime observation is missing {', '.join(missing)}"})
            continue
        parameters: dict[str, Any] = {}
        for key in ("key_size", "mode", "curve"):
            if row.get(key):
                parameters[key] = row[key]
        events.append({
            "class": "RUNTIME_OBSERVED",
            "evidence_id": evidence_id,
            "algorithm": algorithm,
            "parameters": parameters,
            "purpose": row.get("purpose"),
            "layer": "runtime",
            "location": row.get("process") or row.get("location"),
            "observed_at": observed_at,
            "operation": operation,
        })
    return {
        "schema": SCHEMA,
        "source": "runtime",
        "events": events,
        "refused": refused,
        "statement": (
            f"{len(events)} recorded crypto operation(s)"
            + (f"; {len(refused)} row(s) refused for being a claim rather than an observation"
               if refused else "")),
    }


def profiles(events: Iterable[Mapping[str, Any]], *,
             purposes: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Group evidence events into one usage profile per algorithm.

    The result is what a CBOM asset should show: for each algorithm, which layers
    observed it, with which evidence ids, at what confidence — and which layers
    have **no collector at all**, so ``NOT_OBSERVED`` is not read as ``not used``.
    """
    rows = list(events)
    by_algorithm: dict[str, list[dict[str, Any]]] = {}
    for event in rows:
        algorithm = str(event.get("algorithm") or "").strip()
        if not algorithm:
            continue
        by_algorithm.setdefault(algorithm, []).append(dict(event))
    built: list[dict[str, Any]] = []
    for algorithm in sorted(by_algorithm):
        asset = {"algorithm": algorithm,
                 "purpose": (purposes or {}).get(algorithm)}
        parameters: dict[str, Any] = {}
        for event in by_algorithm[algorithm]:
            for key, value in (event.get("parameters") or {}).items():
                parameters.setdefault(key, value)
        asset["parameters"] = parameters
        profile = ue.usage_profile(asset, by_algorithm[algorithm])
        profile["roles"] = sorted({str(event.get("role")) for event
                                   in by_algorithm[algorithm] if event.get("role")})
        profile["locations"] = sorted({str(event.get("location")) for event
                                       in by_algorithm[algorithm] if event.get("location")})
        built.append(profile)
    silent = sorted({layer for profile in built for layer, row in profile["layers"].items()
                     if not row["observed"]})
    return {
        "schema": SCHEMA,
        "profiles": built,
        "algorithms": [profile["asset"]["algorithm"] for profile in built],
        "unobserved_layers": silent,
        "statement": (
            f"{len(built)} algorithm(s) from {len(rows)} evidence event(s)"
            + (f"; nothing has observed {', '.join(silent)} for every asset, which is an absent "
               "collector and not an absent algorithm" if silent else "")),
    }
