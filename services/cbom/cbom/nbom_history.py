"""NBOM history: an observation is a moment, so keep the moments.

Review items 18 and 21 ask for the same thing from two directions:

    OBSERVE → NORMALIZE → HASH → COMPARE → CHANGE?
    ...keep snapshots and compare them: endpoint added or removed, port changed,
    certificate changed, TLS version changed, cipher changed, SNI changed, ALPN
    changed, trust path changed.

The NBOM's own discovery lifecycle already says it is point-in-time. A point has no
memory, so the interesting question — *what changed, and did it get worse* — needs a
second artefact: a **normalised** snapshot per observation run, with a hash that makes
"nothing changed" cheap to prove and "something changed" cheap to find.

Three rules keep this honest:

* the hash covers **state**, not provenance. Evidence ids and timestamps travel in
  the snapshot but never in the digest, so re-collecting the same fact does not read
  as a change;
* a change is not a regression. `ENDPOINT_ADDED` is a change, and it needs an owner,
  not an alarm. Only a **weakening** — a lower protocol, a weaker suite, a replaced
  certificate, a changed trust path — becomes `NETWORK_CRYPTO_REGRESSION`;
* the finding says what is not proven. A downgrade and a suspicious certificate are
  a reason to look; the finding never says *attack*, *compromise* or *attacker*.

This is deliberately distinct from the estate engine's `CRYPTOGRAPHIC_REGRESSION`
(shared_models.attack_patterns), which is about **evidence** weakening across planes.
This one is about the **cryptography** on a listener changing between two runs.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

from cbom import tls_state

SCHEMA = "cryptoscan.nbom-history/1"

#: Every change a snapshot pair can produce.
CHANGE_KINDS: tuple[str, ...] = (
    "ENDPOINT_ADDED", "ENDPOINT_REMOVED", "PORT_CHANGED", "TLS_VERSION_CHANGED",
    "CIPHER_SUITE_CHANGED", "CERTIFICATE_CHANGED", "TRUST_PATH_CHANGED",
    "SNI_CHANGED", "ALPN_CHANGED", "COLLECTION_STATUS_CHANGED",
)

#: The subset that means the network's cryptography got weaker.
REGRESSIONS: tuple[str, ...] = ("TLS_VERSION_CHANGED", "CIPHER_SUITE_CHANGED",
                                "CERTIFICATE_CHANGED", "TRUST_PATH_CHANGED")

SEVERITIES: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

#: Tokens that make a negotiated suite classically weak. A move *into* one is a
#: downgrade even when the version stayed the same.
WEAK_SUITE_TOKENS: tuple[str, ...] = ("RC4", "3DES", "DES_CBC", "NULL", "EXPORT",
                                      "MD5", "SHA1", "ANON", "CBC")

NOT_PROVEN: tuple[str, ...] = (
    "that the change was malicious",
    "that the endpoint is compromised",
    "who made the change",
)

#: What a reader is told to do about each regression, in the review's spirit.
NEXT_ACTION = {
    "TLS_VERSION_CHANGED": ("confirm the protocol policy on the terminating device and "
                            "whether the weaker version was intended"),
    "CIPHER_SUITE_CHANGED": ("compare the suite against the cipher policy for this zone; "
                             "a weaker suite on the same version is a configuration drift"),
    "CERTIFICATE_CHANGED": ("confirm the rotation with the PKI owner and check the issuer "
                            "and validity of the replacement"),
    "TRUST_PATH_CHANGED": ("confirm the trust anchor change with PKI; an unexpected issuer "
                           "is a reason to verify the chain out of band"),
}


def _text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _split(endpoint: Mapping[str, Any]) -> tuple[str, Any]:
    """``(host, port)`` from either shape, so ``host`` and ``endpoint`` agree."""
    raw = _text(endpoint.get("endpoint")) or ""
    host = (_text(endpoint.get("host")) or raw).strip().lower()
    port = endpoint.get("port")
    if port in (None, "") and ":" in host:
        candidate = host.rsplit(":", 1)[1]
        host = host.rsplit(":", 1)[0]
        port = int(candidate) if candidate.isdigit() else None
    elif ":" in host:
        host = host.split(":", 1)[0]
    if not host:
        raise ValueError("a network endpoint needs a host before it can be identified")
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    return host, port


def identity(endpoint: Mapping[str, Any]) -> str:
    """``host:port`` in one spelling, because case and spacing are not new endpoints."""
    host, port = _split(endpoint)
    return f"{host}:{port}" if port not in (None, "") else host


def _host(endpoint: Mapping[str, Any]) -> str:
    return _split(endpoint)[0]


#: The bulk cipher's key size, by name. The hash in a suite name ("SHA256") is not a
#: key size, which is exactly the mistake that reading the first three digits makes.
_BULK_KEY_BITS: tuple[tuple[str, int], ...] = (
    (r"CHACHA20", 256),
    (r"AES[_-]?256", 256),
    (r"AES[_-]?192", 192),
    (r"AES[_-]?128", 128),
    (r"ARIA[_-]?256", 256),
    (r"ARIA[_-]?128", 128),
    (r"CAMELLIA[_-]?256", 256),
    (r"CAMELLIA[_-]?128", 128),
    (r"3DES|DES[_-]?CBC3", 112),
    (r"\bDES\b", 56),
    (r"RC4", 128),
    (r"RC2", 40),
)


def _suite_strength(suite: str | None) -> dict[str, Any]:
    """Key size and classical weakness of a negotiated suite, from its bulk cipher."""
    upper = str(suite or "").upper()
    bits = None
    for pattern, size in _BULK_KEY_BITS:
        if re.search(pattern, upper):
            bits = size
            break
    weak = [token for token in WEAK_SUITE_TOKENS if token in upper]
    if "SHA" in upper and not re.search(r"SHA(256|384|512)", upper):
        weak.append("SHA1")
    return {"key_bits": bits, "weak_tokens": sorted(set(weak)), "weak": bool(weak)}


def normalise(endpoint: Mapping[str, Any]) -> dict[str, Any]:
    """One endpoint row -> the state we compare, plus the provenance we keep."""
    if not isinstance(endpoint, Mapping):
        raise ValueError("an endpoint must be an object")
    key = identity(endpoint)
    host, port = _split(endpoint)
    certificate = endpoint.get("certificate") or {}
    if not isinstance(certificate, Mapping):
        certificate = {}
    alpn = endpoint.get("alpn") or endpoint.get("service")
    if isinstance(alpn, str):
        alpn = [alpn]
    evidence = endpoint.get("evidence_ids") or ([endpoint["evidence_id"]]
                                                if endpoint.get("evidence_id") else [])
    state = {
        "identity": key,
        "host": host,
        "port": port,
        "tls_version": tls_state._version(endpoint.get("tls_version")),
        "cipher_suite": _text(endpoint.get("cipher_suite")),
        "sni": _text(endpoint.get("sni")) or _text(endpoint.get("server_name")),
        "alpn": sorted({str(value) for value in (alpn or []) if str(value).strip()}),
        "certificate": {
            "fingerprint_sha256": _text(certificate.get("fingerprint_sha256")),
            "issuer": _text(certificate.get("issuer")),
            "subject": _text(certificate.get("subject")),
            "not_after": _text(certificate.get("not_after")),
            "public_key_algorithm": _text(certificate.get("public_key_algorithm")),
            "public_key_size": certificate.get("public_key_size"),
        },
        "observed": endpoint.get("observed") is not False,
    }
    digest = hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {**state, "digest": digest, "evidence_ids": sorted({str(v) for v in evidence
                                                               if str(v).strip()})}


def snapshot(endpoints: Iterable[Mapping[str, Any]], *, taken_at: str | None = None,
             collector: str | None = None,
             coverage: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One point-in-time, normalised, hashed view of the network.

    Two runs that observed the same state produce the same ``hash`` even when they
    used different evidence ids or ran minutes apart; two runs that observed different
    state produce different hashes even when every component looks familiar.
    """
    entries: dict[str, dict[str, Any]] = {}
    for row in endpoints or ():
        entry = normalise(row)
        if entry["identity"] in entries:
            raise ValueError(
                f"{entry['identity']} appears twice in one snapshot: two observations of "
                "one endpoint must be merged by the collector, not by the diff")
        entries[entry["identity"]] = entry
    ordered = [entries[key] for key in sorted(entries)]
    digest = hashlib.sha256(
        json.dumps([[entry["identity"], entry["digest"]] for entry in ordered],
                   sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "taken_at": taken_at or datetime.now(timezone.utc).isoformat(),
        "collector": collector,
        "coverage": dict(coverage) if isinstance(coverage, Mapping) else None,
        "hash": digest,
        "endpoints": ordered,
        "statement": (f"{len(ordered)} endpoint(s) at {taken_at or 'now'}, hash {digest[:12]}"
                      + (f"; coverage {coverage.get('status')}" if isinstance(
                          coverage, Mapping) and coverage.get("status") else "")),
    }


def _find(snapshot_body: Mapping[str, Any], key: str) -> dict[str, Any] | None:
    for entry in snapshot_body.get("endpoints") or []:
        if entry["identity"] == key:
            return entry
    return None


def _diff_entry(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[dict[str, Any]]:
    key = after["identity"]
    changes: list[dict[str, Any]] = []
    if before.get("port") != after.get("port"):
        changes.append({"kind": "PORT_CHANGED", "severity": "MEDIUM",
                        "before": before.get("port"), "after": after.get("port"),
                        "detail": "the service moved port, so the inventory key changed"})
    if before.get("tls_version") != after.get("tls_version"):
        old_rank = _protocol_rank(before.get("tls_version"))
        new_rank = _protocol_rank(after.get("tls_version"))
        direction = ("DOWNGRADE" if new_rank is not None and old_rank is not None
                     and new_rank < old_rank else "UPGRADE")
        changes.append({
            "kind": "TLS_VERSION_CHANGED",
            "severity": "HIGH" if direction == "DOWNGRADE" else "INFO",
            "direction": direction,
            "before": before.get("tls_version"), "after": after.get("tls_version"),
            "detail": (f"the negotiated protocol went from {before.get('tls_version')} to "
                       f"{after.get('tls_version')}")})
    if before.get("cipher_suite") != after.get("cipher_suite"):
        old_suite = _suite_strength(before.get("cipher_suite"))
        new_suite = _suite_strength(after.get("cipher_suite"))
        weaker = (
            (new_suite["weak"] and not old_suite["weak"])
            or (old_suite["key_bits"] is not None and new_suite["key_bits"] is not None
                and new_suite["key_bits"] < old_suite["key_bits"])
        )
        changes.append({
            "kind": "CIPHER_SUITE_CHANGED",
            "severity": "HIGH" if weaker else "LOW",
            "direction": "DOWNGRADE" if weaker else "CHANGE",
            "before": before.get("cipher_suite"), "after": after.get("cipher_suite"),
            "detail": (f"the negotiated suite went from {before.get('cipher_suite')} to "
                       f"{after.get('cipher_suite')}"
                       + (f" (weaker: {', '.join(new_suite['weak_tokens']) or 'smaller key'})"
                          if weaker else ""))})
    old_cert = before.get("certificate") or {}
    new_cert = after.get("certificate") or {}
    if old_cert.get("fingerprint_sha256") != new_cert.get("fingerprint_sha256"):
        changes.append({
            "kind": "CERTIFICATE_CHANGED", "severity": "MEDIUM", "direction": "CHANGE",
            "before": old_cert.get("fingerprint_sha256"),
            "after": new_cert.get("fingerprint_sha256"),
            "detail": ("the served certificate changed; a rotation is ordinary and an "
                       "unexplained replacement is not")})
    if old_cert.get("issuer") != new_cert.get("issuer"):
        changes.append({
            "kind": "TRUST_PATH_CHANGED", "severity": "MEDIUM", "direction": "CHANGE",
            "before": old_cert.get("issuer"), "after": new_cert.get("issuer"),
            "detail": "the issuing authority changed, which moves the trust anchor"})
    if before.get("sni") != after.get("sni"):
        changes.append({"kind": "SNI_CHANGED", "severity": "LOW", "direction": "CHANGE",
                        "before": before.get("sni"), "after": after.get("sni"),
                        "detail": "the requested server name changed"})
    if before.get("alpn") != after.get("alpn"):
        changes.append({"kind": "ALPN_CHANGED", "severity": "LOW", "direction": "CHANGE",
                        "before": before.get("alpn"), "after": after.get("alpn"),
                        "detail": "the negotiated application protocol changed"})
    if before.get("observed") != after.get("observed"):
        changes.append({
            "kind": "COLLECTION_STATUS_CHANGED",
            "severity": "MEDIUM" if before.get("observed") and not after.get("observed")
            else "INFO",
            "direction": ("DOWNGRADE" if before.get("observed")
                          and not after.get("observed") else "UPGRADE"),
            "before": before.get("observed"), "after": after.get("observed"),
            "detail": ("the endpoint stopped answering, which is a collection gap and not "
                       "a finding about its cryptography")})
    for change in changes:
        change.update({
            "endpoint": key,
            "evidence_before": before.get("evidence_ids") or [],
            "evidence_after": after.get("evidence_ids") or [],
        })
    return changes


def _protocol_rank(version: Any) -> int | None:
    try:
        return tls_state.PROTOCOL_ORDER.index(str(version))
    except ValueError:
        return None


def compare(before: Mapping[str, Any], after: Mapping[str, Any],
            *, systems: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Two snapshots -> every change, classified as upgrade, downgrade or neither."""
    for name, body in (("before", before), ("after", after)):
        if not isinstance(body, Mapping) or body.get("schema") != SCHEMA:
            raise ValueError(f"the {name} snapshot is not a {SCHEMA} document")
    changes: list[dict[str, Any]] = []
    old_entries = {entry["identity"]: entry for entry in before.get("endpoints") or []}
    new_entries = {entry["identity"]: entry for entry in after.get("endpoints") or []}
    old_keys = set(old_entries)
    new_keys = set(new_entries)
    removed, added = old_keys - new_keys, new_keys - old_keys

    # a listener that moved port is one endpoint moving, not a disappearance plus an
    # arrival: pair them by host, and diff the rest of the state as usual
    moved: dict[str, str] = {}
    for old_key in sorted(removed):
        candidates = [key for key in sorted(added)
                      if _host(old_entries[old_key]) == _host(new_entries[key])]
        if len(candidates) == 1:
            pair = candidates[0]
            moved[old_key] = pair
            added.discard(pair)
            changes.extend(_diff_entry(old_entries[old_key], new_entries[pair]))
    removed = removed - set(moved)
    for key in sorted(removed):
        entry = _find(before, key) or {}
        changes.append({
            "kind": "ENDPOINT_REMOVED", "severity": "MEDIUM", "direction": "CHANGE",
            "endpoint": key, "before": _state_summary(entry), "after": None,
            "evidence_before": entry.get("evidence_ids") or [], "evidence_after": [],
            "detail": ("the listener disappeared: it was decommissioned, or it stopped "
                       "answering, and only a probe can tell those apart")})
    for key in sorted(added):
        entry = _find(after, key) or {}
        changes.append({
            "kind": "ENDPOINT_ADDED", "severity": "INFO", "direction": "CHANGE",
            "endpoint": key, "before": None, "after": _state_summary(entry),
            "evidence_before": [], "evidence_after": entry.get("evidence_ids") or [],
            "detail": ("a new listener is a change that needs an owner, not a finding "
                       "about its cryptography")})
    unchanged = 0
    for key in sorted(old_keys & new_keys):
        old_entry = _find(before, key) or {}
        new_entry = _find(after, key) or {}
        if old_entry.get("digest") == new_entry.get("digest"):
            unchanged += 1
            continue
        changes.extend(_diff_entry(old_entry, new_entry))
    for change in changes:
        if systems and change["endpoint"] in systems:
            change["affected_systems"] = list(systems[change["endpoint"]])
    counts: dict[str, int] = {}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1
    downgrades = [change for change in changes if change.get("direction") == "DOWNGRADE"]
    return {
        "schema": SCHEMA,
        "before": {"taken_at": before.get("taken_at"), "hash": before.get("hash")},
        "after": {"taken_at": after.get("taken_at"), "hash": after.get("hash")},
        "identical": before.get("hash") == after.get("hash"),
        "changes": changes,
        "counts": dict(sorted(counts.items())),
        "unchanged": unchanged,
        "downgrades": len(downgrades),
        "statement": _compare_statement(before, after, changes, unchanged),
    }


def _state_summary(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {"tls_version": entry.get("tls_version"),
            "cipher_suite": entry.get("cipher_suite"),
            "certificate": (entry.get("certificate") or {}).get("fingerprint_sha256"),
            "observed": entry.get("observed")}


def _compare_statement(before: Mapping[str, Any], after: Mapping[str, Any],
                       changes: list[Mapping[str, Any]], unchanged: int) -> str:
    if before.get("hash") == after.get("hash"):
        return (f"the two snapshots are identical ({len(before.get('endpoints') or [])} "
                "endpoint(s), same hash), so nothing changed")
    kinds = sorted({str(change["kind"]) for change in changes})
    return (f"{len(changes)} change(s) across {len(kinds)} kind(s) between "
            f"{before.get('taken_at')} and {after.get('taken_at')}: "
            + ", ".join(kinds)
            + f"; {unchanged} endpoint(s) unchanged")


def regression(comparison: Mapping[str, Any]) -> dict[str, Any]:
    """The subset of changes that is a *weakening*, as `NETWORK_CRYPTO_REGRESSION`.

    One finding per endpoint, so a listener that dropped its protocol and its suite in
    the same window is one thing to investigate rather than two lines to reconcile.
    """
    by_endpoint: dict[str, list[dict[str, Any]]] = {}
    for change in comparison.get("changes") or []:
        if change["kind"] not in REGRESSIONS:
            continue
        weakened = (change.get("direction") == "DOWNGRADE"
                    or change["kind"] in {"CERTIFICATE_CHANGED", "TRUST_PATH_CHANGED"})
        if not weakened:
            continue  # an upgrade is a change, not a regression
        by_endpoint.setdefault(str(change["endpoint"]), []).append(change)
    findings: list[dict[str, Any]] = []
    for endpoint in sorted(by_endpoint):
        signals = by_endpoint[endpoint]
        severity = max((str(signal["severity"]) for signal in signals),
                       key=lambda name: _SEVERITY_RANK.get(name, 0))
        primary = signals[0]
        findings.append({
            "finding": "NETWORK_CRYPTO_REGRESSION",
            "endpoint": endpoint,
            "severity": severity,
            "signals": [signal["kind"] for signal in signals],
            "before": {signal["kind"]: signal.get("before") for signal in signals},
            "after": {signal["kind"]: signal.get("after") for signal in signals},
            "detail": "; ".join(str(signal.get("detail")) for signal in signals),
            "evidence_before": sorted({value for signal in signals
                                       for value in signal.get("evidence_before") or []}),
            "evidence_after": sorted({value for signal in signals
                                      for value in signal.get("evidence_after") or []}),
            "observed_at": (comparison.get("after") or {}).get("taken_at"),
            "affected_systems": sorted({system for signal in signals
                                        for system in signal.get("affected_systems") or []}),
            "next_action": NEXT_ACTION.get(str(primary["kind"]), "review the change"),
            "not_proven": list(NOT_PROVEN),
            "statement": (f"{endpoint} weakened between the two snapshots: "
                          + ", ".join(signal["kind"] for signal in signals)
                          + ". This is a reason to investigate, not a conclusion"),
        })
    return {
        "schema": SCHEMA,
        "findings": findings,
        "counts": {name: sum(1 for finding in findings if finding["severity"] == name)
                   for name in SEVERITIES if any(finding["severity"] == name
                                                 for finding in findings)},
        "statement": (
            f"{len(findings)} NETWORK_CRYPTO_REGRESSION finding(s)"
            + (f", worst {max((f['severity'] for f in findings), key=lambda n: _SEVERITY_RANK[n])}"
               if findings else "")
            + "; each names what is not proven"),
    }


def timeline(snapshots: Iterable[Mapping[str, Any]], *,
             systems: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Several snapshots, compared in order: the historical NBOM of item 21."""
    ordered = sorted((snapshot for snapshot in snapshots or ()),
                     key=lambda body: str(body.get("taken_at") or ""))
    periods: list[dict[str, Any]] = []
    for previous, current in zip(ordered, ordered[1:]):
        comparison = compare(previous, current, systems=systems)
        periods.append({
            "from": previous.get("taken_at"),
            "to": current.get("taken_at"),
            "identical": comparison["identical"],
            "counts": comparison["counts"],
            "regression": regression(comparison),
        })
    findings = [finding for period in periods for finding in period["regression"]["findings"]]
    changed = [period for period in periods if not period["identical"]]
    return {
        "schema": SCHEMA,
        "snapshots": len(ordered),
        "periods": periods,
        "changes": sum(sum((period["counts"] or {}).values()) for period in periods),
        "regressions": len(findings),
        "worst": (max((finding["severity"] for finding in findings),
                      key=lambda name: _SEVERITY_RANK[name]) if findings else None),
        "statement": (
            f"{len(ordered)} snapshot(s), {len(periods)} period(s), {len(changed)} with "
            f"changes"
            + (f"; {len(findings)} NETWORK_CRYPTO_REGRESSION finding(s)" if findings
               else "; no regression between any two consecutive snapshots")),
    }


def summary(comparison: Mapping[str, Any],
            regressed: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """One screen: did anything move, and did any of it move the wrong way."""
    regressed = regressed or regression(comparison)
    return {
        "schema": SCHEMA,
        "identical": comparison.get("identical"),
        "changes": len(comparison.get("changes") or []),
        "counts": comparison.get("counts"),
        "downgrades": comparison.get("downgrades"),
        "regressions": len(regressed.get("findings") or []),
        "worst": (max((finding["severity"] for finding in regressed.get("findings") or []),
                      key=lambda name: _SEVERITY_RANK[name])
                  if regressed.get("findings") else None),
        "statement": comparison.get("statement", "") + "; "
                     + regressed.get("statement", ""),
    }
