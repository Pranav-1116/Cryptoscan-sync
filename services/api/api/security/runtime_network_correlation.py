"""Runtime ↔ network correlation (spec 92 §15, spec 67 §26).

The two layers answer different questions and are therefore correlated, never
merged:

    runtime  "which crypto operation did this process run?"        Level 1–3
    network  "which session did this endpoint negotiate?"          Level 4

Only *same-artifact* facts are compared. A TLS version seen in a negotiated
session is comparable with the TLS version a process's own TLS context reported;
an application's AES-256-GCM bulk cipher is **not** comparable with a TLS
cipher suite that happens to contain AES-256 — that comparison is refused with a
reason, because the layers protect different data (§27).

Matching is done on host identity only (runtime ``identity.host`` against the
network target host/IP, or a declared mapping). Nothing is inferred from
timing, ports or naming similarity.
"""

from __future__ import annotations

from typing import Any, Iterable

MODEL = "cryptoscan.runtime-network-correlation/1"

#: transport facts that may be compared across the runtime/network boundary
COMPARABLE_TRANSPORT_FIELDS = ("tls_version", "cipher_suite")

REFUSED_COMPARISONS = (
    (
        "runtime bulk cipher vs TLS cipher suite",
        "a runtime AES-256-GCM operation encrypts application data; a TLS suite encrypts the "
        "connection. They are different layers even when both say AES-256 (§27)",
    ),
    (
        "runtime key size vs certificate key size",
        "an application's session key length is not the certificate's public-key length",
    ),
    (
        "runtime Level 1 operation vs network Level 4 session count",
        "observation counts measure different things and must not be added",
    ),
)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def runtime_identities(events: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group runtime events by host identity."""
    by_host: dict[str, dict[str, Any]] = {}
    for event in events:
        identity = event.get("identity") or {}
        host = _norm(identity.get("host"))
        if not host:
            continue
        bucket = by_host.setdefault(
            host,
            {
                "host": identity.get("host"),
                "applications": set(),
                "processes": set(),
                "levels": {},
                "algorithms": {},
                "operations": {},
                "events": 0,
                "tls_versions": set(),
                "cipher_suites": set(),
            },
        )
        if identity.get("application"):
            bucket["applications"].add(str(identity["application"]))
        if identity.get("process"):
            bucket["processes"].add(str(identity["process"]))
        level = str(event.get("attribution_level"))
        bucket["levels"][level] = bucket["levels"].get(level, 0) + 1
        if event.get("algorithm"):
            bucket["algorithms"][str(event["algorithm"])] = bucket["algorithms"].get(str(event["algorithm"]), 0) + 1
        bucket["operations"][str(event.get("operation"))] = bucket["operations"].get(str(event.get("operation")), 0) + 1
        bucket["events"] += int(event.get("observation_count") or 1)
        transport = event.get("transport") or {}
        version = transport.get("tls_version") or event.get("tls_version")
        if version:
            bucket["tls_versions"].add(str(version))
        suite = transport.get("cipher_suite")
        if suite:
            bucket["cipher_suites"].add(str(suite))
    return by_host


def network_endpoints(records: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Group network evidence by host identity."""
    by_host: dict[str, dict[str, Any]] = {}
    for record in records:
        target = record.get("target") or {}
        endpoint = str(target.get("endpoint") or "")
        host = _norm(target.get("host") or endpoint.rsplit(":", 1)[0])
        if not host:
            continue
        bucket = by_host.setdefault(
            host,
            {
                "host": target.get("host") or endpoint.rsplit(":", 1)[0],
                "endpoints": set(),
                "protocols": set(),
                "tls_versions": set(),
                "cipher_suites": set(),
                "evidence_types": set(),
                "records": 0,
            },
        )
        if endpoint:
            bucket["endpoints"].add(endpoint)
        bucket["protocols"].add(str(record.get("protocol") or "UNKNOWN"))
        bucket["evidence_types"].add(str(record.get("evidence_type") or "UNKNOWN"))
        bucket["records"] += 1
        if record.get("tls_version"):
            bucket["tls_versions"].add(str(record["tls_version"]))
        if record.get("cipher_suite"):
            bucket["cipher_suites"].add(str(record["cipher_suite"]))
    return by_host


def _serialise(bucket: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in bucket.items():
        if isinstance(value, set):
            out[key] = sorted(value)
        elif isinstance(value, dict):
            out[key] = dict(value)
        else:
            out[key] = value
    return out


def correlate(
    runtime_events: Iterable[dict[str, Any]],
    network_records: Iterable[dict[str, Any]],
    *,
    host_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Correlate runtime and network views of the same hosts.

    ``host_map`` lets an operator declare that a runtime host and a network
    endpoint host are the same machine (``{"payments-prod-01": "10.20.10.15"}``)
    instead of the engine guessing it.
    """
    runtime_by_host = runtime_identities(runtime_events)
    network_by_host = network_endpoints(network_records)
    mapping = {_norm(key): _norm(value) for key, value in (host_map or {}).items()}

    subjects: list[dict[str, Any]] = []
    compared = 0
    matched = 0
    mismatched = 0
    both = 0
    runtime_only = 0
    network_only = 0

    all_hosts = set(runtime_by_host) | set(network_by_host) | set(mapping)
    for host in sorted(all_hosts):
        runtime_key = host if host in runtime_by_host else next(
            (key for key, value in mapping.items() if value == host), None
        )
        network_key = host if host in network_by_host else mapping.get(host)
        runtime_side = runtime_by_host.get(runtime_key or host)
        network_side = network_by_host.get(network_key or host)

        comparisons: list[dict[str, Any]] = []
        if runtime_side and network_side:
            both += 1
            for field in COMPARABLE_TRANSPORT_FIELDS:
                if field == "tls_version":
                    left = sorted(runtime_side["tls_versions"])
                    right = sorted(network_side["tls_versions"])
                else:
                    # a runtime tracer rarely reports the negotiated suite; it is
                    # compared only when it explicitly did
                    left = sorted(runtime_side["cipher_suites"])
                    right = sorted(network_side["cipher_suites"])
                if not left or not right:
                    comparisons.append(
                        {
                            "field": field,
                            "result": "NOT_COMPARABLE",
                            "reason": "one side did not observe this field",
                            "runtime": left,
                            "network": right,
                        }
                    )
                    continue
                compared += 1
                same = set(left) & set(right)
                if same:
                    matched += 1
                    result = "MATCH"
                else:
                    mismatched += 1
                    result = "MISMATCH"
                comparisons.append(
                    {
                        "field": field,
                        "result": result,
                        "runtime": left,
                        "network": right,
                        "note": "same artifact class on both sides; a mismatch is a review item",
                    }
                )
        elif runtime_side:
            runtime_only += 1
        elif network_side:
            network_only += 1

        subjects.append(
            {
                "host": (runtime_side or network_side or {}).get("host") or host,
                "runtime": _serialise(runtime_side) if runtime_side else None,
                "network": _serialise(network_side) if network_side else None,
                "layers": [
                    layer
                    for layer, present in (
                        ("RUNTIME", bool(runtime_side)),
                        ("NETWORK", bool(network_side)),
                    )
                    if present
                ],
                "comparisons": comparisons,
                "note": (
                    "runtime and network both observed this host"
                    if runtime_side and network_side
                    else "runtime observation only — transport crypto NOT_OBSERVED"
                    if runtime_side
                    else "network observation only — application crypto NOT_OBSERVED"
                ),
            }
        )

    return {
        "model": MODEL,
        "subjects": subjects,
        "summary": {
            "hosts": len(subjects),
            "both_layers": both,
            "runtime_only": runtime_only,
            "network_only": network_only,
            "comparisons": compared,
            "matched": matched,
            "mismatched": mismatched,
            "declared_host_map": len(mapping),
        },
        "refused_comparisons": [
            {"comparison": name, "reason": reason} for name, reason in REFUSED_COMPARISONS
        ],
        "limitations": [
            "host identity is matched on declared host names/IPs only — nothing is inferred from ports or timing",
            "a host present in one layer only is NOT_OBSERVED in the other, not crypto-free",
            "runtime bulk crypto and TLS crypto protect different data and are never compared",
        ],
        "boundary": (
            "runtime facts are Level 1–3 application observations; network facts are Level 4 transport "
            "observations. Only same-artifact fields are compared"
        ),
    }
