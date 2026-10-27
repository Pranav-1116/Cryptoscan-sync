"""Cross-layer correlation: STATIC + RUNTIME + NETWORK (spec 67 §26, §27).

Correlation is not averaging. Each layer contributes facts about a different
thing, and the engine only compares facts that describe the *same artifact*:

    comparable      a declared TLS policy vs the negotiated TLS version,
                    a configured certificate fingerprint vs the presented one,
                    a declared mTLS policy vs an observed client-certificate
                    requirement, a declared cipher list vs the negotiated one
    not comparable  a library found in source vs a negotiated TLS cipher — the
                    TLS suite is transport encryption, the library is
                    application crypto (§27)

Anything that cannot be compared is reported as ``NOT_COMPARABLE`` with the
reason, never as a match and never as a finding. Missing layers are
``NOT_OBSERVED`` — absence of evidence is not evidence of absence (§29).
"""

from __future__ import annotations

from typing import Any, Iterable

MODEL = "cryptoscan.cross-layer-correlation/1"

LAYERS = ("STATIC", "RUNTIME", "NETWORK")

#: fact kinds that can legitimately be compared across layers, and what the
#: comparison means to a reader
COMPARABLE_KINDS: dict[str, str] = {
    "certificate_fingerprint": "the same certificate identity can appear in configuration and on the wire",
    "tls_version": "declared TLS policy vs the negotiated TLS version",
    "mutual_tls": "declared mTLS policy vs the observed client-certificate requirement",
    "cipher_suite": "declared cipher suite vs the negotiated cipher suite",
}

#: roles that describe transport behaviour. A fact with one of these roles may
#: be compared with a network observation; any other role is a different layer.
TRANSPORT_ROLES = frozenset({"network-transport", "tls-server-certificate", "tls-client-facing", "tls-internal"})

#: TLS version spellings seen in configs, scanners and stack traces
_TLS_ALIASES = {
    "tls1": "TLS1.0",
    "tlsv1": "TLS1.0",
    "tlsv1.0": "TLS1.0",
    "tls1.0": "TLS1.0",
    "tlsv1_0": "TLS1.0",
    "tls1.1": "TLS1.1",
    "tlsv1.1": "TLS1.1",
    "tls1.2": "TLS1.2",
    "tlsv1.2": "TLS1.2",
    "tls1.3": "TLS1.3",
    "tlsv1.3": "TLS1.3",
    "tls13": "TLS1.3",
    "tls12": "TLS1.2",
}

_MUTUAL_TLS_ALIASES = {
    "required": "REQUIRED",
    "require": "REQUIRED",
    "true": "REQUIRED",
    "request": "REQUIRED",
    "optional": "OPTIONAL",
    "requested": "OPTIONAL",
    "not_required": "NOT_REQUIRED",
    "false": "NOT_REQUIRED",
    "none": "NOT_REQUIRED",
    "unknown": "UNKNOWN",
}


def _norm(kind: str, value: Any) -> str | None:
    """Canonicalise a fact value for comparison; unknown spellings stay distinct."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if kind == "certificate_fingerprint":
        return lowered.removeprefix("sha256:").removeprefix("sha-256:").replace(":", "")
    if kind == "tls_version":
        return _TLS_ALIASES.get(lowered, text.upper())
    if kind == "mutual_tls":
        return _MUTUAL_TLS_ALIASES.get(lowered, text.upper())
    if kind == "cipher_suite":
        return lowered.replace("-", "_").upper()
    return lowered


def _keys_for(service: dict[str, Any]) -> set[str]:
    keys = {str(service.get("name") or "").strip().lower()}
    keys.update(str(host).strip().lower() for host in service.get("hosts") or [])
    keys.update(str(endpoint).strip().lower() for endpoint in service.get("endpoints") or [])
    return {key for key in keys if key}


def _fact_owner(fact: dict[str, Any]) -> set[str]:
    keys = {str(fact.get("service") or "").strip().lower()}
    keys.add(str(fact.get("host") or "").strip().lower())
    keys.add(str(fact.get("endpoint") or "").strip().lower())
    return {key for key in keys if key}


def _fact(fact: dict[str, Any], layer: str) -> dict[str, Any]:
    kind = str(fact.get("kind") or "").strip().lower()
    return {
        "layer": layer,
        # identity keys travel with the fact so it can be matched to a service
        "service": fact.get("service"),
        "host": fact.get("host"),
        "endpoint": fact.get("endpoint"),
        "kind": kind,
        "value": fact.get("value"),
        "normalized": _norm(kind, fact.get("value")),
        "role": str(fact.get("role") or "unspecified").strip().lower(),
        "source": fact.get("source"),
        "evidence_id": fact.get("evidence_id"),
        "observed_at": fact.get("observed_at"),
        "confidence": fact.get("confidence"),
    }


def network_facts_from_evidence(evidence: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Derive comparable network facts from stored §24 evidence records.

    Only what the record actually states becomes a fact. An endpoint with no
    handshake contributes nothing here — it shows up as missing coverage, which
    the caller reports as ``NOT_OBSERVED``.
    """
    facts: list[dict[str, Any]] = []
    for record in evidence:
        if record.get("evidence_type") not in {"NETWORK_ACTIVE_OBSERVED", "NETWORK_PASSIVE_OBSERVED"}:
            continue
        target = record.get("target") or {}
        base = {
            "endpoint": target.get("endpoint"),
            "host": target.get("host"),
            "source": f"network:{record.get('evidence_id') or target.get('endpoint')}",
            "evidence_id": record.get("evidence_id"),
            "observed_at": record.get("observed_at"),
            "confidence": record.get("confidence"),
        }
        certificate = record.get("certificate") or {}
        if certificate.get("fingerprint_sha256"):
            facts.append({**base, "kind": "certificate_fingerprint", "role": "tls-server-certificate", "value": certificate["fingerprint_sha256"]})
        if record.get("tls_version"):
            facts.append({**base, "kind": "tls_version", "role": "network-transport", "value": record["tls_version"]})
        if record.get("cipher_suite"):
            facts.append({**base, "kind": "cipher_suite", "role": "network-transport", "value": record["cipher_suite"]})
        if record.get("mutual_tls"):
            facts.append({**base, "kind": "mutual_tls", "role": "network-transport", "value": record["mutual_tls"]})
    return facts


def _compare(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    kind = left["kind"]
    base = {
        "kind": kind,
        "meaning": COMPARABLE_KINDS.get(kind),
        "left": {key: left[key] for key in ("layer", "value", "role", "source", "evidence_id")},
        "right": {key: right[key] for key in ("layer", "value", "role", "source", "evidence_id")},
    }
    if kind not in COMPARABLE_KINDS:
        return {**base, "result": "NOT_COMPARABLE", "reason": f"'{kind}' is not a cross-layer comparable fact kind"}
    left_transport = left["role"] in TRANSPORT_ROLES
    right_transport = right["role"] in TRANSPORT_ROLES
    if not (left_transport and right_transport):
        return {
            **base,
            "result": "NOT_COMPARABLE",
            "reason": (
                "the two facts describe different layers: transport crypto is not application or "
                "storage crypto, so the values are not interchangeable (§27)"
            ),
        }
    if left["normalized"] is None or right["normalized"] is None:
        return {**base, "result": "NOT_COMPARABLE", "reason": "a value is missing — nothing to compare"}
    matched = left["normalized"] == right["normalized"]
    return {
        **base,
        "result": "MATCH" if matched else "MISMATCH",
        "reason": None
        if matched
        else "declared/observed values disagree — this is a review item, not an automatic vulnerability",
    }


def correlate(
    *,
    services: Iterable[dict[str, Any]],
    static: Iterable[dict[str, Any]] = (),
    runtime: Iterable[dict[str, Any]] = (),
    network: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Correlate three layers per service, keeping every layer's facts distinct."""
    service_list = [service for service in services if str(service.get("name") or "").strip()]
    facts = {
        "STATIC": [_fact(item, "STATIC") for item in static],
        "RUNTIME": [_fact(item, "RUNTIME") for item in runtime],
        "NETWORK": [_fact(item, "NETWORK") for item in network],
    }

    index: list[tuple[set[str], dict[str, Any]]] = []
    for service in service_list:
        keys = _keys_for(service)
        index.append((keys, service))

    per_layer: dict[str, dict[str, list[dict[str, Any]]]] = {layer: {} for layer in LAYERS}
    unattributed: list[dict[str, Any]] = []
    for layer, layer_facts in facts.items():
        for fact in layer_facts:
            owners = _fact_owner(fact)
            matched_service = None
            for keys, service in index:
                if owners & keys:
                    matched_service = service
                    break
            if matched_service is None:
                unattributed.append({**fact, "reason": "no declared service matched this fact's service/host/endpoint"})
                continue
            per_layer[layer].setdefault(matched_service["name"], []).append(fact)

    results: list[dict[str, Any]] = []
    mismatches = matches = not_comparable = 0
    complete_services = 0
    without_network = 0

    for service in service_list:
        name = service["name"]
        layers = {
            layer: {"present": bool(per_layer[layer].get(name)), "facts": per_layer[layer].get(name, [])}
            for layer in LAYERS
        }
        present = [layer for layer in LAYERS if layers[layer]["present"]]
        if len(present) == 3:
            complete_services += 1
        if not layers["NETWORK"]["present"]:
            without_network += 1

        comparisons: list[dict[str, Any]] = []
        # compare every fact of a comparable kind against every fact of the same
        # kind from another layer, keeping the layer pair explicit
        for i, left_layer in enumerate(LAYERS):
            for right_layer in LAYERS[i + 1 :]:
                for left in layers[left_layer]["facts"]:
                    for right in layers[right_layer]["facts"]:
                        if left["kind"] != right["kind"]:
                            continue
                        comparison = _compare(left, right)
                        if comparison["result"] == "MATCH":
                            matches += 1
                        elif comparison["result"] == "MISMATCH":
                            mismatches += 1
                        else:
                            not_comparable += 1
                        comparisons.append(comparison)

        risk_hints = [
            {
                "kind": f"CROSS_LAYER_{comparison['kind'].upper()}_MISMATCH",
                "service": name,
                "detail": comparison["reason"],
                "left": comparison["left"],
                "right": comparison["right"],
                "severity": "REVIEW",
                "requires_analyst_confirmation": True,
                "automatic_verdict": False,
            }
            for comparison in comparisons
            if comparison["result"] == "MISMATCH"
        ]

        results.append(
            {
                "service": name,
                "system": service.get("system"),
                "layers": layers,
                "layers_present": present,
                "layers_missing": [layer for layer in LAYERS if layer not in present],
                "comparisons": comparisons,
                "risk_hints": risk_hints,
                "coverage": {
                    "complete": len(present) == 3,
                    "note": "a missing layer is NOT_OBSERVED for this service — it is not proof that the layer has no crypto",
                },
            }
        )

    return {
        "model": MODEL,
        "layers": {
            "order": list(LAYERS),
            "separation": "STATIC ≠ RUNTIME ≠ NETWORK: each layer's facts stay in their own bucket",
            "transports": list(sorted(TRANSPORT_ROLES)),
        },
        "services": results,
        "summary": {
            "services": len(results),
            "services_with_all_layers": complete_services,
            "services_without_network_evidence": without_network,
            "comparisons": matches + mismatches + not_comparable,
            "matches": matches,
            "mismatches": mismatches,
            "not_comparable": not_comparable,
            "unattributed_facts": len(unattributed),
            "risk_hints": sum(len(item["risk_hints"]) for item in results),
        },
        "unattributed_facts": unattributed,
        "limitations": [
            "correlation matches on service/host/endpoint keys supplied by the caller — an unmatched fact is reported, not guessed",
            "a mismatch is a review item: it says two layers disagree, not which one is wrong",
            "transport crypto never stands in for application, storage or HSM/KMS crypto (§27)",
            "static analysis of source/config cannot prove runtime behaviour, and a network handshake cannot see application crypto",
        ],
        "boundary": "three evidence layers, correlated on identity — never merged into one 'crypto algorithm'",
    }
