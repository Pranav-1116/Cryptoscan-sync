"""Estate-level policy over the correlated STATIC + RUNTIME + NETWORK picture.

Design spec: ``docs/bank-environment/67-network-crypto-discovery-engine.md``
§26 (three-layer correlation), §27 (layers never mix), §28 (BOM roles) and §31
(POLICY/RISK -> PQC/DRIFT stage).

Two existing modules answer one layer each:
:mod:`network_scanner.inventory.network_policy` scores network evidence and the
runtime engine scores runtime events. Neither of them can say what an
*application* looks like across layers, because a service only becomes visible
when static facts, runtime operations and network observations are joined.

This module is that joining step, and it deliberately stops short of a verdict
it cannot support:

* findings stay attached to the layer that produced them (``layer`` is copied,
  never overwritten);
* a layer with no facts is ``INCOMPLETE_COVERAGE`` for that service — the risk is
  blindness, not a pass;
* cross-layer *algorithm* comparisons are refused here as well; only the
  same-artifact comparisons the correlation engine already made appear, and they
  always carry ``requires_analyst_confirmation: true``;
* the migration queue ranks by exposure + policy failure, and says what it does
  not know.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

MODEL = "cryptoscan.network-estate-risk/1"
LAYERS = ("STATIC", "RUNTIME", "NETWORK")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: comparisons this module will never make, and why (§27)
REFUSED_COMPARISONS = (
    "network TLS bulk cipher vs application library cipher — different artifacts",
    "certificate RSA size vs application RSA key size — different key material",
    "SSH KEX algorithm vs TLS key exchange — different protocols",
    "count of network sessions vs count of runtime operations — different units",
    "KMS/HSM algorithm vs application algorithm — the HSM may wrap, not perform",
)

OUT_OF_REACH = (
    "application crypto in binaries that were never scanned (STATIC absent)",
    "runtime operations on hosts outside the approved runtime scope (RUNTIME absent)",
    "network paths that were never in the approved network scope (NETWORK absent)",
    "storage/at-rest encryption, HSM/KMS key material, private keys",
)


def _now(now: str | datetime | None = None) -> datetime:
    if isinstance(now, datetime):
        return now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    if isinstance(now, str) and now:
        try:
            parsed = datetime.fromisoformat(now.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _keys(service: Mapping[str, Any]) -> set[str]:
    """Identity keys of a declared service: name, system, hosts, endpoints."""
    keys = {str(service.get("name") or "").strip().lower()}
    for field in ("system", "hostname", "host", "fqdn"):
        value = str(service.get(field) or "").strip().lower()
        if value:
            keys.add(value)
    for field in ("hosts", "endpoints", "hostnames"):
        for value in service.get(field) or []:
            text = str(value or "").strip().lower()
            if text:
                keys.add(text)
    return {key for key in keys if key}


def _owner_keys(finding: Mapping[str, Any]) -> set[str]:
    candidates = [
        finding.get("service"),
        finding.get("host"),
        finding.get("endpoint"),
        finding.get("application"),
    ]
    keys: set[str] = set()
    for value in candidates:
        text = str(value or "").strip().lower()
        if not text:
            continue
        keys.add(text)
        if ":" in text:
            keys.add(text.rsplit(":", 1)[0])
    return keys


def _attach(
    findings: Iterable[Mapping[str, Any]],
    index: list[tuple[set[str], str]],
    *,
    layer: str,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    """Attach findings to services by identity keys; unmatched stays visible."""
    attached: dict[str, list[dict[str, Any]]] = {}
    unattributed: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        owners = _owner_keys(finding)
        matched = None
        for keys, name in index:
            if owners & keys:
                matched = name
                break
        entry = {
            "layer": layer,
            "rule_id": finding.get("rule_id"),
            "severity": str(finding.get("severity") or "medium"),
            "status": finding.get("status"),
            "observed": finding.get("observed"),
            "expected": finding.get("expected"),
            "reason": finding.get("reason") or finding.get("message"),
            "evidence_id": finding.get("evidence_id"),
            "endpoint": finding.get("endpoint"),
            "protocol": finding.get("protocol"),
            "reference": finding.get("reference"),
        }
        if matched is None:
            unattributed.append(
                {
                    **entry,
                    "reason_unattributed": (
                        "no declared service matched this finding's host/endpoint — "
                        "the estate map is incomplete, the finding is not dismissed"
                    ),
                }
            )
            continue
        attached.setdefault(matched, []).append(entry)
    return attached, unattributed


def _highest(findings: Iterable[Mapping[str, Any]]) -> str | None:
    severities = [str(finding.get("severity") or "") for finding in findings if finding.get("status") == "FAIL"]
    if not severities:
        return None
    return sorted(severities, key=lambda name: SEVERITY_ORDER.get(name, 99))[0]


def runtime_facts_from_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Turn runtime crypto events into correlation facts for the RUNTIME layer.

    Only what the event states becomes a fact. An event with no algorithm (a
    Level 6 observation) contributes its identity but no algorithm fact, so it
    shows up as missing coverage instead of a comparable value.
    """
    facts: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        identity = event.get("identity") or {}
        base = {
            "service": identity.get("application"),
            "host": identity.get("host"),
            "source": f"runtime:{event.get('event_id') or identity.get('process') or 'unknown'}",
            "evidence_id": event.get("event_id"),
            "observed_at": event.get("observed_at"),
            "confidence": f"LEVEL_{event.get('attribution_level')}" if event.get("attribution_level") else None,
        }
        if event.get("algorithm"):
            facts.append({**base, "kind": "algorithm", "role": "application-crypto", "value": event["algorithm"]})
        if event.get("mode"):
            facts.append({**base, "kind": "mode", "role": "application-crypto", "value": event["mode"]})
        if event.get("key_size"):
            facts.append({**base, "kind": "key_size", "role": "application-crypto", "value": event["key_size"]})
        if event.get("operation"):
            facts.append({**base, "kind": "operation", "role": "application-crypto", "value": event["operation"]})
    return facts


def evaluate_estate(
    *,
    correlation: Mapping[str, Any],
    services: Iterable[Mapping[str, Any]],
    network: Mapping[str, Any] | None = None,
    runtime: Mapping[str, Any] | None = None,
    static: Mapping[str, Any] | None = None,
    network_pqc: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    now: str | datetime | None = None,
) -> dict[str, Any]:
    """Aggregate per-layer findings per service without merging the layers."""
    moment = _now(now)
    service_list = [service for service in services if str(service.get("name") or "").strip()]
    index = [(_keys(service), str(service["name"])) for service in service_list]

    layer_reports: dict[str, Mapping[str, Any] | None] = {
        "NETWORK": network,
        "RUNTIME": runtime,
        "STATIC": static,
    }
    attached: dict[str, dict[str, list[dict[str, Any]]]] = {name: {} for _keys, name in index}
    unattributed: list[dict[str, Any]] = []
    for layer, report in layer_reports.items():
        if not report:
            continue
        findings = report.get("findings") if isinstance(report, Mapping) else None
        if findings is None and isinstance(report, Mapping):
            findings = [item for item in report.get("assets") or [] if item.get("status") == "FAIL"]
        per_service, unmatched = _attach(findings or [], index, layer=layer)
        for name, items in per_service.items():
            attached.setdefault(name, {})[layer] = items
        unattributed.extend(unmatched)

    correlated = {str(item.get("service")): item for item in correlation.get("services") or []}
    results: list[dict[str, Any]] = []
    blind_spots: list[str] = []
    by_layer_failures: dict[str, int] = {layer: 0 for layer in LAYERS}
    by_severity: dict[str, int] = {severity: 0 for severity in SEVERITY_ORDER}

    for service in service_list:
        name = str(service["name"])
        entry = correlated.get(name) or {}
        layers_present = set(entry.get("layers_present") or [])
        layers_missing = [layer for layer in LAYERS if layer not in layers_present]

        layer_blocks: dict[str, Any] = {}
        service_findings: list[dict[str, Any]] = []
        for layer in LAYERS:
            items = attached.get(name, {}).get(layer, [])
            failures = [item for item in items if item.get("status") == "FAIL"]
            service_findings.extend(failures)
            by_layer_failures[layer] = by_layer_failures.get(layer, 0) + len(failures)
            layer_blocks[layer] = {
                "observed": layer in layers_present,
                "evidence": (layer_reports[layer] or {}).get("model") if layer_reports.get(layer) else None,
                "findings": len(items),
                "failures": len(failures),
                "highest_severity": _highest(failures),
            }

        for finding in service_findings:
            severity = str(finding.get("severity") or "medium")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        service_findings.sort(key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 99))

        if not layers_present:
            verdict = "NO_EVIDENCE"
            blind_spots.append(name)
        elif any(finding.get("severity") in {"critical", "high"} for finding in service_findings):
            verdict = "NON_COMPLIANT"
        elif service_findings:
            verdict = "AT_RISK"
        elif layers_missing:
            verdict = "INCOMPLETE_COVERAGE"
        else:
            verdict = "COMPLIANT"

        results.append(
            {
                "service": name,
                "system": service.get("system"),
                "verdict": verdict,
                "layers": layer_blocks,
                "layers_present": sorted(layers_present),
                "layers_missing": layers_missing,
                "findings": service_findings,
                "cross_layer_review": entry.get("risk_hints") or [],
                "comparisons": entry.get("comparisons") or [],
                "coverage_note": (
                    "a missing layer is NOT_OBSERVED for this service — it is not proof the layer has no crypto"
                ),
            }
        )

    ranked = sorted(
        results,
        key=lambda item: (
            0 if item["verdict"] == "NON_COMPLIANT" else 1 if item["verdict"] == "AT_RISK" else 2,
            SEVERITY_ORDER.get(
                str((item["findings"][0] if item["findings"] else {}).get("severity") or "low"), 99
            ),
            item["service"],
        ),
    )

    exposed = (network_pqc or {}).get("harvest_now_decrypt_later") or {}
    migration = [
        {
            "service": item["service"],
            "why": f"{item['verdict']} — {len(item['findings'])} policy failure(s)",
            "layers": item["layers_present"],
        }
        for item in ranked
        if item["verdict"] in {"NON_COMPLIANT", "AT_RISK"}
    ]
    for endpoint in exposed.get("endpoints") or []:
        migration.append(
            {
                "service": None,
                "endpoint": endpoint,
                "why": "classical-only key exchange observed — harvest-now-decrypt-later exposure",
                "layers": ["NETWORK"],
            }
        )

    if not results:
        estate_verdict = "NO_EVIDENCE"
    elif any(item["verdict"] == "NON_COMPLIANT" for item in results):
        estate_verdict = "NON_COMPLIANT"
    elif any(item["verdict"] == "AT_RISK" for item in results):
        estate_verdict = "AT_RISK"
    elif any(item["verdict"] in {"INCOMPLETE_COVERAGE", "NO_EVIDENCE"} for item in results):
        estate_verdict = "INCOMPLETE_COVERAGE"
    else:
        estate_verdict = "COMPLIANT"

    return {
        "model": MODEL,
        "evaluated_at": moment.isoformat(),
        "policy": {
            "estate_policy": (policy or {}).get("policy_id") or "bank-crypto-estate-baseline",
            "version": (policy or {}).get("version") or "1",
            "layers": list(LAYERS),
        },
        "verdict": estate_verdict,
        "services": ranked,
        "summary": {
            "services": len(results),
            "by_verdict": {
                verdict: sum(1 for item in results if item["verdict"] == verdict)
                for verdict in ("COMPLIANT", "INCOMPLETE_COVERAGE", "AT_RISK", "NON_COMPLIANT", "NO_EVIDENCE")
            },
            "by_severity": by_severity,
            "by_layer": by_layer_failures,
            "blind_spots": len(blind_spots),
            "unattributed_findings": len(unattributed),
            "cross_layer_review_items": sum(len(item["cross_layer_review"]) for item in results),
        },
        "blind_spots": blind_spots,
        "unattributed_findings": unattributed,
        "migration_queue": migration[:50],
        "pqc": network_pqc,
        "refused_comparisons": list(REFUSED_COMPARISONS),
        "out_of_reach": list(OUT_OF_REACH),
        "limitations": [
            "an estate verdict is only as complete as the layers that were observed",
            "findings are attached by declared service/host/endpoint identity — an unattributed finding is a map gap",
            "network transport findings never become application findings here (§27)",
            "cross-layer comparison items require an analyst; nothing is auto-closed",
        ],
    }


__all__ = [
    "LAYERS",
    "MODEL",
    "OUT_OF_REACH",
    "REFUSED_COMPARISONS",
    "SEVERITY_ORDER",
    "evaluate_estate",
    "runtime_facts_from_events",
]
