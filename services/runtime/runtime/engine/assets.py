"""Normalize runtime events into crypto assets, CBOM, TechBOM (spec 92 §31).

Assets are grouped by the *artifact* that performed the operation — algorithm +
parameters + application + executable/image identity — so the CBOM answers
"which deployed thing uses AES-256-GCM" instead of listing four thousand
individual calls.

Attribution levels are reported, never smoothed: an asset that mixes a Level 1
crypto-API observation with a Level 4 TLS observation keeps both counts and both
labels, because they are not the same kind of proof.
"""

from __future__ import annotations

from typing import Any, Iterable

LEVEL_LABELS = {
    1: "CRYPTO_API_OBSERVED",
    2: "FRAMEWORK_OBSERVED",
    3: "AUDIT_TELEMETRY_OBSERVED",
    4: "NETWORK_SESSION_OBSERVED",
    5: "BINARY_INSTRUMENTATION_OBSERVED",
    6: "UNKNOWN",
}


def _identity(event: dict[str, Any]) -> dict[str, Any]:
    return event.get("identity") or {}


def _asset_key(event: dict[str, Any]) -> tuple:
    decomposition = event.get("decomposition") or {}
    identity = _identity(event)
    return (
        str(event.get("algorithm") or "UNKNOWN"),
        str(event.get("key_size")),
        str(decomposition.get("mode")),
        str(identity.get("application")),
        str(identity.get("executable_digest") or identity.get("executable")),
        str(identity.get("container_digest") or identity.get("image")),
    )


def build_runtime_assets(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group events into assets keyed by algorithm + parameters + artifact."""
    grouped: dict[tuple, dict[str, Any]] = {}
    for event in events:
        key = _asset_key(event)
        asset = grouped.get(key)
        decomposition = event.get("decomposition") or {}
        identity = _identity(event)
        if asset is None:
            asset = {
                "asset_key": list(key),
                "algorithm": event.get("algorithm"),
                "key_size": event.get("key_size"),
                "mode": decomposition.get("mode"),
                "padding": decomposition.get("padding"),
                "hash": decomposition.get("hash"),
                "curve": decomposition.get("curve"),
                "kdf": decomposition.get("kdf"),
                "operations": {},
                "providers": set(),
                "sources": set(),
                "levels": {},
                "applications": set(),
                "processes": set(),
                "containers": set(),
                "images": set(),
                "pods": set(),
                "deployments": set(),
                "event_ids": [],
                "observation_count": 0,
                "first_observed": event.get("observed_at"),
                "last_observed": event.get("observed_at"),
                "evidence_types": set(),
                "parameter_metadata": {},
            }
            grouped[key] = asset
        count = int(event.get("observation_count") or 1)
        asset["operations"][str(event.get("operation"))] = (
            asset["operations"].get(str(event.get("operation")), 0) + count
        )
        if event.get("crypto_provider"):
            asset["providers"].add(str(event["crypto_provider"]))
        asset["sources"].add(str(event.get("source")))
        level = int(event.get("attribution_level") or 6)
        label = LEVEL_LABELS.get(level, "UNKNOWN")
        asset["levels"][label] = asset["levels"].get(label, 0) + 1
        for bucket, value in (
            ("applications", identity.get("application")),
            ("processes", identity.get("process")),
            ("containers", identity.get("container_id")),
            ("images", identity.get("container_digest") or identity.get("image")),
            ("pods", identity.get("pod")),
            ("deployments", identity.get("deployment")),
        ):
            if value:
                asset[bucket].add(str(value))
        asset["event_ids"].append(event.get("event_id"))
        asset["observation_count"] += int(event.get("observation_count") or 1)
        asset["evidence_types"].add(str(event.get("evidence_type")))
        parameters = event.get("parameters") or {}
        for name in ("nonce_length", "tag_length", "iv_length", "digest_length"):
            value = parameters.get(name)
            if value not in (None, "UNKNOWN"):
                asset["parameter_metadata"].setdefault(name, value)
        timestamp = str(event.get("observed_at") or "")
        if timestamp and (not asset["first_observed"] or timestamp < asset["first_observed"]):
            asset["first_observed"] = timestamp
        if timestamp and (not asset["last_observed"] or timestamp > asset["last_observed"]):
            asset["last_observed"] = timestamp

    assets: list[dict[str, Any]] = []
    for asset in grouped.values():
        for bucket in (
            "providers", "sources", "applications", "processes",
            "containers", "images", "pods", "deployments", "evidence_types",
        ):
            asset[bucket] = sorted(asset[bucket])
        asset["event_ids"] = asset["event_ids"][:200]
        asset["layer"] = "RUNTIME"
        asset["confidence"] = (
            "HIGH" if set(asset["levels"]) - {"UNKNOWN"} else "LOW"
        )
        assets.append(asset)
    assets.sort(key=lambda item: (-item["observation_count"], str(item["algorithm"])))
    return assets


def build_runtime_cbom(
    events: Iterable[dict[str, Any]],
    *,
    estate: str | None = None,
) -> dict[str, Any]:
    """CBOM-shaped projection of runtime assets (§28-adjacent, runtime layer)."""
    events = list(events)
    assets = build_runtime_assets(events)
    algorithms: dict[str, int] = {}
    operations: dict[str, int] = {}
    levels: dict[str, int] = {}
    for asset in assets:
        algorithms[str(asset["algorithm"])] = algorithms.get(str(asset["algorithm"]), 0) + asset["observation_count"]
        for operation, count in asset["operations"].items():
            operations[operation] = operations.get(operation, 0) + count
        for label, count in asset["levels"].items():
            levels[label] = levels.get(label, 0) + count
    return {
        "model": "cryptoscan.runtime-cbom/1",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "estate": estate,
        "layer": "RUNTIME",
        "asset_count": len(assets),
        "event_count": len(events),
        "assets": assets,
        "algorithms": algorithms,
        "operations": operations,
        "attribution_levels": levels,
        "boundary": (
            "runtime crypto observed on this estate — transport crypto seen only at Level 4 is "
            "labelled as such, and application crypto is never inferred from a TLS session"
        ),
        "unobserved_note": (
            "an application with no runtime event is NOT_OBSERVED: it may use no crypto, or its "
            "crypto may be a Level 6 blind spot"
        ),
    }


def build_runtime_techbom(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Which processes, providers and operations were seen running."""
    events = list(events)
    providers: dict[str, int] = {}
    applications: dict[str, int] = {}
    processes: dict[str, int] = {}
    hosts: dict[str, int] = {}
    images: dict[str, int] = {}
    for event in events:
        identity = _identity(event)
        if event.get("crypto_provider"):
            providers[str(event["crypto_provider"])] = providers.get(str(event["crypto_provider"]), 0) + 1
        if identity.get("application"):
            applications[str(identity["application"])] = applications.get(str(identity["application"]), 0) + 1
        if identity.get("process"):
            processes[str(identity["process"])] = processes.get(str(identity["process"]), 0) + 1
        if identity.get("host"):
            hosts[str(identity["host"])] = hosts.get(str(identity["host"]), 0) + 1
        image = identity.get("container_digest") or identity.get("image")
        if image:
            images[str(image)] = images.get(str(image), 0) + 1
    def _rows(mapping: dict[str, int], name: str) -> list[dict[str, Any]]:
        return [
            {name: key, "observations": value}
            for key, value in sorted(mapping.items(), key=lambda item: (-item[1], item[0]))
        ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "bom_type": "TECHBOM",
        "model": "cryptoscan.runtime-techbom/1",
        "events": len(events),
        "hosts": _rows(hosts, "host"),
        "applications": _rows(applications, "application"),
        "processes": _rows(processes, "process"),
        "providers": _rows(providers, "crypto_provider"),
        "images": _rows(images, "image"),
        "note": "a TechBOM records what ran; it makes no crypto claim about unobserved code",
    }


def summarize_runtime_events(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Counts an operator needs first: operations, levels, blind spots."""
    events = list(events)
    operations: dict[str, int] = {}
    levels: dict[str, int] = {}
    sources: dict[str, int] = {}
    algorithms: dict[str, int] = {}
    hosts: set[str] = set()
    applications: set[str] = set()
    unknown_algorithm = 0
    unknown_level6 = 0
    for event in events:
        operations[str(event.get("operation"))] = operations.get(str(event.get("operation")), 0) + 1
        level = int(event.get("attribution_level") or 6)
        label = LEVEL_LABELS.get(level, "UNKNOWN")
        levels[label] = levels.get(label, 0) + 1
        sources[str(event.get("source"))] = sources.get(str(event.get("source")), 0) + 1
        if event.get("algorithm"):
            algorithms[str(event["algorithm"])] = algorithms.get(str(event["algorithm"]), 0) + 1
        else:
            unknown_algorithm += 1
        if level == 6:
            unknown_level6 += 1
        identity = _identity(event)
        if identity.get("host"):
            hosts.add(str(identity["host"]))
        if identity.get("application"):
            applications.add(str(identity["application"]))
    return {
        "model": "cryptoscan.runtime-summary/1",
        "events": len(events),
        "hosts": len(hosts),
        "applications": len(applications),
        "operations": operations,
        "attribution_levels": levels,
        "sources": sources,
        "algorithms": algorithms,
        "unknown_algorithm_events": unknown_algorithm,
        "level6_events": unknown_level6,
        "note": (
            "Level 6 events are blind spots, not clean results; an application with no event is "
            "NOT_OBSERVED rather than crypto-free"
        ),
    }
