"""What the estate's cryptography actually is — weak, unknown, and post-quantum (§12, §24, §26).

Three of the Digital Twin's questions are about the same artefacts read three ways:

* **weak** — an algorithm the platform's registry rates ``DISALLOWED`` or ``DEPRECATED``;
* **unknown** — a value nobody has identified. An unrecognised algorithm is not a
  compliant one, and the twin must not let "we do not know what this is" pass as "nothing
  to report here";
* **post-quantum** — how much of the estate rests on an algorithm that a quantum computer
  breaks (``quantum_impact == "shor"``: RSA, ECDSA, ECDH, DH, DSA), and **who could
  change it in a config and who cannot** — an application is a recompile, an HSM is a
  vendor.

Three rules keep the answer usable, and each is enforced below rather than documented:

1. **capability is not use.** A library that supports DES has not used DES. Every finding
   carries its ``usage_state``, ``SUPPORTED`` is counted separately and never in
   ``in_use_count``, and the payload says so in words — otherwise a PQC programme starts
   with a list of libraries that merely *could* do the wrong thing.
2. **a verdict is an opinion, not evidence.** The status comes from
   ``shared_models.algorithm_registry``, this product's own policy table, not from the
   bank. That is labelled on every entry and stated in the limits: the registry can be
   argued with, the evidence behind each value cannot.
3. **a version string is not an algorithm.** Collectors sometimes put a library version in
   the ``algorithm`` fact. That is reported as ``NOT_AN_ALGORITHM`` — a data-quality
   finding about the *collector* — rather than as unidentified cryptography, because the
   two need different people to fix them.

Nothing here scores the estate. ``pqc_readiness`` is a count of artefacts and the blockers
that need a vendor, and a low number is a description of the estate, never a verdict on it.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from shared_models.algorithm_registry import parse_algorithm

SCHEMA = "cryptoscan.estate-crypto-intel/1"
ALGORITHM_SCHEMA = "cryptoscan.estate-algorithm/1"

#: statuses from the registry that mean "this should not be here"
WEAK_STATUSES = ("DISALLOWED", "DEPRECATED")

#: a value shaped like "OpenSSL 3.0.13" is a product version that landed in an algorithm
#: fact, not cryptography nobody has identified
_VERSIONISH = re.compile(r"^[A-Za-z][A-Za-z ._+-]*\s+\d+(?:\.\d+)+", re.UNICODE)

#: asset types that cannot be fixed by changing a configuration file
VENDOR_BOUND_TYPES = frozenset({"HSM", "KMS_KEY", "FIRMWARE", "HARDWARE", "PRODUCT", "VENDOR"})

#: the states in which an artefact is something the estate *did*, not something it could do
IN_USE_STATES = frozenset({"CONFIGURED", "NEGOTIATED", "OBSERVED"})

REMEDIATION = {
    "DISALLOWED": (
        "this algorithm is not permitted. Find what still needs it, change the configuration or "
        "the library that selects it, and re-collect to prove the old value is gone"
    ),
    "DEPRECATED": (
        "this algorithm is on its way out. Record why it is still in use, and put it on the "
        "migration plan with the owner of the asset"
    ),
    "UNKNOWN": (
        "nobody has identified this value. Find out what it is before deciding anything about it "
        "— an unknown algorithm is not a compliant one"
    ),
    "NOT_AN_ALGORITHM": (
        "this is a library or product version, not an algorithm. The collector that wrote it into "
        "an algorithm fact is mislabelling, so the real algorithm on this asset is still unknown"
    ),
}


def classify(value: Any) -> dict[str, Any]:
    """One algorithm value, read against the registry and against its own shape."""
    raw = str(value if value is not None else "").strip()
    info = parse_algorithm(raw)
    payload = info.to_dict()
    payload["raw"] = raw
    if info.recognized:
        payload["verdict_source"] = "algorithm_registry"
        payload["reading"] = "ALGORITHM"
        return payload

    # unrecognised: is it cryptography we cannot name, or a version string in the wrong field?
    versionish = bool(_VERSIONISH.match(raw))
    payload["verdict_source"] = "algorithm_registry"
    payload["reading"] = "NOT_AN_ALGORITHM" if versionish else "UNRECOGNIZED"
    payload["notes"] = (
        "this looks like a product or library version rather than an algorithm name"
        if versionish
        else "the registry does not recognise this value as an algorithm"
    )
    return payload


def _entry(artifact: Mapping[str, Any], verdict: Mapping[str, Any]) -> dict[str, Any]:
    """One artefact, with the reading of its algorithm and what that means for it."""
    usage_state = str(artifact.get("usage_state") or "UNKNOWN")
    in_use = usage_state in IN_USE_STATES
    return {
        "asset_id": artifact.get("asset_id"),
        "asset_name": artifact.get("asset_name"),
        "asset_type": artifact.get("asset_type"),
        "artifact_id": artifact.get("artifact_id"),
        "algorithm": artifact.get("algorithm"),
        "canonical": verdict.get("algorithm"),
        "family": verdict.get("family"),
        "status": verdict.get("status"),
        "key_size": artifact.get("key_size"),
        "mode": artifact.get("mode"),
        "curve": artifact.get("curve"),
        "layer": artifact.get("layer"),
        "usage_state": usage_state,
        "in_use": in_use,
        "evidence_type": artifact.get("evidence_type"),
        "confidence": artifact.get("confidence"),
        "evidence_ids": list(artifact.get("evidence_ids") or []),
        "source": artifact.get("source"),
        "observed_at": artifact.get("observed_at"),
        "quantum_impact": verdict.get("quantum_impact"),
        "quantum_vulnerable": bool(verdict.get("quantum_vulnerable")),
        "verdict_source": verdict.get("verdict_source"),
        "reading": verdict.get("reading"),
        "notes": verdict.get("notes"),
    }


def _readings(graph: Any) -> list[dict[str, Any]]:
    """Every crypto artefact the graph holds, each with the registry's reading of it."""
    entries: list[dict[str, Any]] = []
    for artifact in graph.crypto_artifacts():
        if artifact.get("algorithm") in (None, ""):
            continue
        entries.append(_entry(artifact, classify(artifact.get("algorithm"))))
    return entries


def _by(entries: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in entries:
        name = str(entry.get(key) or "UNKNOWN")
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


def _assets(entries: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for entry in entries:
        asset_id = str(entry.get("asset_id"))
        record = seen.setdefault(
            asset_id,
            {
                "asset_id": asset_id,
                "asset_name": entry.get("asset_name"),
                "asset_type": entry.get("asset_type"),
                "algorithms": [],
                "in_use": False,
                "vendor_bound": str(entry.get("asset_type")) in VENDOR_BOUND_TYPES,
            },
        )
        if str(entry.get("algorithm")) not in record["algorithms"]:
            record["algorithms"].append(str(entry.get("algorithm")))
        record["in_use"] = record["in_use"] or bool(entry.get("in_use"))
    return sorted(seen.values(), key=lambda item: str(item.get("asset_name") or item["asset_id"]))


def survey(graph: Any, *, limit: int = 200) -> dict[str, Any]:
    """Weak, unknown and post-quantum cryptography across the whole estate (§12, §24)."""
    readings = _readings(graph)

    weak = [
        entry for entry in readings
        if entry["reading"] == "ALGORITHM" and entry["status"] in WEAK_STATUSES
    ]
    unidentified = [entry for entry in readings if entry["reading"] in ("UNRECOGNIZED", "NOT_AN_ALGORITHM")]
    mislabelled = [entry for entry in readings if entry["reading"] == "NOT_AN_ALGORITHM"]
    unknown_crypto = [entry for entry in readings if entry["reading"] == "UNRECOGNIZED"]

    vulnerable = [entry for entry in readings if entry["quantum_vulnerable"]]
    vulnerable_in_use = [entry for entry in vulnerable if entry["in_use"]]
    # what a migration cannot fix with a config change: the vendor has to ship it
    blockers = [
        entry for entry in vulnerable
        if str(entry.get("asset_type")) in VENDOR_BOUND_TYPES
    ]
    pqc_algorithms = sorted({
        str(entry["canonical"]) for entry in readings
        if entry.get("family") in ("signature-pqc", "kem-pqc") or
        str(entry.get("family") or "").endswith("-pqc")
    })

    weak_in_use = [entry for entry in weak if entry["in_use"]]
    weak_capability = [entry for entry in weak if not entry["in_use"]]

    return {
        "schema": SCHEMA,
        "artifacts_examined": len(readings),
        "weak": {
            "count": len(weak),
            "in_use_count": len(weak_in_use),
            "capability_only_count": len(weak_capability),
            "by_status": _by(weak, "status"),
            "by_asset_type": _by(weak_in_use, "asset_type"),
            "assets": _assets(weak_in_use)[:limit],
            "capability_only": [
                {
                    "asset_id": entry["asset_id"],
                    "asset_name": entry["asset_name"],
                    "algorithm": entry["algorithm"],
                    "status": entry["status"],
                    "layer": entry["layer"],
                    "note": (
                        "this asset declares support for it; nothing observed it being used. "
                        "Capability is not use"
                    ),
                }
                for entry in weak_capability[:limit]
            ],
            "entries": weak[:limit],
            "meaning": (
                "an algorithm this product's registry rates DISALLOWED or DEPRECATED, counted "
                "separately by whether the estate is recorded as *doing* it"
            ),
        },
        "unknown": {
            "count": len(unidentified),
            "unrecognised_count": len(unknown_crypto),
            "mislabelled_count": len(mislabelled),
            "assets": _assets(unidentified)[:limit],
            "entries": unidentified[:limit],
            "meaning": (
                "cryptography nobody has identified, or a version string in an algorithm fact — "
                "the first is a gap in knowledge, the second a gap in a collector"
            ),
        },
        "pqc": {
            "vulnerable_artifacts": len(vulnerable),
            "vulnerable_in_use": len(vulnerable_in_use),
            "by_algorithm": _by(vulnerable, "canonical"),
            "by_asset_type": _by(vulnerable, "asset_type"),
            "affected_assets": _assets(vulnerable)[:limit],
            "vendor_bound_blockers": _assets(blockers)[:limit],
            "vendor_bound_blocker_count": len(_assets(blockers)),
            "pqc_algorithms_present": pqc_algorithms,
            "pending_migration_count": len(vulnerable_in_use),
            "meaning": (
                "artefacts whose algorithm a quantum computer breaks (Shor). The count is a "
                "description of the estate, not a readiness score: readiness is which of these "
                "can be changed in a configuration and which need the vendor to ship a version"
            ),
        },
        "next_action": (
            "start with the in-use weak algorithms — they are the ones an auditor will ask about "
            "and the ones a configuration change can close. Then the vendor-bound post-quantum "
            "blockers, which need a procurement conversation rather than an engineer"
        ),
        "limits": [
            "a verdict comes from this product's algorithm registry, not from the bank's own "
            "policy: it can be argued with, and it is labelled on every entry so it is not "
            "mistaken for evidence",
            "capability is counted apart from use. A library that supports DES has not used DES, "
            "and merging the two turns a PQC programme into a list of things that might be wrong",
            "an unknown algorithm is reported as unknown, never as compliant: the list is what "
            "nobody has identified yet, and it is not empty on any estate this product has seen",
            "post-quantum exposure is judged from the algorithm name alone. Whether a particular "
            "RSA-2048 key protects data that must stay secret for twenty years is a question for "
            "the data owner",
        ],
    }


def algorithm(graph: Any, query: str, *, limit: int = 200) -> dict[str, Any]:
    """Everything the estate holds about one algorithm (§26, §27).

    The question is "who depends on RSA-2048", and the answer is a set of assets by type,
    each with the evidence that put it there — plus the honest split between assets that
    *use* it and assets that merely *support* it.
    """
    wanted = " ".join(str(query or "").split())
    if not wanted:
        raise ValueError("an algorithm name is required")
    verdict = classify(wanted)
    canonical = str(verdict.get("algorithm") or wanted)

    matched = [
        entry for entry in _readings(graph)
        if str(entry.get("algorithm")).strip().lower() == wanted.lower()
        or str(entry.get("canonical")).strip().lower() == canonical.lower()
    ]
    if not matched:
        # fall back to the family so "RSA" finds "RSA-2048", but say that is what happened
        family = str(verdict.get("family") or "")
        if family and family != "unknown":
            matched = [entry for entry in _readings(graph) if entry.get("family") == family]
            if matched:
                canonical = f"{canonical} (family {family})"
    in_use = [entry for entry in matched if entry["in_use"]]
    capability = [entry for entry in matched if not entry["in_use"]]

    return {
        "schema": ALGORITHM_SCHEMA,
        "query": wanted,
        "algorithm": canonical,
        "family": verdict.get("family"),
        "status": verdict.get("status"),
        "quantum_impact": verdict.get("quantum_impact"),
        "quantum_vulnerable": bool(verdict.get("quantum_vulnerable")),
        "recognized": bool(verdict.get("recognized")),
        "reading": verdict.get("reading"),
        "verdict_source": verdict.get("verdict_source"),
        "found": bool(matched),
        "artifacts": len(matched),
        "in_use": len(in_use),
        "capability_only": len(capability),
        "by_asset_type": _by(matched, "asset_type"),
        "by_asset_type_in_use": _by(in_use, "asset_type"),
        "by_usage_state": _by(matched, "usage_state"),
        "by_layer": _by(matched, "layer"),
        "assets": _assets(matched)[:limit],
        "entries": matched[:limit],
        "next_action": (
            REMEDIATION.get(str(verdict.get("status")), REMEDIATION["UNKNOWN"])
            if not verdict.get("recognized")
            else REMEDIATION.get(str(verdict.get("status")), "")
        ),
        "limits": [
            "counts are of artefacts the evidence supports, not of every instance in the bank: "
            "an asset nothing collected is absent, which is why coverage is reported next to this",
            "an asset that merely supports the algorithm is counted in capability_only and not in "
            "in_use, so 'we depend on RSA-2048' cannot be built out of a library's feature list",
            "an empty answer means no observation asserted this algorithm — not that the estate "
            "does not use it",
        ],
    }
