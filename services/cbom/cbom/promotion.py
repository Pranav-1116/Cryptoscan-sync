"""Promotion: from "this library can do AES" to "this is a CBOM asset".

The review's item 6 is the one that decides whether a CBOM is trustworthy: a
library named ``openssl`` must not mint ``AES-128 USED``, ``AES-256 USED``,
``RSA-2048 USED`` and ``ECDSA-P256 USED`` merely because OpenSSL supports them.
The chain it asks for instead is:

    library capability  ->  candidate algorithms  ->  evidence promotes

This module implements exactly that chain and makes the promotion boundary
explicit. A candidate becomes a **CBOM asset** only when an observing class
(static, configuration, runtime, network) reports the algorithm. A
capability-only candidate stays a candidate: it is returned, with the evidence
that would promote it, and is deliberately *not* written into the CBOM
document — because a document is what a reviewer reads as fact.

Each promoted asset also carries a promotion level, so the document says *why*
the asset is in it:

``STATIC``/``CONFIGURED``
    the code or the configuration was seen to select it
``RUNTIME``/``NETWORK``
    the operation or the handshake was seen to use it
``VERIFIED``
    runtime **and** network both saw it — two independent mechanisms
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from cbom import usage_evidence as ue

SCHEMA = "cryptoscan.cbom-promotion/1"

#: Ordered weakest to strongest. ``VERIFIED`` is not "more observed", it is
#: "observed twice by mechanisms that cannot both be one liar".
PROMOTION_LEVELS: tuple[str, ...] = (
    "NONE", "CAPABILITY", "STATIC", "CONFIGURED", "RUNTIME", "NETWORK", "VERIFIED",
)

LEVEL_FOR_CLASS: dict[str, str] = {
    "UNKNOWN": "NONE",
    "IMPORTED": "CAPABILITY",
    "VENDOR_DECLARED": "CAPABILITY",
    "INFERRED": "CAPABILITY",
    "STATIC_OBSERVED": "STATIC",
    "CONFIGURED": "CONFIGURED",
    "RUNTIME_OBSERVED": "RUNTIME",
    "NETWORK_OBSERVED": "NETWORK",
}

LEVEL_RANK: dict[str, int] = {
    "NONE": 0, "CAPABILITY": 1, "STATIC": 2, "CONFIGURED": 2, "RUNTIME": 3,
    "NETWORK": 3, "VERIFIED": 4,
}

#: CycloneDX ``cryptoFunction`` values, from the primitive the asset declares.
_FUNCTION_FOR_PRIMITIVE: dict[str, list[str]] = {
    "aead": ["encrypt", "decrypt"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
    "pke": ["encrypt", "decrypt"],
    "signature": ["sign", "verify"],
    "key-agree": ["keygen", "derive"],
    "key-agreement": ["keygen", "derive"],
    "hash": ["digest"],
    "mac": ["tag"],
    "kdf": ["derive"],
}


def promotion_level(classes: Iterable[str]) -> str:
    """The strongest level the evidence classes support, ``VERIFIED`` at the top."""
    present = {str(value).strip().upper() for value in classes}
    levels = {LEVEL_FOR_CLASS.get(value, "NONE") for value in present}
    if levels & {"RUNTIME", "NETWORK"} == {"RUNTIME", "NETWORK"}:
        return "VERIFIED"
    return max(levels, key=lambda level: LEVEL_RANK.get(level, 0), default="NONE")


def _bom_ref(algorithm: str) -> str:
    return "crypto/algorithm/" + algorithm.strip().replace(" ", "-").lower()


def crypto_component(algorithm: str, *, profile: Mapping[str, Any] | None = None,
                     primitive: str | None = None, oid: str | None = None) -> dict[str, Any]:
    """A CycloneDX 1.5 ``cryptographic-asset`` for one promoted algorithm.

    Only the specification's fields go in ``cryptoProperties``; everything this
    platform adds — usage state, confidence, evidence ids, promotion level — is a
    ``cryptoscan:`` property, so the document stays valid CycloneDX and the
    platform's claims stay distinguishable from the standard's.
    """
    profile = profile or {}
    asset = profile.get("asset") or {}
    parameters = asset.get("parameters") or {}
    classes = list(profile.get("observed_classes") or [])
    level = promotion_level(classes) if classes else "CAPABILITY"
    properties = [
        {"name": "cryptoscan:usage", "value": str(profile.get("usage") or "OBSERVED")},
        {"name": "cryptoscan:confidence", "value": str(profile.get("confidence") or "UNKNOWN")},
        {"name": "cryptoscan:promotion_level", "value": level},
        {"name": "cryptoscan:observed_classes", "value": ",".join(sorted(classes))},
    ]
    for evidence_id in profile.get("evidence_ids") or ():
        properties.append({"name": "cryptoscan:evidence_id", "value": str(evidence_id)})
    if asset.get("purpose"):
        properties.append({"name": "cryptoscan:purpose", "value": str(asset["purpose"])})
    algorithm_properties: dict[str, Any] = {
        "parameterSetIdentifier": (str(parameters.get("key_size"))
                                   if parameters.get("key_size") else None),
        "mode": parameters.get("mode"),
        "curve": parameters.get("curve"),
        "executionEnvironment": "software-plain-ram",
        "implementationPlatform": "unknown",
        "certificationLevel": [],
        "cryptoFunction": _FUNCTION_FOR_PRIMITIVE.get(str(primitive or "").lower(), []),
    }
    algorithm_properties = {key: value for key, value in algorithm_properties.items()
                            if value not in (None, "", [])}
    crypto_properties: dict[str, Any] = {"assetType": "algorithm"}
    if oid:
        crypto_properties["oid"] = oid
    if primitive:
        crypto_properties["primitive"] = primitive
    crypto_properties["algorithmProperties"] = algorithm_properties
    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref(algorithm),
        "name": algorithm,
        "cryptoProperties": crypto_properties,
        "properties": properties,
    }


def promote(components: Iterable[Mapping[str, Any]],
            evidence: Iterable[Mapping[str, Any]], *,
            purposes: Mapping[str, str] | None = None,
            primitives: Mapping[str, str] | None = None,
            oids: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Promote observed algorithms to CBOM assets, and keep the rest candidates.

    ``components`` are the SBOM's crypto-capable libraries with the algorithms
    they support (``{"name": "openssl", "algorithms": [...], "evidence_id":
    "SBOM-1"}``). ``evidence`` are the collector events from
    :mod:`cbom.usage_collectors`.

    A component with no evidence id at all is refused: the SBOM that listed it
    could not be pointed at, so its capabilities are not attributable claims.
    An algorithm with only declared evidence stays a **candidate** — reported,
    never written into the document.
    """
    events = [dict(event) for event in evidence]
    purposes = purposes or {}
    primitives = primitives or {}
    oids = oids or {}
    assets: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    levels: dict[str, int] = {}
    for component in components:
        if not isinstance(component, Mapping):
            refused.append({"component": component, "reason": "a component must be an object"})
            continue
        name = str(component.get("name") or "").strip()
        algorithms = [str(value).strip() for value in (component.get("algorithms") or [])
                      if str(value).strip()]
        if not name or not algorithms:
            refused.append({"component": name or None,
                            "reason": "a component needs a name and the algorithms it supports"})
            continue
        evidence_id = str(component.get("evidence_id") or "").strip()
        if not evidence_id:
            refused.append({
                "component": name,
                "reason": "the component has no evidence id, so its capabilities cannot be "
                          "attributed to a document"})
            continue
        listed = ue.capability_candidates(name, algorithms, evidence_id=evidence_id)
        for candidate in listed["candidates"]:
            algorithm = candidate["algorithm"]
            parameters: dict[str, Any] = {}
            for event in events:
                if str(event.get("algorithm") or "") != algorithm:
                    continue
                for key, value in (event.get("parameters") or {}).items():
                    parameters.setdefault(key, value)
            profile = ue.usage_profile({"algorithm": algorithm, "parameters": parameters,
                                        "purpose": purposes.get(algorithm)},
                                       events)
            profile["roles"] = sorted({str(event.get("role")) for event in events
                                       if event.get("role")
                                       and str(event.get("algorithm")) == algorithm})
            profile["component"] = name
            level = promotion_level(profile["observed_classes"])
            profile["promotion_level"] = level
            if profile["usage"] != "OBSERVED":
                candidates.append({**candidate, "profile": profile,
                                   "promotable_by": listed["promotable_by"]})
                continue
            assets.append({
                "algorithm": algorithm,
                "component": name,
                "promotion_level": level,
                "component_document": crypto_component(
                    algorithm, profile=profile, primitive=primitives.get(algorithm),
                    oid=oids.get(algorithm)),
                "profile": profile,
            })
            levels[level] = levels.get(level, 0) + 1
    assets.sort(key=lambda row: (row["algorithm"], row["component"]))
    return {
        "schema": SCHEMA,
        "assets": assets,
        "candidates": candidates,
        "refused": refused,
        "levels": dict(sorted(levels.items())),
        "statement": (
            f"{len(assets)} CBOM asset(s) promoted from evidence, "
            f"{len(candidates)} candidate(s) left out of the document"
            + ("; a capability is not an invocation" if candidates else "")
            + (f"; {len(refused)} component(s) refused for carrying no evidence"
               if refused else "")),
    }


def to_cbom(promoted: Mapping[str, Any], *, name: str = "cryptoscan-promotion",
            version: str = "1.0.0") -> dict[str, Any]:
    """A CycloneDX 1.5 CBOM holding the promoted assets and nothing else.

    The candidates are summarised as a count in metadata properties, not as
    components: putting them in the document is how an inventory becomes a claim.
    """
    components = [asset["component_document"] for asset in promoted.get("assets") or ()]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": name, "version": version},
            # Platform claims live in metadata properties: CycloneDX has no
            # top-level ``properties`` array, so writing one there produced a
            # document a strict consumer rejects.
            "properties": [
                {"name": "cryptoscan:promoted_assets", "value": str(len(components))},
                {"name": "cryptoscan:candidates_excluded",
                 "value": str(len(promoted.get("candidates") or ()))},
                {"name": "cryptoscan:promotion_schema", "value": SCHEMA},
                {"name": "cryptoscan:promotion_statement",
                 "value": str(promoted.get("statement") or "")},
            ],
        },
        "components": components,
    }


def asset_inventory(promoted: Mapping[str, Any]) -> dict[str, Any]:
    """What the document may be read as saying — counts per algorithm and level."""
    by_algorithm: dict[str, list[str]] = {}
    for asset in promoted.get("assets") or ():
        by_algorithm.setdefault(str(asset["algorithm"]), []).append(str(asset["promotion_level"]))
    return {
        "schema": SCHEMA,
        "algorithms": {name: sorted(set(levels)) for name, levels in sorted(by_algorithm.items())},
        "levels": dict(promoted.get("levels") or {}),
        "candidates": len(promoted.get("candidates") or ()),
        "refused": len(promoted.get("refused") or ()),
        "statement": (
            f"{len(by_algorithm)} algorithm(s) in the document across "
            f"{len(promoted.get('levels') or {})} promotion level(s); "
            f"{len(promoted.get('candidates') or {})} candidate(s) are not in it"),
    }
