"""PQC handoff: a CBOM says what exists; migration says what must change.

The review's items 14 and 15 ask for two things that are easy to get wrong:

1. **PQC readiness is not the CBOM.** A CBOM inventories cryptography. Deciding
   what needs migration, what depends on it and what blocks it belongs to the PQC
   engine. So this module is the *seam*: it takes inventoried assets (with their
   usage evidence) and returns a per-asset migration handoff — it never adds the
   verdict back into the document as if the document had proven it.
2. **A boolean is not a quantum status.** ``quantumVulnerable: null`` was honest,
   ``quantumVulnerable: false`` for AES-256 hid the Grover caveat, and neither
   could say "this is a hybrid we are transitioning to". The vocabulary here is
   the review's: ``NOT_ASSESSED`` / ``CLASSICAL_ONLY`` / ``QUANTUM_SENSITIVE`` /
   ``QUANTUM_RESISTANT`` / ``HYBRID`` / ``TRANSITIONAL`` / ``UNKNOWN``, with
   ``algorithm_class``, ``quantum_risk``, ``migration_priority`` and
   ``migration_status`` kept as separate fields.

Classification is deterministic and comes from the platform's own registry
(``shared_models.algorithm_registry``) plus ``quantum.risk`` — no model calls, no
guessing. An algorithm the registry does not recognise is ``UNKNOWN`` with
``requires_review: true``; it is never quietly bucketed as resistant.

Priority is where usage evidence enters, and it only ever escalates: an algorithm
with runtime evidence outranks the same algorithm that is merely a capability,
because the first is a deployment and the second is a possibility. Nothing here
de-escalates a finding.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import Any

SCHEMA = "cryptoscan.cbom-pqc-handoff/1"

#: The review's status vocabulary, in escalation order (``NOT_ASSESSED`` and
#: ``UNKNOWN`` are not on the ladder; they are the absence of an answer).
PQC_STATUSES: tuple[str, ...] = (
    "NOT_ASSESSED", "CLASSICAL_ONLY", "TRANSITIONAL", "QUANTUM_RESISTANT", "HYBRID",
    "QUANTUM_SENSITIVE", "UNKNOWN",
)

MIGRATION_PRIORITIES: tuple[str, ...] = ("NONE", "LOW", "MEDIUM", "HIGH", "IMMEDIATE", "UNKNOWN")

MIGRATION_STATUSES: tuple[str, ...] = (
    "NOT_STARTED", "PLANNED", "IN_PROGRESS", "MIGRATED", "NOT_APPLICABLE",
)

ALGORITHM_CLASSES: tuple[str, ...] = (
    "PUBLIC_KEY", "SIGNATURE", "KEM", "SYMMETRIC", "HASH", "PROTOCOL", "UNKNOWN",
)

#: Registry families -> the class a reader cares about.
_FAMILY_CLASSES: dict[str, str] = {
    "pke": "PUBLIC_KEY", "kem": "PUBLIC_KEY", "signature": "PUBLIC_KEY",
    "ecdh": "PUBLIC_KEY", "dh": "PUBLIC_KEY", "kex": "PUBLIC_KEY",
    "kem-pqc": "KEM", "kem-hybrid-pqc": "KEM",
    "signature-pqc": "SIGNATURE", "signature-hybrid-pqc": "SIGNATURE",
    "aead": "SYMMETRIC", "cipher": "SYMMETRIC", "block-cipher": "SYMMETRIC",
    "stream-cipher": "SYMMETRIC", "mac": "SYMMETRIC", "kdf": "SYMMETRIC",
    "hash": "HASH", "xof": "HASH", "protocol": "PROTOCOL",
}

#: Purposes where a Shor-vulnerable algorithm protects data that will be
#: harvested now and decrypted later. Signature use is excluded on purpose: it is
#: an authenticity problem, not a harvested-ciphertext one.
_CONFIDENTIALITY_PURPOSES = frozenset({
    "ENCRYPTION", "DECRYPTION", "KEY_AGREEMENT", "KEY_EXCHANGE", "KEY_TRANSPORT",
    "TLS", "DATA_AT_REST", "DATA_IN_TRANSIT",
})

_RISK_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_PRIORITY_FOR_RISK = {"CRITICAL": "IMMEDIATE", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                      "LOW": "LOW", "NONE": "NONE", "UNKNOWN": "UNKNOWN"}

#: Usage levels that mean "this is deployed and running", not "this could be".
_OBSERVED_USAGE = frozenset({"RUNTIME", "NETWORK", "VERIFIED"})


def _parse(algorithm: str | None):
    from shared_models.algorithm_registry import parse_algorithm

    return parse_algorithm(algorithm or "")


def _norm(value: Any) -> str:
    return str(value or "").strip().upper().replace("-", "_")


def algorithm_class(algorithm: str | None) -> str:
    """Registry family -> PUBLIC_KEY / SIGNATURE / KEM / SYMMETRIC / HASH / ..."""
    parsed = _parse(algorithm)
    if not parsed.recognized:
        return "UNKNOWN"
    return _FAMILY_CLASSES.get(parsed.family, "UNKNOWN")


def quantum_status(algorithm: str | None, key_size: int | None = None) -> dict[str, Any]:
    """The review's status, with the basis that produced it.

    ``TRANSITIONAL`` is deliberate for Grover-impacted primitives (AES-128,
    SHA-256): they are not broken today and they are not PQC-grade either. A
    boolean has no way to say that, which is the review's point.
    """
    name = str(algorithm or "").strip()
    if not name:
        return {"status": "NOT_ASSESSED", "basis": "NO_ALGORITHM",
                "note": "no algorithm identity, so no quantum claim is made"}
    parsed = _parse(name)
    if not parsed.recognized or parsed.family == "unknown":
        return {"status": "UNKNOWN", "basis": "UNRECOGNIZED_ALGORITHM", "requires_review": True,
                "note": f"{name!r} is not in the algorithm registry; resistance is not assumed"}
    family = parsed.family
    if family.endswith("-hybrid-pqc"):
        return {"status": "HYBRID", "basis": "REGISTRY_HYBRID",
                "note": "classical + PQC in one construction; the classical half must not be "
                        "dropped during migration"}
    if family.endswith("-pqc"):
        return {"status": "QUANTUM_RESISTANT", "basis": "REGISTRY_PQC",
                "note": "PQC algorithm; deployment and negotiation are separate findings"}
    if parsed.quantum_impact == "shor":
        return {"status": "QUANTUM_SENSITIVE", "basis": "REGISTRY_SHOR",
                "note": "Shor breaks this public-key primitive; migrate to ML-KEM / ML-DSA"}
    if parsed.quantum_impact == "grover":
        # Grover halves the security level, so the *size* decides whether this is a
        # finding or a note: AES-256 / SHA-384 keep >=128 bits and are acceptable,
        # AES-128 / SHA-256 do not. A bare boolean could not have said this.
        size = key_size if isinstance(key_size, int) else parsed.key_size
        target = 384 if parsed.family in {"hash", "xof"} else 256
        if isinstance(size, int) and size >= target:
            return {"status": "CLASSICAL_ONLY", "basis": "REGISTRY_GROVER_ACCEPTABLE_MARGIN",
                    "note": f"Grover halves {size}-bit to >={size // 2} bits; acceptable, "
                            "and still not a PQC algorithm"}
        return {"status": "TRANSITIONAL", "basis": "REGISTRY_GROVER",
                "note": "Grover halves the margin below the target; usable now, not the "
                        "target state"}
    if parsed.status in {"DEPRECATED", "DISALLOWED"}:
        # The review's vocabulary has no "classically broken" state because it is
        # not a quantum question at all. Saying so on the same row keeps a reader
        # from reading CLASSICAL_ONLY as "acceptable".
        return {"status": "CLASSICAL_ONLY", "basis": "REGISTRY_CLASSICALLY_BROKEN",
                "classically_broken": True,
                "note": f"registry status {parsed.status}: purge regardless of quantum"}
    return {"status": "CLASSICAL_ONLY", "basis": "REGISTRY_NO_QUANTUM_IMPACT",
            "note": "no known quantum break of this primitive class, and it is not PQC"}


#: Lowest band a status may produce. The registry's quantum impact and the risk
#: engine must not disagree downwards: if the algorithm is Shor-vulnerable by the
#: registry, a key-size heuristic in the scorer cannot make it "low".
_RISK_FLOOR = {"QUANTUM_SENSITIVE": "HIGH", "TRANSITIONAL": "MEDIUM"}


def quantum_risk(algorithm: str | None, key_size: int | None = None,
                 purpose: str | None = None, status: str | None = None) -> dict[str, Any]:
    """Risk band from the PQC engine, never from the CBOM."""
    from quantum.risk import classify

    info = classify(algorithm, key_size=key_size, purpose=purpose)
    threat = str(info.get("threat_type") or "UNKNOWN")
    band = {
        "CLASSICALLY_BROKEN": "CRITICAL",
        "SHOR_VULNERABLE": "HIGH",
        "GROVER_WEAKENED": "MEDIUM",
        "GROVER_MINIMAL": "LOW",
        "PQC_RESISTANT": "NONE",
        "UNKNOWN": "UNKNOWN",
    }.get(threat, "UNKNOWN")
    floor = _RISK_FLOOR.get(str(status or ""))
    basis = f"quantum.risk.classify:{threat}"
    if floor and band in _RISK_ORDER and _RISK_ORDER.index(band) < _RISK_ORDER.index(floor):
        band = floor
        basis += f"; floored to {floor} by the registry classification"
    return {"risk": band, "threat_type": threat,
            "harvest_now_decrypt_later": info.get("harvest_now_decrypt_later_risk") or "UNKNOWN",
            "estimated_break_year": info.get("estimated_break_year"),
            "recommended_replacement": info.get("recommended_replacement"),
            "hybrid_recommended": bool(info.get("hybrid_mode_recommended")),
            "basis": basis}


def migration_priority(*, risk: str, status: str, usage: str | None,
                       purpose: str | None) -> dict[str, Any]:
    """Priority from risk, escalated (never lowered) by observed usage.

    Escalation rules are deliberately few and stated:

    * a confidentiality purpose on a Shor-vulnerable algorithm is ``IMMEDIATE`` —
      that is harvest-now-decrypt-later, and waiting does not help;
    * runtime or network evidence escalates one band, because a deployed
      invocation is not the same finding as an unused capability.
    """
    if status in {"QUANTUM_RESISTANT", "HYBRID"} or risk == "NONE":
        return {"priority": "NONE", "escalated_by": [], "basis": "NO_MIGRATION_NEEDED"}
    if status == "CLASSICAL_ONLY" and risk in {"LOW", "NONE"}:
        return {"priority": "NONE", "escalated_by": [],
                "basis": "CLASSICAL_PRIMITIVE_WITH_ACCEPTABLE_MARGIN"}
    if risk == "UNKNOWN":
        return {"priority": "UNKNOWN", "escalated_by": [], "basis": "RISK_UNKNOWN"}
    priority = _PRIORITY_FOR_RISK.get(risk, "UNKNOWN")
    escalations: list[str] = []
    purpose_n = _norm(purpose)
    if status == "QUANTUM_SENSITIVE" and purpose_n in _CONFIDENTIALITY_PURPOSES:
        if priority != "IMMEDIATE":
            priority = "IMMEDIATE"
            escalations.append("HNDL_CONFIDENTIALITY_PURPOSE")
    usage_n = _norm(usage)
    if usage_n in _OBSERVED_USAGE and priority != "IMMEDIATE":
        ladder = ["NONE", "LOW", "MEDIUM", "HIGH", "IMMEDIATE"]
        priority = ladder[min(ladder.index(priority) + 1, len(ladder) - 1)]
        escalations.append(f"OBSERVED_USAGE:{usage_n}")
    return {"priority": priority, "escalated_by": escalations,
            "basis": "RISK" + ("+" + "+".join(escalations) if escalations else "")}


def handoff(assets: Iterable[Mapping[str, Any]], *,
            as_of: str | None = None) -> dict[str, Any]:
    """Inventoried assets -> one migration handoff row each, plus refusals.

    ``assets`` are the platform's own shape: ``algorithm``, ``key_size``,
    ``purpose``, ``usage`` (a promotion level such as ``RUNTIME`` or a usage
    state) and ``evidence_ids``. Anything without an algorithm is refused: a
    migration item that cannot name its algorithm is not actionable.
    """
    rows: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for asset in assets:
        if not isinstance(asset, Mapping):
            refused.append({"asset": asset, "reason": "an asset must be an object"})
            continue
        algorithm = str(asset.get("algorithm") or "").strip()
        if not algorithm:
            refused.append({"asset": dict(asset),
                            "reason": "the asset names no algorithm, so it cannot be handed off"})
            continue
        key_size = asset.get("key_size")
        try:
            key_size = int(key_size) if key_size is not None else None
        except (TypeError, ValueError):
            key_size = None
        purpose = asset.get("purpose")
        status = quantum_status(algorithm, key_size)
        risk = quantum_risk(algorithm, key_size=key_size, purpose=purpose,
                            status=status["status"])
        usage = str(asset.get("usage") or "").strip().upper() or None
        escalation = migration_priority(risk=risk["risk"], status=status["status"],
                                        usage=usage, purpose=purpose)
        row = {
            "algorithm": algorithm,
            "algorithm_class": algorithm_class(algorithm),
            "key_size": key_size,
            "purpose": str(purpose).upper() if purpose else None,
            "quantum_status": status["status"],
            "status_basis": status["basis"],
            "quantum_risk": risk["risk"],
            "risk_basis": risk["basis"],
            "migration_priority": escalation["priority"],
            "priority_basis": escalation["basis"],
            "priority_escalated_by": escalation["escalated_by"],
            "migration_status": str(asset.get("migration_status") or "NOT_STARTED").upper(),
            "usage": usage,
            "component": asset.get("component") or asset.get("name"),
            "evidence_ids": sorted({str(item) for item in (asset.get("evidence_ids") or [])
                                    if item}),
            "requires_review": bool(status.get("requires_review")),
            "classically_broken": bool(status.get("classically_broken")),
        }
        row["recommended_replacement"] = _replacement(algorithm, purpose, status, risk)
        row["hybrid_recommended"] = bool(risk.get("hybrid_recommended")) if (
            row["recommended_replacement"]) else False
        row["statement"] = _statement(row)
        rows.append(row)

    # Most urgent first; ``UNKNOWN`` sinks below ``NONE`` so an unassessed asset is
    # never presented as a solved one.
    rows.sort(key=lambda row: (_descending(row["migration_priority"]), row["algorithm"],
                               row["key_size"] or 0))
    return {
        "schema": SCHEMA,
        "as_of": as_of or datetime.now(timezone.utc).date().isoformat(),
        "rows": rows,
        "refused": refused,
        "summary": _summary(rows),
        "statement": _handoff_statement(rows, refused),
    }


#: Family prefixes whose "migration" is a size bump rather than a new algorithm.
_GROWER_TARGETS: tuple[tuple[str, str], ...] = (
    ("AES_128", "AES-256"),
    ("SHA_256", "SHA-384"),
    ("SHA256", "SHA-384"),
    ("SHA_1", "SHA-256"),
    ("SHA1", "SHA-256"),
    ("MD5", "SHA-256"),
)


def _replacement(algorithm: str, purpose: str | None, status: Mapping[str, Any],
                 risk: Mapping[str, Any]) -> str | None:
    """What to migrate to, or ``None`` when the platform has no basis to say.

    The engine's own answer wins; a size bump is offered only for the
    Grover-impacted primitives where the algorithm family is unchanged.
    """
    from quantum.risk import recommended_replacement

    name = _norm(algorithm)
    if status.get("classically_broken"):
        # A hash must not be "replaced" by a block cipher: prefer the same family's
        # larger size when the table has one, then fall back to the engine.
        for prefix, target in _GROWER_TARGETS:
            if name.startswith(prefix):
                return target
        return str(risk.get("recommended_replacement") or "") or None
    if status["status"] in {"QUANTUM_RESISTANT", "HYBRID",
                            "CLASSICAL_ONLY", "NOT_ASSESSED", "UNKNOWN"}:
        return None
    engine = risk.get("recommended_replacement")
    if engine:
        return str(engine)
    if status["status"] == "TRANSITIONAL":
        for prefix, target in _GROWER_TARGETS:
            if name.startswith(prefix):
                return target
        return None
    return recommended_replacement(algorithm, purpose=purpose).get("algorithm")


def _descending(priority: str) -> int:
    order = ["IMMEDIATE", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
    return order.index(priority) if priority in order else len(order)


def _statement(row: Mapping[str, Any]) -> str:
    parts = [f"{row['algorithm']}"
             + (f" ({row['key_size']})" if row.get("key_size") else "")
             + f": {row['quantum_status']}, risk {row['quantum_risk']}, "
             + f"{row['migration_priority']} priority, {row['migration_status']}"]
    if row.get("priority_escalated_by"):
        parts.append("escalated by " + ", ".join(row["priority_escalated_by"]))
    if row.get("requires_review"):
        parts.append("algorithm not recognised — human review required")
    if row.get("classically_broken"):
        parts.append("classically broken; a quantum migration would not fix it")
    return "; ".join(parts)


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    priorities = Counter(row["migration_priority"] for row in rows)
    statuses = Counter(row["quantum_status"] for row in rows)
    return {
        "assets": len(rows),
        "by_status": dict(sorted(statuses.items())),
        "by_priority": {name: priorities[name]
                        for name in reversed(MIGRATION_PRIORITIES) if priorities[name]},
        "requiring_migration": sum(1 for row in rows
                                   if row["migration_priority"] not in {"NONE", "UNKNOWN"}),
        "requires_review": sum(1 for row in rows if row["requires_review"]),
        "verified_usage": sum(1 for row in rows if (_norm(row["usage"]) in _OBSERVED_USAGE)),
    }


def _handoff_statement(rows: list[dict[str, Any]], refused: list[dict[str, Any]]) -> str:
    summary = _summary(rows)
    urgent = {name: count for name, count in summary["by_priority"].items()
              if name not in {"NONE", "UNKNOWN"}}
    return (
        f"{summary['assets']} asset(s) handed off; {summary['requiring_migration']} need "
        f"migration ({', '.join(f'{k}={v}' for k, v in urgent.items()) or 'none'})"
        + (f"; {summary['requires_review']} unrecognised algorithm(s) need review"
           if summary["requires_review"] else "")
        + (f"; {len(refused)} asset(s) refused" if refused else "")
    )


def handoff_from_cbom(document: Mapping[str, Any], *,
                      as_of: str | None = None) -> dict[str, Any]:
    """A CBOM document -> the same handoff.

    Usage comes from the ``cryptoscan:usage`` / ``cryptoscan:promotion_level``
    properties the platform writes; a document with no such property is treated as
    *not* observed, because a plain CycloneDX CBOM is an inventory and says
    nothing about deployment.
    """
    assets: list[dict[str, Any]] = []
    for component in (document or {}).get("components") or []:
        if not isinstance(component, Mapping):
            continue
        crypto = component.get("cryptoProperties") or {}
        algo_props = crypto.get("algorithmProperties") or {}
        props = {str(row.get("name")): row.get("value")
                 for row in component.get("properties") or [] if isinstance(row, Mapping)}
        evidence = component.get("evidence") or {}
        evidence_ids = [props.get("cryptoscan:evidence_id"),
                        (evidence or {}).get("evidence_id")]
        assets.append({
            "algorithm": algo_props.get("algorithm") or component.get("name"),
            "key_size": algo_props.get("parameterSetIdentifier") or props.get(
                "cryptoscan:key_size"),
            "purpose": props.get("cryptoscan:purpose") or algo_props.get("primitive"),
            "usage": props.get("cryptoscan:usage") or props.get("cryptoscan:promotion_level"),
            "component": component.get("bom-ref") or component.get("name"),
            "evidence_ids": [item for item in evidence_ids if item],
        })
    body = handoff(assets, as_of=as_of)
    body["source"] = {"components": len((document or {}).get("components") or []),
                      "basis": "DOCUMENT_INVENTORY_AND_PLATFORM_PROPERTIES"}
    return body


# --------------------------------------------------------------------------- #
# CBOM-side projection: the status may live in the document, the decision may not


def component_properties(algorithm: str | None, key_size: int | None = None) -> list[dict[str, str]]:
    """Namespaced properties to write onto a component instead of a boolean.

    CycloneDX 1.5/1.6 ``cryptoProperties`` has no ``quantumVulnerable``: strict
    consumers reject it (the 1.6 schema does, which is why the platform's 1.6
    path never wrote it). The status therefore travels as a ``cryptoscan:``
    property, with its basis, so a reader can tell a registry classification from
    an unassessed asset.
    """
    status = quantum_status(algorithm, key_size)
    properties = [
        {"name": "cryptoscan:quantum_status", "value": status["status"]},
        {"name": "cryptoscan:quantum_status_basis", "value": status["basis"]},
        {"name": "cryptoscan:algorithm_class", "value": algorithm_class(algorithm)},
    ]
    if status.get("requires_review"):
        properties.append({"name": "cryptoscan:requires_review", "value": "true"})
    return properties


#: The only statuses a boolean can carry without losing the distinction the review
#: asked for. ``TRANSITIONAL`` and ``UNKNOWN`` map to ``None`` on purpose: "Grover
#: weakens this" and "we do not know" are not the same answer as "safe".
_VULNERABLE_STATUSES: dict[str, bool] = {
    "QUANTUM_SENSITIVE": True,
    "CLASSICAL_ONLY": False,
    "QUANTUM_RESISTANT": False,
    "HYBRID": False,
}


def vulnerable_from_status(status: str | None) -> bool | None:
    """Status -> boolean where that is defensible, ``None`` where it is not."""
    return _VULNERABLE_STATUSES.get(str(status or ""))


def vulnerable_from_component(component: Mapping[str, Any]) -> bool | None:
    return vulnerable_from_status(status_from_component(component))


def status_from_component(component: Mapping[str, Any]) -> str | None:
    """Read the status back, tolerating documents written before this change.

    Old documents carry ``cryptoProperties.quantumVulnerable`` (or nothing at
    all). A legacy ``true`` maps to ``QUANTUM_SENSITIVE`` and ``false`` to
    ``CLASSICAL_ONLY`` — the most the boolean could ever have meant — and the
    caller is told the basis was legacy.
    """
    crypto = (component or {}).get("cryptoProperties") or {}
    props = {str(row.get("name")): row.get("value")
             for row in (component or {}).get("properties") or [] if isinstance(row, Mapping)}
    status = props.get("cryptoscan:quantum_status")
    if status:
        return str(status)
    legacy = crypto.get("quantumVulnerable")
    if legacy is True:
        return "QUANTUM_SENSITIVE"
    if legacy is False:
        return "CLASSICAL_ONLY"
    return None
