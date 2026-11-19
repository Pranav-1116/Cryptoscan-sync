"""Post-quantum deployment stages.

"ML-KEM found" is not "PQC ready". A post-quantum algorithm moves through
distinct, separately evidenced stages, and a CBOM must say which ones the
evidence reaches:

    SOURCE → CONFIG → BUILD → LOADED → NEGOTIATED → APPROVED_FOR_PRODUCTION

* SOURCE      — referenced in source code (static detection);
* CONFIG      — enabled in a configuration file that a deployment reads;
* BUILD       — present in a built artefact (binary, image, installed package);
* LOADED      — loaded by a running process (library/provider observed in memory);
* NEGOTIATED  — actually negotiated on the wire (handshake shows the PQC/hybrid group);
* APPROVED_FOR_PRODUCTION — a recorded human/change-board approval for production use.

A later stage does not imply the earlier ones were recorded, and nothing
implies a stage the evidence does not show. ``pqc_ready`` is true only when the
algorithm was NEGOTIATED *and* APPROVED_FOR_PRODUCTION.
"""
from __future__ import annotations

from typing import Any, Iterable

STAGES: tuple[str, ...] = ("SOURCE", "CONFIG", "BUILD", "LOADED", "NEGOTIATED", "APPROVED_FOR_PRODUCTION")

#: CBOM deployment_stage (crypto_normalization.deployment_stage) → PQC stage.
#: Host presence is an installed artefact, not a loaded library.
_FROM_DEPLOYMENT = {
    "DETECTED_IN_SOURCE": "SOURCE",
    "CONFIGURED": "CONFIG",
    "PRESENT_IN_BINARY": "BUILD",
    "PRESENT_ON_HOST": "BUILD",
    "LOADED_IN_PROCESS": "LOADED",
}

_PQC_FAMILIES = {"ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC", "XMSS", "LMS", "HSS"}


def is_pqc(n: Any) -> bool:
    family = str(getattr(n, "family", "") or "").upper()
    return family in _PQC_FAMILIES or str(getattr(n, "primitive", "")) in {"kem", "combiner"} and \
        family not in {"RSA", "ECDH", "DH", "DHE"}


def stage_ladder(deployment_stages: Iterable[str], *, negotiated: bool = False,
                 approval_ref: str | None = None) -> dict[str, Any]:
    """The ladder for one PQC component.

    ``deployment_stages`` are the CBOM deployment stages its evidence supports
    (one per occurrence). ``negotiated`` is true only when a handshake
    observation names the PQC/hybrid group. ``approval_ref`` is a recorded
    production approval — the platform stores none today, so callers pass None.
    """
    reached: set[str] = set()
    for stage in deployment_stages:
        mapped = _FROM_DEPLOYMENT.get(str(stage or ""))
        if mapped:
            reached.add(mapped)
        elif stage == "RUNTIME_OBSERVED" and negotiated:
            reached.add("NEGOTIATED")
    if negotiated:
        reached.add("NEGOTIATED")
    if approval_ref:
        reached.add("APPROVED_FOR_PRODUCTION")
    ladder = []
    for stage in STAGES:
        entry = {"stage": stage, "status": "ESTABLISHED" if stage in reached else "NOT_ESTABLISHED"}
        if stage == "APPROVED_FOR_PRODUCTION" and approval_ref:
            entry["evidence"] = approval_ref
        ladder.append(entry)
    highest = next((s for s in reversed(STAGES) if s in reached), None)
    ready = "NEGOTIATED" in reached and "APPROVED_FOR_PRODUCTION" in reached
    missing = [s for s in STAGES if s not in reached and (highest is None or STAGES.index(s) > STAGES.index(highest))]
    if ready:
        reason = "negotiated on the wire and approved for production"
    elif highest is None:
        reason = "no deployment stage is established by the evidence"
    else:
        reason = (f"evidence reaches {highest} only; not shown " + ", ".join(m.lower().replace("_", " ") for m in missing)
                  + " — a PQC algorithm at this stage is not PQC deployment")
    return {"highest_stage": highest or "NONE", "ladder": ladder, "pqc_ready": ready, "reason": reason,
            "approval_recorded": bool(approval_ref)}


def summary(ladders: Iterable[dict[str, Any]]) -> dict[str, Any]:
    by_stage: dict[str, int] = {}
    ready = 0
    total = 0
    for item in ladders:
        total += 1
        by_stage[item["highest_stage"]] = by_stage.get(item["highest_stage"], 0) + 1
        ready += bool(item["pqc_ready"])
    return {"pqc_components": total, "by_highest_stage": dict(sorted(by_stage.items())), "pqc_ready": ready,
            "stages": list(STAGES),
            "basis": "a PQC algorithm is ready only when negotiated and approved for production; "
                     "source, config or build presence is not deployment"}
