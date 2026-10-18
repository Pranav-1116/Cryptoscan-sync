"""Edge provenance vocabulary (§4.5 — round 43).

A graph edge must say WHERE it came from, or say honestly that it does not
know. The classes follow the platform gap contract ("distinguish observed
traffic, declared topology, scanner-derived dependency and inferred
association"):

* ``OBSERVED``         — measured at runtime (traffic, TLS probe, process event).
* ``DECLARED``         — a human/operator declared it (dependency table, owner
                         mapping, declared network topology). A declaration is
                         not an observation.
* ``SCANNER_DERIVED``  — derived from scan evidence (asset→system USES from the
                         evidence-chained inventory, cert/container inventory).
* ``INFERRED``         — correlation or heuristic produced it; useful, but it
                         must never be presented as a measured call.
* ``UNATTRIBUTED``     — origin unknown. This is the default when a caller
                         adds an edge without saying where it came from, so an
                         unknown edge can never silently become a "known
                         dependency".
"""

from __future__ import annotations

from typing import Any, Iterable
from shared_models.relationship_lifecycle import lifecycle_payload

PROVENANCE_OBSERVED = "OBSERVED"
PROVENANCE_DECLARED = "DECLARED"
PROVENANCE_SCANNER_DERIVED = "SCANNER_DERIVED"
PROVENANCE_INFERRED = "INFERRED"
PROVENANCE_UNATTRIBUTED = "UNATTRIBUTED"

ALL_PROVENANCE = (
    PROVENANCE_OBSERVED,
    PROVENANCE_DECLARED,
    PROVENANCE_SCANNER_DERIVED,
    PROVENANCE_INFERRED,
    PROVENANCE_UNATTRIBUTED,
)


def normalize_provenance(value: Any) -> str:
    """Coerce an arbitrary provenance value to the vocabulary.

    Unknown values are NOT guessed into a stronger class — they collapse to
    ``UNATTRIBUTED`` so the honest label survives bad input.
    """
    text = str(value or "").strip().upper().replace("-", "_").replace(" ", "_")
    if text in ALL_PROVENANCE:
        return text
    return PROVENANCE_UNATTRIBUTED


def provenance_counts(edges: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Count edges per provenance class — every class present, zeros honest."""
    counts = {cls: 0 for cls in ALL_PROVENANCE}
    for edge in edges:
        counts[normalize_provenance((edge or {}).get("provenance"))] += 1
    return counts


def edge_meta_payload(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Serialize stored edge meta for vis export: provenance always, extras
    only when they exist (never fabricated)."""
    if not meta:
        return {"provenance": PROVENANCE_UNATTRIBUTED}
    out: dict[str, Any] = {"provenance": normalize_provenance(meta.get("provenance"))}
    for key in ("source", "observed_at", "confidence", "evidence_ref"):
        value = meta.get(key)
        if value is not None:
            out[key] = value
    out.update(lifecycle_payload(meta))
    return out
