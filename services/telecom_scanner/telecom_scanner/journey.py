"""PQC adoption journey (pure) — per-NF readiness history over scan passes.

Detection (realtime.evaluate_changes) says "something changed NOW"; the
journey answers the question steering committees and regulators actually
ask: *where is PQC adoption, and where is it going?* Every pass coalesces
into per-NF "eras" — consecutive passes with the same readiness extend the
current era (a ``passes`` counter, no event spam); a readiness flip opens a
new era (the transition log). Storage is a small JSON file next to the
telecom snapshot, written by the same writers (API scan/ingest, monitor
mirror) and read mtime-aware like the snapshot.

Honesty rules: an NF is tracked only once actually probed (no invented
baselines); adoption is over tracked NFs only; an empty journey reports
``nf_tracked: 0`` with ``adoption_pct: None`` — never a fabricated percent.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


def _ready(verdict: Mapping[str, Any]) -> bool:
    """Hybrid-PQC readiness of one verdict (same rule as the realtime layer)."""
    if verdict.get("pqc_ready") is None:
        return bool(verdict.get("pqc_kex"))
    return bool(verdict.get("pqc_ready"))


def update_journey(history: Mapping[str, Any] | None,
                   generated_at: str,
                   rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Fold one scan pass into the journey. ``history`` may be None (first
    observation). Eras per nf_id: {from, until, pqc_ready, passes}."""
    eras: dict[str, list[dict[str, Any]]] = {
        nf: list(e) for nf, e in ((history or {}).get("eras") or {}).items()
    }
    for row in rows:
        nf_id = str(row.get("nf_id") or "")
        if not nf_id:
            continue
        ready = _ready(row)
        nf_eras = eras.setdefault(nf_id, [])
        if nf_eras and bool(nf_eras[-1].get("pqc_ready")) == ready:
            nf_eras[-1]["until"] = generated_at
            nf_eras[-1]["passes"] = int(nf_eras[-1].get("passes") or 1) + 1
        else:
            nf_eras.append({"from": generated_at, "until": generated_at,
                            "pqc_ready": ready, "passes": 1})
    return {"generated_at": generated_at, "eras": eras}


def pqc_adoption(journey: Mapping[str, Any] | None) -> dict[str, Any]:
    """Adoption summary: current readiness, since-when, transitions, passes."""
    per_nf: dict[str, dict[str, Any]] = {}
    transitions = 0
    for nf_id, eras in ((journey or {}).get("eras") or {}).items():
        if not eras:
            continue
        current = eras[-1]
        flips = len(eras) - 1
        transitions += flips
        per_nf[nf_id] = {
            "pqc_ready": bool(current.get("pqc_ready")),
            "since": current.get("from"),
            "eras": len(eras),
            "flips": flips,
            "passes": sum(int(e.get("passes") or 1) for e in eras),
            "history": [{"from": e.get("from"), "until": e.get("until"),
                         "pqc_ready": bool(e.get("pqc_ready")),
                         "passes": int(e.get("passes") or 1)} for e in eras],
        }
    tracked = len(per_nf)
    ready = sum(1 for v in per_nf.values() if v["pqc_ready"])
    return {
        "nf_tracked": tracked,
        "pqc_ready_now": ready,
        "adoption_pct": round(100.0 * ready / tracked, 1) if tracked else None,
        "transitions": transitions,
        "per_nf": per_nf,
    }
