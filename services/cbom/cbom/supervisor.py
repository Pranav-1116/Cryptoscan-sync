"""Supervisory reporting — migration roadmap + supervisor pack (pure).

Serves the supervisor/regulator read-only portal: what a financial
supervisor may see, assembled from the same engines the bank uses
internally — nothing re-derived, nothing embellished.

Two real primitives are reused (never re-implemented):

* :func:`cbom.banking.quantum_vulnerability` — the NIST IR 8547
  classification: legacy/broken → purge now; 112-bit public-key →
  deprecated after 2030; >=128-bit public-key → disallowed after 2035.
  The bucket deadlines below are those constants, not new math.
* :func:`cbom.group.entity_rollup` — per-legal-entity family counts
  (``top_families`` as ``["RSA-2048", 12]`` style pairs).

``group_roadmap`` turns entity rollups into prioritized, bucketed
migration rows; ``supervisor_pack`` assembles the read-only pack with an
explicit ``declared_limits`` section — the honest boundary travels with
the artifact.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Iterable, Mapping

from cbom.banking import quantum_vulnerability

BUCKET_IMMEDIATE = "immediate"
BUCKET_BY_2030 = "by-2030"
BUCKET_BY_2035 = "by-2035"

_BUCKET_ORDER = (BUCKET_IMMEDIATE, BUCKET_BY_2030, BUCKET_BY_2035)

_ACTION_BY_BUCKET = {
    BUCKET_IMMEDIATE: "Purge or replace now — broken/impaired legacy, no transition window",
    BUCKET_BY_2030: "Migrate to ML-DSA/ML-KEM before the 2030 deprecation horizon",
    BUCKET_BY_2035: "PQC migration planned before 2035 — disallowed after",
}

SUPERVISOR_LIMITS: tuple[str, ...] = (
    "Extract-based inventory: absence of a family from this pack is not "
    "proof of absence — coverage follows the operator-produced extracts.",
    "DORA register bank_to_supply fields are placeholders until the bank "
    "completes them; the pack does not fabricate them.",
    "No key material is included, by design — cryptographic metadata only.",
)

_ROADMAP_BASIS = "NIST IR 8547 transition milestones (purge legacy -> 2030 -> 2035)"


def _split_family(family: str) -> tuple[str, int | None]:
    """``"RSA-2048"`` -> ``("RSA", 2048)``; ``"AES"`` -> ``("AES", None)``."""
    text = str(family).strip()
    head, _, tail = text.rpartition("-")
    if head and tail.isdigit():
        return head, int(tail)
    return text, None


def _bucket_for(verdict: Mapping[str, Any]) -> str | None:
    """Map a quantum_vulnerability verdict to a roadmap bucket (None = none)."""
    if verdict.get("legacy"):
        return BUCKET_IMMEDIATE
    if verdict.get("quantum_vulnerable"):
        return BUCKET_BY_2030 if verdict.get("deadline") == 2030 else BUCKET_BY_2035
    return None


def _deadline_iso(bucket: str, as_of: date) -> str:
    if bucket == BUCKET_IMMEDIATE:
        return as_of.isoformat()  # overdue: due at the reporting date itself
    if bucket == BUCKET_BY_2030:
        return "2030-12-31"
    return "2035-12-31"


def group_roadmap(
    entity_rollups: Iterable[Mapping[str, Any]] | None,
    *,
    as_of: date | None = None,
) -> dict[str, Any]:
    """Prioritized migration roadmap across entities.

    Rows exist only for families the classification flags (legacy or
    Shor-vulnerable public-key); posture-ok families are counted, not
    rowed. Sorted worst-first: bucket, then instance count, then family.
    """
    this_date = as_of or datetime.now(timezone.utc).date()
    rows: list[dict[str, Any]] = []

    for rollup in entity_rollups or []:
        entity = rollup.get("entity") or {}
        for family, count in rollup.get("top_families") or []:
            algorithm, key_size = _split_family(str(family))
            bucket = _bucket_for(quantum_vulnerability(algorithm, key_size))
            if bucket is None:
                continue
            rows.append({
                "entity_code": entity.get("code", ""),
                "entity_name": entity.get("name", ""),
                "jurisdiction": entity.get("jurisdiction", ""),
                "family": str(family),
                "instances": int(count or 0),
                "bucket": bucket,
                "deadline": _deadline_iso(bucket, this_date),
                "action": _ACTION_BY_BUCKET[bucket],
            })

    order = {bucket: i for i, bucket in enumerate(_BUCKET_ORDER)}
    rows.sort(key=lambda r: (order[r["bucket"]], -r["instances"], r["family"]))

    summary = {
        "rows": len(rows),
        "instances_by_bucket": {
            bucket: sum(r["instances"] for r in rows if r["bucket"] == bucket)
            for bucket in _BUCKET_ORDER
        },
        "families_by_bucket": {
            bucket: len({r["family"] for r in rows if r["bucket"] == bucket})
            for bucket in _BUCKET_ORDER
        },
        "entities_affected": sorted({r["entity_code"] for r in rows if r["entity_code"]}),
    }
    return {
        "basis": _ROADMAP_BASIS,
        "generated_for": this_date.isoformat(),
        "rows": rows,
        "summary": summary,
    }


def supervisor_pack(
    *,
    group: Mapping[str, Any] | None,
    entity_rollups: Iterable[Mapping[str, Any]] | None,
    dora_summary: Mapping[str, Any] | None,
    roadmap: Mapping[str, Any] | None,
    pack_version: str = "1.0.0",
    as_of: date | None = None,
) -> dict[str, Any]:
    """Assemble the read-only supervisory pack.

    Sections are passed in from real engines and passed through as-is;
    missing sections stay empty rather than being invented, and the
    pack carries its own ``declared_limits`` so the honest boundary is
    part of the artifact a supervisor receives.
    """
    this_date = as_of or datetime.now(timezone.utc).date()
    entities = []
    for rollup in entity_rollups or []:
        entity = rollup.get("entity") or {}
        entities.append({
            "code": entity.get("code", ""),
            "name": entity.get("name", ""),
            "jurisdiction": entity.get("jurisdiction", ""),
            "lei": entity.get("lei", ""),
        })
    return {
        "pack": {
            "kind": "supervisory-pack",
            "version": pack_version,
            "generated_for": this_date.isoformat(),
        },
        "group_totals": dict((group or {}).get("totals") or {}),
        "by_jurisdiction": dict((group or {}).get("by_jurisdiction") or {}),
        "entities": entities,
        "dora_register_summary": dict(dora_summary or {}),
        "migration_roadmap_summary": dict((roadmap or {}).get("summary") or {}),
        "declared_limits": list(SUPERVISOR_LIMITS),
    }
