"""Telecom migration roadmap (pure) — NF crypto facts → IR 8547 buckets.

The telecom estate joins the SAME migration plan the bank uses: families
are derived from the verdicts' crypto_inventory (leaf key, signature
algorithm, negotiated cipher) using cbom.banking.quantum_vulnerability —
no telecom-specific re-classification — and bucketed by
cbom.supervisor.group_roadmap (legacy → purge now; 112-bit public-key →
by-2030; >=128-bit → by-2035).

Carrier granularity: each carrier is a roadmap "entity" (code, name,
jurisdiction = country), so a multi-country operator group sees its
migration plan per carrier. ``carrier_entity_families`` additionally folds
carrier families into the group legal-entity view so the banking and
telecom estates land in ONE roadmap artifact.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from cbom.banking import quantum_vulnerability

_CIPHER_WEAK_FAMILIES = ("3DES", "DES-CBC", "DES-EDE", "RC4", "RC2")


def _family_verdict(family: str) -> dict[str, Any]:
    """quantum_vulnerability for a ``NAME-bits`` family string."""
    text = str(family).strip()
    head, _, tail = text.rpartition("-")
    if head and tail.isdigit():
        return quantum_vulnerability(head, int(tail))
    return quantum_vulnerability(text)


def _inventory_families(inventory: Mapping[str, Any]) -> list[str]:
    """Families one NF contributes (deduped, already filtered to flagged)."""
    families: list[str] = []

    key = str(inventory.get("cert_key") or "")
    if key:
        families.append(key)

    sig = str(inventory.get("cert_sig") or "")
    if sig and ("SHA1" in sig or "MD5" in sig):
        key_bits = key.rpartition("-")[2] if "-" in key else ""
        families.append(f"{sig}-{key_bits}" if key_bits.isdigit() else sig)

    cipher = str(inventory.get("cipher") or "").upper()
    for token in _CIPHER_WEAK_FAMILIES:
        if token in cipher:
            families.append("3DES-112" if "DES" in token else "RC4")
            break

    out: list[str] = []
    for family in families:
        verdict = _family_verdict(family)
        if verdict.get("quantum_vulnerable") or verdict.get("legacy"):
            if family not in out:
                out.append(family)
    return out


def carrier_families(verdicts: Iterable[Mapping[str, Any]]) -> dict[str, list[tuple[str, int]]]:
    """carrier_code → [(family, instances)] for flagged families only.

    One NF contributes at most one instance per family (its own key/sig/
    cipher). Posture-unknown verdicts (unprobed, unreachable, IPSEC_UNKNOWN)
    contribute nothing — the roadmap never invents inventory.
    """
    counts: dict[str, dict[str, int]] = {}
    for row in verdicts:
        if row.get("status") != "TLS_OK":
            continue
        carrier = str(row.get("carrier_code") or "—")
        for family in _inventory_families(row.get("crypto_inventory") or {}):
            slot = counts.setdefault(carrier, {})
            slot[family] = slot.get(family, 0) + 1
    return {carrier: sorted(slot.items(), key=lambda kv: (-kv[1], kv[0]))
            for carrier, slot in counts.items()}


def carrier_entity_families(
    verdicts: Iterable[Mapping[str, Any]],
    carriers: Mapping[str, Mapping[str, Any]],
) -> dict[str, list[tuple[str, int]]]:
    """legal_entity → [(family, instances)] across that entity's carriers."""
    per_carrier = carrier_families(verdicts)
    merged: dict[str, dict[str, int]] = {}
    for code, families in per_carrier.items():
        entity = str((carriers.get(code) or {}).get("legal_entity") or "").strip().lower()
        if not entity:
            continue
        slot = merged.setdefault(entity, {})
        for family, count in families:
            slot[family] = slot.get(family, 0) + count
    return {entity: sorted(slot.items(), key=lambda kv: (-kv[1], kv[0]))
            for entity, slot in merged.items()}


def telecom_roadmap(
    verdicts: Iterable[Mapping[str, Any]],
    carriers: Mapping[str, Mapping[str, Any]],
    *,
    as_of: Any = None,
) -> dict[str, Any]:
    """Carrier-bucketed migration roadmap (cbom.supervisor.group_roadmap shape).

    Each carrier with flagged families becomes one roadmap entity; carriers
    and families the classification does not flag simply produce no rows.
    """
    from cbom.supervisor import group_roadmap

    per_carrier = carrier_families(verdicts)
    rollups: list[dict[str, Any]] = []
    for code, families in sorted(per_carrier.items()):
        carrier = carriers.get(code) or {}
        rollups.append({
            "entity": {
                "code": code,
                "name": carrier.get("name") or code,
                "jurisdiction": carrier.get("country") or "",
                "lei": carrier.get("lei") or "",
            },
            "top_families": families,
        })
    return group_roadmap(rollups, as_of=as_of)
