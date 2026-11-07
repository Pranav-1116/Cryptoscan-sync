"""Asset aliases and duplicate resolution (gap analysis Phase 2).

Two identity keys can name the same real-world asset: a scanner that saw
``host:web-1`` and one that saw ``ip:10.0.0.5``, a renamed file, a migrated
key. The domain model's answer is ``asset_aliases`` — and the house rules:

- an alias claim is evidence-backed and attributed: a bare "these are the
  same" is refused;
- merging duplicates PRESERVES both original identity keys as aliases — a
  merge records, it never deletes;
- a conflicting alias (one alias claimed by two different canonical assets)
  is reported as a CONFLICT and kept — never silently resolved;
- alias chains resolve deterministically and cycles are refused: identity
  resolution must terminate;
- a key with no alias resolves to itself: no alias is identity, not a gap.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

ALIAS_SCHEMA = "cryptoscan.asset-alias/1"

CONFLICT = "CONFLICT"
RESOLVED = "RESOLVED"
UNALIASED = "UNALIASED"
RESOLUTION_STATES: tuple[str, ...] = (RESOLVED, UNALIASED, CONFLICT)

_MAX_CHAIN = 32


def alias_record(*, alias_key: str, canonical_key: str, actor: str,
                 reason: str, evidence_ref: str,
                 at: str | None = None) -> dict[str, Any]:
    """One attributed, evidence-backed alias claim."""
    alias = str(alias_key or "").strip()
    canonical = str(canonical_key or "").strip()
    if not alias or not canonical:
        raise ValueError("alias_key and canonical_key are mandatory")
    if alias == canonical:
        raise ValueError("an asset is its own identity: self-alias is refused")
    if not str(actor or "").strip():
        raise ValueError("actor is mandatory: an unattributed alias is "
                         "unreviewable")
    if not str(reason or "").strip():
        raise ValueError("reason is mandatory: 'these are the same' without "
                         "a reason is not a decision")
    ref = str(evidence_ref or "").strip()
    if not ref:
        raise ValueError("evidence_ref is mandatory: an alias claim without "
                         "evidence is a guess")
    return {
        "schema": ALIAS_SCHEMA,
        "alias_key": alias,
        "canonical_key": canonical,
        "actor": str(actor),
        "reason": str(reason),
        "evidence_ref": ref,
        "at": at or datetime.now(timezone.utc).isoformat(),
    }


def merge_duplicates(*, keys: Iterable[str], canonical_key: str, actor: str,
                     reason: str, evidence_ref: str,
                     at: str | None = None) -> dict[str, Any]:
    """Resolve duplicate identity keys under one canonical asset.

    Every original key is PRESERVED as an alias of the canonical — a merge
    is a record, not a deletion. The canonical need not be one of the keys.
    """
    originals = [str(k).strip() for k in keys if str(k).strip()]
    if len(originals) < 2:
        raise ValueError("merging needs at least two distinct identity keys")
    if len(set(originals)) != len(originals):
        raise ValueError("duplicate keys in one merge: that is the same key "
                         "listed twice, not a merge")
    canonical = str(canonical_key or "").strip()
    if not canonical:
        raise ValueError("canonical_key is mandatory")
    aliases = [
        alias_record(alias_key=key, canonical_key=canonical, actor=actor,
                     reason=f"duplicate resolution: {reason}".strip(),
                     evidence_ref=evidence_ref, at=at)
        for key in originals if key != canonical
    ]
    return {
        "schema": ALIAS_SCHEMA,
        "kind": "merge",
        "canonical_key": canonical,
        "original_keys": sorted(originals),
        "aliases": aliases,
        "actor": str(actor),
        "reason": str(reason),
        "evidence_ref": str(evidence_ref),
        "at": at or datetime.now(timezone.utc).isoformat(),
        "note": ("every original key is preserved as an alias: a merge "
                 "records identity, it never deletes one"),
    }


def resolve(key: str, aliases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Follow alias claims to the canonical asset. Terminates; cycles refused."""
    current = str(key or "").strip()
    if not current:
        raise ValueError("cannot resolve an empty key")
    claims: dict[str, list[str]] = {}
    for row in aliases:
        claims.setdefault(str(row.get("alias_key") or "").strip(), []).append(
            str(row.get("canonical_key") or "").strip())
    seen = [current]
    for _ in range(_MAX_CHAIN):
        targets = sorted(set(claims.get(current, [])))
        if not targets:
            return {
                "key": str(key),
                "canonical_key": current,
                "state": RESOLVED if current != str(key).strip() else UNALIASED,
                "chain": seen,
            }
        if len(targets) > 1:
            return {
                "key": str(key),
                "canonical_key": None,
                "state": CONFLICT,
                "chain": seen,
                "conflicting_targets": targets,
                "note": ("one alias claimed by several canonical assets: "
                         "kept as a conflict, never silently resolved"),
            }
        nxt = targets[0]
        if nxt in seen:
            raise ValueError(
                f"alias cycle at {nxt!r}: identity resolution must terminate")
        seen.append(nxt)
        current = nxt
    raise ValueError("alias chain too deep: identity resolution must terminate")


def resolve_all(keys: Iterable[str],
                aliases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Deterministic resolution map for a set of keys."""
    rows = [resolve(k, aliases) for k in keys]
    rows.sort(key=lambda r: str(r["key"]))
    conflicted = [r for r in rows if r["state"] == CONFLICT]
    return {
        "schema": ALIAS_SCHEMA,
        "kind": "resolution_map",
        "resolutions": rows,
        "conflicted": [r["key"] for r in conflicted],
        "is_clean_result": not conflicted,
        "note": ("a conflicted alias is kept and named: identity resolution "
                 "never silently picks a winner"),
    }
