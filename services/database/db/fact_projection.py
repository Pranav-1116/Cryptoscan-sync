"""Cryptographic fact identity — the one truth for what a fact IS.

Advanced/51 P0#1 (write-side step, round 35): facts become rows
(``cryptographic_facts``), so the identity function must live in the
database kernel where the fact repository uses it — and the API's live
projection imports the same function, so the read contract and the
stored rows can never disagree about identity.

Identity: what + why + where + parameters. Line number is deliberately
NOT part of the identity — the same algorithm/purpose/parameters in the
same file is one fact observed at several lines (lines stay on the
evidence rows).
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from shared_models.asset_identity import crypto_asset_key_from_row


def fact_key(row: Mapping[str, Any]) -> tuple:
    """Fact identity: (algorithm, purpose, file_path, key_size, mode)."""
    return (
        str(row.get("algorithm") or "UNKNOWN"),
        str(row.get("purpose") or ""),
        str(row.get("file_path") or ""),
        row.get("key_size"),
        str(row.get("mode") or ""),
    )


def identity_values(key: tuple) -> dict[str, Any]:
    """Spread a fact_key into column-name -> value for row construction.

    Values are stored VERBATIM (empty string for absent purpose/file/mode,
    never None): SQL NULLs are distinct under unique constraints in SQLite,
    so normalising to "" keeps fact identity exact-match everywhere.
    """
    algorithm, purpose, file_path, key_size, mode = key
    return {
        "algorithm": algorithm,
        "purpose": purpose,
        "file_path": file_path,
        "key_size": key_size,
        "mode": mode,
    }


def scanner_id(row: Mapping[str, Any]) -> Optional[str]:
    """Resolve the observing scanner from an evidence row's finding data."""
    finding = row.get("finding_data")
    if isinstance(finding, Mapping):
        value = finding.get("scanner_id") or (finding.get("metadata") or {}).get("scanner_id")
        return str(value) if value else None
    return None


def asset_fact_key(asset: Mapping[str, Any]) -> tuple:
    """The fact identity of one crypto_assets row (same tuple space as
    ``fact_key`` — "" normalisation, never None).

    crypto_assets is the fused write path (report 51); the fact store is
    the evidence-derived projection. Mapping an asset onto the fact
    identity space is what makes the two comparable at all — the
    prerequisite for any future single-writer cutover.
    """
    return (
        str(asset.get("algorithm") or "").strip(),
        str(asset.get("purpose") or ""),
        str(asset.get("file_path") or ""),
        asset.get("key_size") if asset.get("key_size") is not None else "",
        str(asset.get("mode") or ""),
    )


def reconcile_assets_with_facts(
    assets: Iterable[Mapping[str, Any]],
    facts: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Measure drift between the fused asset write path and the fact store.

    Pure. Both sides are indexed by the coarse drift key (algorithm,
    file_path); the parameter fields (key size / purpose / mode) are then
    compared across sides. Identities on only one side are reported
    separately. It does NOT judge which side is right — evidence is the
    truth per the 51 rearchitecture; this makes the divergence visible
    and countable, which is what the single-writer cutover needs.
    """
    def _drift_key(row: Mapping[str, Any]) -> tuple:
        return (str(row.get("algorithm") or "").strip(),
                str(row.get("file_path") or ""))

    asset_by_key: dict[tuple, list] = {}
    for asset in assets or ():
        asset_by_key.setdefault(_drift_key(asset), []).append(asset)
    fact_by_key: dict[tuple, list] = {}
    for fact in facts or ():
        fact_by_key.setdefault(_drift_key(fact), []).append(fact)

    def _params(rows: list) -> dict[str, set]:
        out: dict[str, set] = {}
        for row in rows:
            for field in ("key_size", "purpose", "mode"):
                value = row.get(field)
                out.setdefault(field, set()).add(
                    "" if value is None else str(value))
        return out

    matched = 0
    disagreements: list[dict[str, Any]] = []
    for key in sorted(set(asset_by_key) & set(fact_by_key), key=str):
        matched += 1
        left, right = _params(asset_by_key[key]), _params(fact_by_key[key])
        fields = {}
        for field in ("key_size", "purpose", "mode"):
            if left[field] != right[field]:
                def _clean(values):
                    return sorted(v if v else None for v in values)

                fields[field] = {"asset": _clean(left[field]),
                                 "fact": _clean(right[field])}
        if fields:
            disagreements.append({
                "algorithm": key[0], "file_path": key[1], "fields": fields})

    def _labels(keys) -> list[str]:
        return sorted(f"{algorithm}@{path}" for algorithm, path in keys)

    assets_only = _labels(set(asset_by_key) - set(fact_by_key))
    facts_only = _labels(set(fact_by_key) - set(asset_by_key))
    # §4.2 spine (round 57): asset rows claiming the same canonical
    # identity — the fork the single-writer cutover must disposition.
    # Visible, not judged: a fork may be legitimate history.
    spine_counts: dict[str, int] = {}
    for asset in assets or ():
        key = crypto_asset_key_from_row(asset)
        if key:
            spine_counts[key] = spine_counts.get(key, 0) + 1
    duplicate_asset_keys = {k: n for k, n in spine_counts.items() if n > 1}
    return {
        "model": "asset-fact/reconciliation-v1",
        "assets_indexed": len(asset_by_key),
        "facts_indexed": len(fact_by_key),
        "identities_matched": matched,
        "duplicate_asset_keys": duplicate_asset_keys,
        "duplicate_asset_key_count": len(duplicate_asset_keys),
        "field_disagreements": disagreements,
        "disagreement_count": len(disagreements),
        "assets_without_facts": assets_only,
        "facts_without_assets": facts_only,
        "in_sync": not disagreements and not assets_only and not facts_only,
        "note": "drift between the fused crypto_assets write path and the "
                "evidence-derived fact store; the 51 single-writer "
                "rearchitecture needs this at zero before cutover",
    }
