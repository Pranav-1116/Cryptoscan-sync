"""Key-inventory ↔ source reconciliation (pure functions; used by the API, the worker drift stage and the CLI script).

Inputs are plain dicts as stored in ``evidence_records.finding_data`` and ``Scan.statistics.cascade.key_references``.
"""

from __future__ import annotations


def _label_candidates(label: str) -> set[str]:
    low = label.lower()
    return {c for c in (low, low.rsplit("/", 1)[-1], low.replace(".", "_"), low.replace("_", "."), low.rsplit(".", 1)[0]) if c}


def reconcile_key_inventory(inventory_findings: list[dict], key_references: list[tuple[str, dict]]) -> dict:
    """Join key-inventory records (HSM/KMS/keystore/cert exports) with key identifiers referenced from source.

    * ``consumers`` — inventory keys whose label/alias/file name is referenced by scanned source;
    * ``orphans`` — inventory keys referenced by no scanned repo (retire candidates, or a system not yet scanned);
    * ``not_in_inventory`` — aliases / keystore files the code uses that no inventory export lists.
    Pure function so the same logic serves the API and ``scripts/ingest_key_inventory.py``.
    """
    refs: dict[str, list[dict]] = {}
    for scan_id, ref in key_references:
        item = {**ref, "scan_id": scan_id}
        ident = str(ref.get("identifier") or "").lower()
        for c in {ident, ident.rsplit(".", 1)[0]}:
            if c:
                refs.setdefault(c, []).append(item)
    consumers, orphans, seen = [], [], set()
    inv_labels: set[str] = set()
    for f in inventory_findings:
        inv = f.get("inventory") or {}
        label = str(inv.get("key_label") or "")
        if not label:
            continue
        crypto = f.get("crypto") or {}
        key = (label.lower(), (f.get("metadata") or {}).get("library"))
        if key in seen:
            continue
        seen.add(key)
        inv_labels |= _label_candidates(label)
        hits: dict[tuple, dict] = {}
        for c in _label_candidates(label):
            for r in refs.get(c, []):
                hits[(r["scan_id"], r["kind"], r["identifier"])] = r
        row = {"system": key[1], "label": label, "algorithm": crypto.get("algorithm"), "key_size": crypto.get("key_size"),
               "key_store": inv.get("key_store"), "state": inv.get("state"), "not_after": inv.get("not_after"),
               "file": (f.get("source") or {}).get("file_path")}
        if hits:
            consumers.append({**row, "references": sorted(hits.values(), key=lambda r: (r["scan_id"], r["kind"], r["identifier"]))})
        else:
            orphans.append(row)
    not_in_inventory = sorted(
        ({**ref, "scan_id": scan_id} for scan_id, ref in key_references
         if ref.get("kind") in ("key_alias", "key_file")
         and str(ref.get("identifier") or "").lower() not in inv_labels
         and str(ref.get("identifier") or "").lower().rsplit(".", 1)[0] not in inv_labels),
        key=lambda r: (-int(r.get("files") or 0), r["kind"], r["identifier"]),
    )
    return {
        "summary": {"inventory_keys": len(seen), "consumers": len(consumers), "orphans": len(orphans), "not_in_inventory": len(not_in_inventory),
                    "source_key_references": len(key_references)},
        "consumers": consumers, "orphans": orphans, "not_in_inventory": not_in_inventory,
    }


