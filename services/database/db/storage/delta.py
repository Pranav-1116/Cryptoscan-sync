"""Incremental scan snapshots: record changes, reference what did not change.

Spec 2.1/7: "incremental scanning — collect changes rather than
everything", "delta storage — store differences between scan snapshots",
"reference-based storage — multiple BOMs reference shared evidence",
"snapshot management — preserve important historical states".

A snapshot is a mapping of item key (asset key, evidence id, BOM entry …)
to canonical item bytes. Storing it:

1. puts every item's bytes through the content-addressed store — items
   unchanged since the base snapshot land on their EXISTING content
   objects (reference-based: the bytes exist once, every snapshot that
   carries them references the same hash);
2. computes the difference against the base snapshot's item hashes and
   stores ONLY that difference (added / changed / removed) as a
   compressed delta object;
3. records the delta metadata (counts + the shared unchanged references)
   in ``snapshot_deltas``.

Historical states are preserved by never rewriting a stored delta: a
changed cryptographic configuration links a NEW observation to the
historical state; it never overwrites it. ``materialize_snapshot``
reconstructs any snapshot by walking the chain and reading shared
content — the same bytes, no copies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.snapshot_delta import SnapshotDelta
from db.storage.cas import ContentAddressedStore, sha256_hex


@dataclass(frozen=True)
class SnapshotDiff:
    """What changed between two item maps (key → content hash)."""

    added: dict[str, str] = field(default_factory=dict)     # key → new sha
    changed: dict[str, str] = field(default_factory=dict)   # key → new sha
    removed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)


def diff_items(base: dict[str, str], current: dict[str, str]) -> SnapshotDiff:
    """Difference of two item-hash maps: added / changed / removed / unchanged."""
    added: dict[str, str] = {}
    changed: dict[str, str] = {}
    unchanged: list[str] = []
    removed = [k for k in base if k not in current]
    for key, digest in current.items():
        previous = base.get(key)
        if previous is None:
            added[key] = digest
        elif previous != digest:
            changed[key] = digest
        else:
            unchanged.append(key)
    return SnapshotDiff(added=added, changed=changed, removed=removed, unchanged=unchanged)


def store_snapshot_delta(
    session: Session,
    *,
    tenant_id: str,
    snapshot_id: str,
    items: dict[str, bytes],
    base_snapshot_id: Optional[str] = None,
    base_items: Optional[dict[str, bytes]] = None,
    snapshot_kind: str = "scan",
    category: str = "asset_observation",
    store: Optional[ContentAddressedStore] = None,
) -> SnapshotDelta:
    """Store one snapshot as item content references + a delta document.

    ``items`` maps item key → canonical item bytes. ``base_items`` is the
    BASE snapshot's items (bytes) when one exists — when only hashes are
    at hand, use :func:`diff_items` and put content via the store directly.
    """
    cas = store if store is not None else ContentAddressedStore(session)

    # Every item's bytes go through the CAS: unchanged items dedupe onto
    # the base snapshot's content objects — one copy across N snapshots.
    current_hashes: dict[str, str] = {}
    for key, data in items.items():
        ref = cas.put(tenant_id, data, category=category)
        current_hashes[key] = ref.sha256

    base_hashes: dict[str, str] = {}
    if base_items:
        for key, data in base_items.items():
            base_hashes[key] = sha256_hex(data)

    diff = diff_items(base_hashes, current_hashes)

    # The delta document is itself content-addressed and compressed.
    delta_doc = {
        "added": diff.added,
        "changed": diff.changed,
        "removed": diff.removed,
        "unchanged": diff.unchanged,
    }
    import json
    delta_ref = cas.put(tenant_id, json.dumps(delta_doc, sort_keys=True).encode("utf-8"),
                        category=category, kind="delta")

    row = SnapshotDelta(
        tenant_id=tenant_id,
        snapshot_id=snapshot_id,
        base_snapshot_id=base_snapshot_id,
        snapshot_kind=snapshot_kind,
        delta_content_sha256=delta_ref.sha256,
        added_count=len(diff.added),
        removed_count=len(diff.removed),
        changed_count=len(diff.changed),
        unchanged_count=len(diff.unchanged),
        unchanged_refs=[current_hashes[k] for k in diff.unchanged],
    )
    session.add(row)
    return row


def snapshot_state(session: Session, tenant_id: str, snapshot_id: str) -> dict[str, str]:
    """Materialize a snapshot's item map (key → content hash) by chain walk."""
    chain: list[SnapshotDelta] = []
    seen: set[str] = set()
    current_id: Optional[str] = snapshot_id
    while current_id is not None:
        if current_id in seen:
            raise RuntimeError(f"snapshot chain cycle at {current_id}")
        seen.add(current_id)
        row = session.execute(
            select(SnapshotDelta).where(
                SnapshotDelta.tenant_id == tenant_id,
                SnapshotDelta.snapshot_id == current_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise RuntimeError(f"unknown snapshot {current_id}")
        chain.append(row)
        current_id = row.base_snapshot_id
    chain.reverse()

    import json
    from db.storage.cas import ContentAddressedStore as _CAS
    cas = _CAS(session, enforce_quotas=False)
    state: dict[str, str] = {}
    for row in chain:
        doc = json.loads(cas.get(tenant_id, row.delta_content_sha256).decode("utf-8"))
        for key in doc.get("removed", []):
            state.pop(key, None)
        state.update(doc.get("added", {}))
        state.update(doc.get("changed", {}))
    return state


def materialize_snapshot(session: Session, tenant_id: str, snapshot_id: str) -> dict[str, bytes]:
    """Reconstruct the snapshot's item bytes from shared content references."""
    cas = ContentAddressedStore(session, enforce_quotas=False)
    state = snapshot_state(session, tenant_id, snapshot_id)
    return {key: cas.get(tenant_id, digest) for key, digest in state.items()}
