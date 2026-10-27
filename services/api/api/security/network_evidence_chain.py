"""Tamper-evident hash chain for network evidence (spec 67 §24, §29).

Evidence is only worth something if you can tell whether it changed after it was
recorded. Each chained record gets:

    record_hash = sha256(canonical JSON of the record)
    prev_hash   = the previous entry's record_hash (genesis = 64 zeros)

and the chain head is stored with the entries, so editing a stored record,
deleting one, or re-ordering them shows up as a broken link or a hash mismatch
on verification.

Honest limits, returned with every receipt: this is a **local** chain in the
platform database. It detects modification of stored evidence; it does not stop
an operator with database access from rewriting the whole chain, because there
is no external anchor or signature yet (``anchoring: "local-database-only"``).
It is also not a distributed ledger (``distributed: false``).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

CHAIN_SCHEMA = "cryptoscan.network-evidence-chain/1"
VERIFY_SCHEMA = "cryptoscan.network-evidence-chain-verification/1"

#: genesis link — a chain that verifies from seq 1 must start here
GENESIS = "0" * 64

#: keep the setting blob bounded; older entries are dropped and *declared* as
#: such rather than silently disappearing
MAX_ENTRIES = 5000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def chain_key(tenant_id: str | None) -> str:
    return f"network:evidence-chain:{tenant_id or 'global'}"


def canonical_record(record: dict[str, Any]) -> str:
    """Deterministic JSON for hashing: sorted keys, no read-time ``integrity``."""
    payload = {key: value for key, value in record.items() if key != "integrity"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_record(record).encode("utf-8")).hexdigest()


def ensure_evidence_ids(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Give every record a stable id so the chain can reference it.

    Passive and IPsec records are built without an id; the id is assigned once,
    before hashing, and stored inside the record so read-back and verification
    agree on the same identity.
    """
    out: list[dict[str, Any]] = []
    for record in records:
        if not record.get("evidence_id"):
            record = {**record, "evidence_id": f"ev-{uuid.uuid4().hex}"}
        out.append(record)
    return out


def _read(db, key: str) -> dict[str, Any] | None:
    from sqlalchemy import select

    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None or not row.value:
        return None
    try:
        payload = json.loads(row.value)
    except (TypeError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def _write(db, key: str, payload: dict[str, Any], user: str | None) -> None:
    from sqlalchemy import select

    from db.models.app_setting import AppSetting

    row = db.execute(select(AppSetting).where(AppSetting.key == key)).scalars().first()
    if row is None:
        db.add(AppSetting(key=key, value=json.dumps(payload), updated_by=user))
    else:
        row.value = json.dumps(payload)
        row.updated_by = user
    db.commit()


def empty_chain() -> dict[str, Any]:
    return {
        "schema": CHAIN_SCHEMA,
        "seq": 0,
        "entries": [],
        "head": GENESIS,
        "truncated_before_seq": 0,
        "anchored_prev_hash": GENESIS,
        "updated_at": None,
    }


def read_chain(db, *, tenant_id: str | None) -> dict[str, Any]:
    return _read(db, chain_key(tenant_id)) or empty_chain()


def append(
    db,
    records: Iterable[dict[str, Any]],
    *,
    run_id: str | None = None,
    tenant_id: str | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    """Append records to the tenant chain; returns the chain head receipt.

    Records must already carry ``evidence_id`` (see :func:`ensure_evidence_ids`).
    Appending is idempotent per ``(run_id, evidence_id)`` so a retried request
    cannot create duplicate links that would look like tampering.
    """
    items = [record for record in records if record.get("evidence_id")]
    chain = read_chain(db, tenant_id=tenant_id)
    entries: list[dict[str, Any]] = list(chain.get("entries") or [])
    known = {(entry.get("run_id"), entry.get("evidence_id")) for entry in entries}
    head = str(chain.get("head") or GENESIS)
    seq = int(chain.get("seq") or 0)
    appended: list[str] = []

    for record in items:
        key = (run_id, record.get("evidence_id"))
        if key in known:
            continue
        seq += 1
        digest = record_hash(record)
        entries.append(
            {
                "seq": seq,
                "evidence_id": record.get("evidence_id"),
                "run_id": run_id,
                "evidence_type": record.get("evidence_type"),
                "protocol": record.get("protocol"),
                "scope_name": record.get("scope_name"),
                "record_hash": digest,
                "prev_hash": head,
                "recorded_at": _now(),
            }
        )
        known.add(key)
        appended.append(record["evidence_id"])
        head = digest

    dropped = 0
    truncated_before = int(chain.get("truncated_before_seq") or 0)
    if len(entries) > MAX_ENTRIES:
        dropped = len(entries) - MAX_ENTRIES
        entries = entries[dropped:]
        truncated_before = int(entries[0]["seq"]) - 1

    payload = {
        "schema": CHAIN_SCHEMA,
        "seq": seq,
        "entries": entries,
        "head": head,
        "truncated_before_seq": truncated_before,
        # when entries were dropped the chain is only verifiable from this link
        "anchored_prev_hash": str(entries[0]["prev_hash"]) if entries else GENESIS,
        "updated_at": _now(),
    }
    if appended or dropped:
        _write(db, chain_key(tenant_id), payload, user)
    return {
        "schema": CHAIN_SCHEMA,
        "appended": len(appended),
        "dropped_from_window": dropped,
        "seq": seq,
        "head": head,
        "truncated_before_seq": truncated_before,
        "distributed": False,
        "anchoring": "local-database-only",
    }


def attach_integrity(records: Iterable[dict[str, Any]], chain: dict[str, Any]) -> list[dict[str, Any]]:
    """Copy records with their chain position attached (read-time only)."""
    by_id = {
        str(entry.get("evidence_id")): entry
        for entry in chain.get("entries") or []
        if entry.get("evidence_id")
    }
    out: list[dict[str, Any]] = []
    for record in records:
        entry = by_id.get(str(record.get("evidence_id")))
        if not entry:
            out.append({**record, "integrity": {"chained": False, "reason": "record was not chained"}})
            continue
        out.append(
            {
                **record,
                "integrity": {
                    "chained": True,
                    "seq": entry.get("seq"),
                    "record_hash": entry.get("record_hash"),
                    "prev_hash": entry.get("prev_hash"),
                    "recorded_at": entry.get("recorded_at"),
                },
            }
        )
    return out


def verify(
    chain: dict[str, Any],
    *,
    records: Iterable[dict[str, Any]] = (),
    records_by_run: dict[str, Iterable[dict[str, Any]]] | None = None,
    expected_head: str | None = None,
) -> dict[str, Any]:
    """Recompute the chain and compare it with the stored records.

    ``records`` are the records the caller can currently see; records referenced
    by the chain but not supplied are reported as ``unverifiable`` (an honest
    gap), not as a pass.
    """
    entries = list(chain.get("entries") or [])
    by_id: dict[str, dict[str, Any]] = {
        str(record.get("evidence_id")): record for record in records if record.get("evidence_id")
    }
    for _run_id, run_records in (records_by_run or {}).items():
        for record in run_records:
            if record.get("evidence_id"):
                by_id.setdefault(str(record["evidence_id"]), record)

    problems: list[dict[str, Any]] = []
    unverifiable: list[dict[str, Any]] = []
    tampered: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    checked = 0

    anchored = str(chain.get("anchored_prev_hash") or GENESIS)
    truncated_before = int(chain.get("truncated_before_seq") or 0)
    running = anchored
    for index, entry in enumerate(entries):
        seq = entry.get("seq")
        if entry.get("prev_hash") != running:
            problems.append(
                {
                    "seq": seq,
                    "problem": "BROKEN_LINK",
                    "detail": "this entry's prev_hash does not match the previous entry's record_hash",
                }
            )
        record = by_id.get(str(entry.get("evidence_id")))
        if record is None:
            if entry.get("run_id") in (records_by_run or {}):
                missing.append({"seq": seq, "evidence_id": entry.get("evidence_id"), "run_id": entry.get("run_id")})
            else:
                unverifiable.append(
                    {"seq": seq, "evidence_id": entry.get("evidence_id"), "reason": "record not loaded in this window"}
                )
        else:
            checked += 1
            if record_hash(record) != entry.get("record_hash"):
                tampered.append(
                    {
                        "seq": seq,
                        "evidence_id": entry.get("evidence_id"),
                        "expected": entry.get("record_hash"),
                        "actual": record_hash(record),
                        "problem": "RECORD_HASH_MISMATCH",
                    }
                )
        running = str(entry.get("record_hash") or running)

    head = str(chain.get("head") or GENESIS)
    head_matches = running == head
    if not head_matches:
        problems.append({"problem": "HEAD_MISMATCH", "detail": "recomputed head differs from the stored head"})

    seen_ids = {str(entry.get("evidence_id")) for entry in entries}
    unchained = sorted(
        str(record.get("evidence_id"))
        for record in by_id.values()
        if str(record.get("evidence_id")) not in seen_ids
    )
    if expected_head is not None and expected_head != head:
        problems.append(
            {
                "problem": "ANCHOR_MISMATCH",
                "detail": f"expected head {expected_head} but the chain head is {head}",
            }
        )

    verified = not problems and not tampered and not missing and head_matches
    return {
        "schema": VERIFY_SCHEMA,
        "verified": verified,
        "entries": len(entries),
        "checked_records": checked,
        "seq": chain.get("seq"),
        "head_hash": head,
        "anchored_prev_hash": anchored,
        "truncated_before_seq": truncated_before,
        "truncated": truncated_before > 0,
        "complete_from_seq": (entries[0]["seq"] if entries else None),
        "problems": problems,
        "tampered_records": tampered,
        "missing_records": missing,
        "unverifiable_entries": unverifiable,
        "unchained_records": unchained,
        "reason": None
        if verified
        else (
            "chain does not verify: "
            + ", ".join(
                sorted({item.get("problem") for item in problems} | ({"RECORD_HASH_MISMATCH"} if tampered else set()) | ({"RECORD_MISSING"} if missing else set()))
            )
        ),
        "distributed": False,
        "anchoring": "local-database-only",
        "boundary": (
            "the chain detects modification, deletion or re-ordering of stored evidence in this "
            "database; it is not externally anchored and does not prevent someone with database "
            "access from rewriting the chain"
        ),
    }
