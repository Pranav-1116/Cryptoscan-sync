"""Generic tamper-evident hash chain for stored evidence.

Every chained record gets:

    record_hash = sha256(canonical JSON of the record)
    prev_hash   = the previous entry's record_hash   (genesis = 64 zeros)

so editing a stored record, deleting one, or re-ordering them shows up as a
broken link or a hash mismatch on verification.

The chain is **namespace-scoped** (network evidence, runtime events) so the two
engines do not share a head: a runtime event appearing in the network chain
would be a provenance error, not a feature. Each namespace keeps its own id
field (``evidence_id`` for network records, ``event_id`` for runtime events).

Honest limits, returned with every receipt: this is a **local** chain in the
platform database. It detects modification of stored evidence; it does not stop
an operator with database access from rewriting the whole chain, because there
is no external anchor or signature yet (``anchoring: "local-database-only"``).
It is also not a distributed ledger (``distributed: false``).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

#: genesis link — a chain that verifies from seq 1 must start here
GENESIS = "0" * 64

#: keep the setting blob bounded; older entries are dropped and *declared* as
#: such rather than silently disappearing
MAX_ENTRIES = 5000


@dataclass(frozen=True)
class ChainSpec:
    """Which evidence stream this chain protects."""

    namespace: str
    id_field: str
    chain_schema: str
    verify_schema: str
    #: entry fields copied from the record for readable listing
    entry_fields: tuple[str, ...] = ("evidence_type", "protocol", "scope_name")

    def key(self, tenant_id: str | None) -> str:
        return f"{self.namespace}:evidence-chain:{tenant_id or 'global'}"


NETWORK_CHAIN = ChainSpec(
    namespace="network",
    id_field="evidence_id",
    chain_schema="cryptoscan.network-evidence-chain/1",
    verify_schema="cryptoscan.network-evidence-chain-verification/1",
)

RUNTIME_CHAIN = ChainSpec(
    namespace="runtime",
    id_field="event_id",
    chain_schema="cryptoscan.runtime-evidence-chain/1",
    verify_schema="cryptoscan.runtime-evidence-chain-verification/1",
    entry_fields=("evidence_type", "source", "adapter"),
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_record(record: dict[str, Any]) -> str:
    """Deterministic JSON for hashing: sorted keys, no read-time ``integrity``."""
    payload = {key: value for key, value in record.items() if key != "integrity"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_record(record).encode("utf-8")).hexdigest()


def ensure_ids(records: Iterable[dict[str, Any]], spec: ChainSpec) -> list[dict[str, Any]]:
    """Give every record a stable id so the chain can reference it."""
    out: list[dict[str, Any]] = []
    for record in records:
        if not record.get(spec.id_field):
            record = {**record, spec.id_field: f"ev-{uuid.uuid4().hex}"}
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


def empty_chain(spec: ChainSpec) -> dict[str, Any]:
    return {
        "schema": spec.chain_schema,
        "seq": 0,
        "entries": [],
        "head": GENESIS,
        "truncated_before_seq": 0,
        "anchored_prev_hash": GENESIS,
        "updated_at": None,
    }


def read_chain(db, *, spec: ChainSpec, tenant_id: str | None) -> dict[str, Any]:
    return _read(db, spec.key(tenant_id)) or empty_chain(spec)


def append(
    db,
    records: Iterable[dict[str, Any]],
    *,
    spec: ChainSpec,
    run_id: str | None = None,
    tenant_id: str | None = None,
    user: str | None = None,
) -> dict[str, Any]:
    """Append records to the tenant chain; returns the chain head receipt.

    Records must already carry their id field. Appending is idempotent per
    ``(run_id, id)`` so a retried request cannot create duplicate links that
    would look like tampering.
    """
    id_field = spec.id_field
    items = [record for record in records if record.get(id_field)]
    chain = read_chain(db, spec=spec, tenant_id=tenant_id)
    entries: list[dict[str, Any]] = list(chain.get("entries") or [])
    known = {(entry.get("run_id"), entry.get(id_field)) for entry in entries}
    head = str(chain.get("head") or GENESIS)
    seq = int(chain.get("seq") or 0)
    appended: list[str] = []

    for record in items:
        key = (run_id, record.get(id_field))
        if key in known:
            continue
        seq += 1
        digest = record_hash(record)
        entry: dict[str, Any] = {
            "seq": seq,
            id_field: record.get(id_field),
            "run_id": run_id,
        }
        for name in spec.entry_fields:
            entry[name] = record.get(name)
        entry["record_hash"] = digest
        entry["prev_hash"] = head
        entry["recorded_at"] = _now()
        entries.append(entry)
        known.add(key)
        appended.append(str(record[id_field]))
        head = digest

    dropped = 0
    truncated_before = int(chain.get("truncated_before_seq") or 0)
    if len(entries) > MAX_ENTRIES:
        dropped = len(entries) - MAX_ENTRIES
        entries = entries[dropped:]
        truncated_before = int(entries[0]["seq"]) - 1

    payload = {
        "schema": spec.chain_schema,
        "namespace": spec.namespace,
        "seq": seq,
        "entries": entries,
        "head": head,
        "truncated_before_seq": truncated_before,
        # when entries were dropped the chain is only verifiable from this link
        "anchored_prev_hash": str(entries[0]["prev_hash"]) if entries else GENESIS,
        "updated_at": _now(),
    }
    if appended or dropped:
        _write(db, spec.key(tenant_id), payload, user)
    return {
        "schema": spec.chain_schema,
        "namespace": spec.namespace,
        "appended": len(appended),
        "dropped_from_window": dropped,
        "seq": seq,
        "head": head,
        "truncated_before_seq": truncated_before,
        "distributed": False,
        "anchoring": "local-database-only",
    }


def attach_integrity(
    records: Iterable[dict[str, Any]],
    chain: dict[str, Any],
    *,
    spec: ChainSpec,
) -> list[dict[str, Any]]:
    """Copy records with their chain position attached (read-time only)."""
    by_id = {
        str(entry.get(spec.id_field)): entry
        for entry in chain.get("entries") or []
        if entry.get(spec.id_field)
    }
    out: list[dict[str, Any]] = []
    for record in records:
        entry = by_id.get(str(record.get(spec.id_field)))
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
    spec: ChainSpec,
    records: Iterable[dict[str, Any]] = (),
    records_by_run: dict[str, Iterable[dict[str, Any]]] | None = None,
    expected_head: str | None = None,
) -> dict[str, Any]:
    """Recompute the chain and compare it with the stored records.

    ``records`` are the records the caller can currently see; records referenced
    by the chain but not supplied are reported as ``unverifiable`` (an honest
    gap), not as a pass.
    """
    id_field = spec.id_field
    entries = list(chain.get("entries") or [])
    by_id: dict[str, dict[str, Any]] = {
        str(record.get(id_field)): record for record in records if record.get(id_field)
    }
    for _run_id, run_records in (records_by_run or {}).items():
        for record in run_records:
            if record.get(id_field):
                by_id.setdefault(str(record[id_field]), record)

    problems: list[dict[str, Any]] = []
    unverifiable: list[dict[str, Any]] = []
    tampered: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    checked = 0

    anchored = str(chain.get("anchored_prev_hash") or GENESIS)
    truncated_before = int(chain.get("truncated_before_seq") or 0)
    running = anchored
    for entry in entries:
        seq = entry.get("seq")
        if entry.get("prev_hash") != running:
            problems.append(
                {
                    "seq": seq,
                    "problem": "BROKEN_LINK",
                    "detail": "this entry's prev_hash does not match the previous entry's record_hash",
                }
            )
        record = by_id.get(str(entry.get(id_field)))
        if record is None:
            if entry.get("run_id") in (records_by_run or {}):
                missing.append({"seq": seq, id_field: entry.get(id_field), "run_id": entry.get("run_id")})
            else:
                unverifiable.append(
                    {"seq": seq, id_field: entry.get(id_field), "reason": "record not loaded in this window"}
                )
        else:
            checked += 1
            if record_hash(record) != entry.get("record_hash"):
                tampered.append(
                    {
                        "seq": seq,
                        id_field: entry.get(id_field),
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

    seen_ids = {str(entry.get(id_field)) for entry in entries}
    unchained = sorted(
        str(record.get(id_field)) for record in by_id.values() if str(record.get(id_field)) not in seen_ids
    )
    if expected_head is not None and expected_head != head:
        problems.append(
            {
                "problem": "ANCHOR_MISMATCH",
                "detail": f"expected head {expected_head} but the chain head is {head}",
            }
        )

    verified = not problems and not tampered and not missing and head_matches
    failure_codes = sorted(
        {item.get("problem") for item in problems}
        | ({"RECORD_HASH_MISMATCH"} if tampered else set())
        | ({"RECORD_MISSING"} if missing else set())
    )
    return {
        "schema": spec.verify_schema,
        "namespace": spec.namespace,
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
        "reason": None if verified else "chain does not verify: " + ", ".join(failure_codes),
        "distributed": False,
        "anchoring": "local-database-only",
        "boundary": (
            "the chain detects modification, deletion or re-ordering of stored evidence in this "
            "database; it is not externally anchored and does not prevent someone with database "
            "access from rewriting the chain"
        ),
    }
