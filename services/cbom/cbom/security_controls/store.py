"""Append-only evidence store, baseline diff and retention — history for the control layer.

Without this, guide 181 produced documents: a snapshot you could read once and lose. The
question a bank actually asks is *what changed* — "this firewall rule changed since yesterday",
"the WAF stopped presenting that certificate", "the gateway lost an mTLS route" — and a diff
needs two retained records with their evidence intact.

What this store is, and what it refuses to be
---------------------------------------------

It is **evidence**: the exact snapshot a collector produced, its evidence ids, its refusals, its
redactions and the read state that judged it, written once and never rewritten, chained so that
a later edit is detectable.

It is **not** a second estate. Asset identity stays in :mod:`cbom.techbom` — this store keys
records by *content digest* and never assigns an id, never merges two devices into one node and
never answers "which assets exist". A caller who wants the current estate projects it; a caller
who wants history asks the store what it saw and when. Keeping that line is what stops the
second graph from growing.

Layout (one directory per tenant, so a tenant's evidence can be exported alone)::

    <root>/<tenant>/index.jsonl          one line per snapshot, hash-chained
    <root>/<tenant>/snapshots/<sha>.json the snapshot body, written once
    <root>/<tenant>/tombstones.jsonl     retention decisions, append-only

Three operations, each with the failure it refuses:

* ``append`` — idempotent by digest. A re-post of the same evidence is a duplicate, not a new
  revision, so a collector that retries cannot inflate history.
* ``diff`` — added / removed / changed over assets, claims, evidence ids, refusals and read
  state, with the evidence id on both sides of every change.
* ``retain`` — removes bodies older than the window and records a tombstone, so "we purged it"
  is auditable rather than an absence. It never touches the index and never rewrites a line.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .base import ControlRefused, _norm

INDEX = "index.jsonl"
TOMBSTONES = "tombstones.jsonl"
SNAPSHOTS = "snapshots"

#: fields that change on every read and must not enter the content digest, or a retry would
#: look like a new revision and history would fill with noise
VOLATILE_FIELDS: tuple[str, ...] = ("generated_at", "captured_at", "retrieved_at", "duration_ms",
                                    "elapsed_ms", "digest", "sequence", "previous_hash",
                                    "chain_hash", "storage_key", "stored_at")


def canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def content_digest(snapshot: Mapping[str, Any]) -> str:
    """A digest over what the snapshot *says*, not when it was read."""
    body = {key: value for key, value in snapshot.items() if key not in VOLATILE_FIELDS}
    return "sha256:" + hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class Record:
    sequence: int
    digest: str
    captured_at: str
    tenant: str
    previous_hash: str
    entry_hash: str
    controls: tuple[str, ...]
    counts: Mapping[str, Any]
    tombstoned: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"sequence": self.sequence, "digest": self.digest,
                "captured_at": self.captured_at, "tenant": self.tenant,
                "previous_hash": self.previous_hash, "entry_hash": self.entry_hash,
                "controls": list(self.controls), "counts": dict(self.counts),
                "tombstoned": self.tombstoned}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Record":
        return cls(sequence=int(raw.get("sequence") or 0), digest=str(raw.get("digest") or ""),
                   captured_at=str(raw.get("captured_at") or ""),
                   tenant=str(raw.get("tenant") or ""),
                   previous_hash=str(raw.get("previous_hash") or ""),
                   entry_hash=str(raw.get("entry_hash") or ""),
                   controls=tuple(raw.get("controls") or ()),
                   counts=dict(raw.get("counts") or {}),
                   tombstoned=bool(raw.get("tombstoned")))


#: a tenant is one safe path segment, never a path
_TENANT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class EvidenceStore:
    """Append-only, hash-chained evidence for one tenant. Never rewrites a record."""

    def __init__(self, root: str | os.PathLike[str], tenant: str) -> None:
        base = Path(root)
        if not str(base).startswith("/"):
            raise ControlRefused(
                "STORE_ROOT_NOT_ABSOLUTE",
                f"{root!r} must be an absolute path: evidence written next to the code is "
                "evidence nobody backed up")
        self.tenant = _norm(tenant) or "default"
        # a tenant is a directory name. Anything that is not one — a separator, a relative
        # hop, a glob — would let a caller write evidence outside the store it was given,
        # which is the one property an evidence store cannot lose.
        if not _TENANT_PATTERN.match(self.tenant) or ".." in self.tenant:
            raise ControlRefused(
                "TENANT_NOT_A_SLUG",
                f"{self.tenant!r} is not a tenant name: a tenant is a single path segment of "
                "lower-case letters, digits, dot, dash or underscore, so that no tenant can "
                "name a directory outside the store")
        self.root = base / self.tenant
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / SNAPSHOTS).mkdir(exist_ok=True)

    # -- paths -------------------------------------------------------------- #
    @property
    def index_path(self) -> Path:
        return self.root / INDEX

    @property
    def tombstone_path(self) -> Path:
        return self.root / TOMBSTONES

    def body_path(self, digest: str) -> Path:
        return self.root / SNAPSHOTS / f"{digest.replace(':', '-')}.json"

    # -- append ------------------------------------------------------------- #
    def append(self, snapshot: Mapping[str, Any], *,
               captured_at: datetime | str | None = None) -> dict[str, Any]:
        """Write one snapshot. Idempotent by content digest, chained to the previous entry."""
        if not isinstance(snapshot, Mapping):
            raise ControlRefused("NOT_A_SNAPSHOT", "a store takes a snapshot mapping")
        digest = content_digest(snapshot)
        existing = {record.digest: record for record in self.records()}
        if digest in existing:
            record = existing[digest]
            return {"stored": False, "duplicate": True, "digest": digest,
                    "sequence": record.sequence, "captured_at": record.captured_at,
                    "entry_hash": record.entry_hash,
                    "reason": "this evidence is already retained; a retry is not a revision"}
        moment = captured_at if isinstance(captured_at, datetime) else _parse(str(captured_at or ""))
        moment = moment or _now()
        previous = self.records()
        previous_hash = previous[-1].entry_hash if previous else ""
        sequence = (previous[-1].sequence + 1) if previous else 1
        entry = {
            "sequence": sequence, "digest": digest, "tenant": self.tenant,
            "captured_at": _iso(moment), "previous_hash": previous_hash,
            "controls": sorted(_controls(snapshot)),
            "counts": _counts(snapshot),
        }
        entry_hash = hashlib.sha256(
            canonical({**entry, "previous_hash": previous_hash}).encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash
        body = dict(snapshot)
        self._write_once(self.body_path(digest), body)
        self._append_line(self.index_path, entry)
        return {"stored": True, "duplicate": False, "digest": digest, "sequence": sequence,
                "captured_at": entry["captured_at"], "entry_hash": entry_hash,
                "previous_hash": previous_hash}

    # -- read --------------------------------------------------------------- #
    def records(self) -> list[Record]:
        if not self.index_path.exists():
            return []
        found: list[Record] = []
        for line in self.index_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                found.append(Record.from_dict(json.loads(line)))
            except json.JSONDecodeError:
                # a torn last line is a crash, not a record; the chain check reports it
                continue
        return found

    def tombstones(self) -> list[dict[str, Any]]:
        if not self.tombstone_path.exists():
            return []
        return [json.loads(line) for line in
                self.tombstone_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def read(self, digest: str) -> dict[str, Any] | None:
        record = next((item for item in self.records() if item.digest == digest), None)
        if record is None:
            return None
        if record.tombstoned or not self.body_path(digest).exists():
            return None
        return json.loads(self.body_path(digest).read_text(encoding="utf-8"))

    def latest(self) -> tuple[Record | None, dict[str, Any] | None]:
        for record in reversed(self.records()):
            body = self.read(record.digest)
            if body is not None:
                return record, body
        return None, None

    # -- verify ------------------------------------------------------------- #
    def verify(self) -> dict[str, Any]:
        """Recompute the chain and each retained body's digest. Finds edits, not just gaps."""
        records = self.records()
        problems: list[dict[str, Any]] = []
        previous = ""
        for expected, record in enumerate(records, start=1):
            if record.sequence != expected:
                problems.append({"code": "SEQUENCE_GAP", "at": record.digest,
                                 "expected": expected, "found": record.sequence})
            if record.previous_hash != previous:
                problems.append({"code": "CHAIN_BROKEN", "at": record.digest,
                                 "expected_previous": previous,
                                 "found": record.previous_hash})
            recomputed = hashlib.sha256(canonical({
                "sequence": record.sequence, "digest": record.digest,
                "tenant": record.tenant, "captured_at": record.captured_at,
                "previous_hash": record.previous_hash,
                "controls": list(record.controls), "counts": dict(record.counts),
            }).encode("utf-8")).hexdigest()
            if recomputed != record.entry_hash:
                problems.append({"code": "ENTRY_ALTERED", "at": record.digest})
            if not record.tombstoned and self.body_path(record.digest).exists():
                body = json.loads(self.body_path(record.digest).read_text(encoding="utf-8"))
                if content_digest(body) != record.digest:
                    problems.append({"code": "BODY_ALTERED", "at": record.digest})
            previous = record.entry_hash
        return {
            "tenant": self.tenant,
            "records": len(records),
            "retained": sum(1 for record in records if not record.tombstoned),
            "head": records[-1].entry_hash if records else "",
            "verified": not problems,
            "problems": problems,
        }

    # -- diff --------------------------------------------------------------- #
    def diff(self, older: str | None = None, newer: str | None = None) -> dict[str, Any]:
        """What changed between two retained snapshots, with evidence on both sides."""
        records = [record for record in self.records() if not record.tombstoned]
        if older is None or newer is None:
            if len(records) < 2:
                return {"comparable": False, "reason": "fewer than two retained snapshots",
                        "changes": []}
            older_record, newer_record = records[-2], records[-1]
        else:
            older_record = next((r for r in records if r.digest == older), None)
            newer_record = next((r for r in records if r.digest == newer), None)
            if older_record is None or newer_record is None:
                return {"comparable": False,
                        "reason": "one of the named snapshots is not retained",
                        "changes": []}
        return _diff_bodies(self.read(older_record.digest) or {},
                            self.read(newer_record.digest) or {},
                            {"digest": older_record.digest,
                             "captured_at": older_record.captured_at},
                            {"digest": newer_record.digest,
                             "captured_at": newer_record.captured_at})

    def baseline(self, snapshot: Mapping[str, Any]) -> dict[str, Any]:
        """Compare a *candidate* snapshot with what is retained, without storing it.

        This is the collector's own question before it writes: has anything changed since the
        last retained record? Answering it without a write is what lets a caller decide to
        append only when there is something new to append.
        """
        record, body = self.latest()
        if record is None or body is None:
            return {"comparable": False, "reason": "no retained baseline", "changes": []}
        result = _diff_bodies(body, snapshot,
                              {"digest": record.digest, "captured_at": record.captured_at},
                              {"digest": content_digest(snapshot), "captured_at": None})
        result["candidate_digest"] = result["newer"]["digest"]
        result["would_store"] = not result["unchanged"]
        return result

    # -- retention ---------------------------------------------------------- #
    def retain(self, *, max_age_days: int, keep_last: int = 2,
               now: datetime | None = None) -> dict[str, Any]:
        """Remove bodies past the window; record a tombstone for every removal.

        The index is never touched: the record that a snapshot existed, its sequence and its
        chain hash survive the purge. That is the difference between retention and a gap.
        """
        moment = now or _now()
        horizon = moment - timedelta(days=max_age_days)
        records = self.records()
        retained = [record for record in records if not record.tombstoned]
        keep = {record.digest for record in retained[-keep_last:]} if keep_last else set()
        removed: list[dict[str, Any]] = []
        for record in retained:
            captured = _parse(record.captured_at) or moment
            if captured >= horizon or record.digest in keep:
                continue
            body = self.body_path(record.digest)
            written = body.exists()
            if written:
                body.unlink()
            entry = {"digest": record.digest, "sequence": record.sequence,
                     "captured_at": record.captured_at, "tombstoned_at": _iso(moment),
                     "reason": f"older than {max_age_days} day(s)",
                     "body_removed": written}
            self._append_line(self.tombstone_path, entry)
            removed.append(entry)
        # mark in memory for this process; the index stays as written
        for record in records:
            if any(entry["digest"] == record.digest for entry in removed):
                record.tombstoned = True
        return {"tenant": self.tenant, "removed": removed, "kept": len(keep),
                "horizon": _iso(horizon), "max_age_days": max_age_days}

    def facts(self) -> dict[str, Any]:
        """What the store can and cannot answer — printed with every summary."""
        records = self.records()
        return {
            "tenant": self.tenant,
            "records": len(records),
            "retained_bodies": sum(1 for record in records
                                   if self.body_path(record.digest).exists()),
            "tombstones": len(self.tombstones()),
            "first": records[0].captured_at if records else None,
            "last": records[-1].captured_at if records else None,
            "cannot_answer": [
                "which assets exist now — that is the estate projection, not history",
                "who changed the device — the store records what was read, not who acted",
                "anything about a snapshot that was purged: its body is gone by design",
            ],
        }

    # -- internals ---------------------------------------------------------- #
    def _write_once(self, path: Path, payload: Mapping[str, Any]) -> None:
        if path.exists():
            return  # the same digest is the same bytes; never rewrite
        text = json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n"
        handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                             delete=False)
        try:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        finally:
            handle.close()
        os.replace(handle.name, path)

    def _append_line(self, path: Path, entry: Mapping[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(canonical(entry) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _controls(snapshot: Mapping[str, Any]) -> list[str]:
    controls = set()
    for key in ("control", "host"):
        if snapshot.get(key):
            controls.add(str(snapshot[key]))
    for row in snapshot.get("assets") or []:
        control = (row.get("attributes") or {}).get("control_type")
        if control:
            controls.add(str(control))
    return sorted(controls)


def _counts(snapshot: Mapping[str, Any]) -> dict[str, int]:
    return {
        "assets": len(snapshot.get("assets") or []),
        "claims": len(snapshot.get("relationships") or []),
        "crypto": len(snapshot.get("crypto") or []),
        "events": len(snapshot.get("events") or []),
        "evidence": len(snapshot.get("evidence") or []),
        "refusals": len(snapshot.get("refusals") or []),
        "redactions": len(snapshot.get("redactions") or []),
    }


def _collection(body: Mapping[str, Any], kind: str) -> list[Mapping[str, Any]]:
    mapping = {
        "ASSET": "assets",
        "CLAIM": "relationships",
        "EVIDENCE": "evidence",
        "REFUSAL": "refusals",
    }
    return [row for row in body.get(mapping[kind]) or [] if isinstance(row, Mapping)]


def _asset_key(row: Mapping[str, Any]) -> str:
    return f"{row.get('kind')}:{row.get('name')}:{row.get('environment') or 'PRODUCTION'}"


def _claim_key(row: Mapping[str, Any]) -> str:
    return f"{row.get('from')} {row.get('relation')} {row.get('to')}"


def _evidence_key(row: Mapping[str, Any]) -> str:
    return str(row.get("evidence_id") or row.get("id") or canonical(row))


def _refusal_key(row: Mapping[str, Any]) -> str:
    return f"{row.get('code')}:{row.get('subject')}"


def _evidence_ids(row: Mapping[str, Any]) -> list[str]:
    values = row.get("evidence_ids")
    if isinstance(values, list):
        return sorted(str(value) for value in values if value)
    single = row.get("evidence_id") or row.get("id")
    return [str(single)] if single else []


#: what counts as "the same claim, with different content". Fields that move on every read
#: (a timestamp on an event) are excluded, or every diff would report a change nobody made.
_SHAPE_EXCLUDE = frozenset({"observed_at", "first_seen", "last_seen", "timestamp",
                            "collected_at", "at", "evidence_id", "evidence_ids", "id"})


def _shape(row: Mapping[str, Any]) -> str:
    projected: dict[str, Any] = {}
    for key, value in row.items():
        if key in _SHAPE_EXCLUDE:
            continue
        if key == "facts" and isinstance(value, Mapping):
            value = {inner: item for inner, item in value.items()
                     if inner not in _SHAPE_EXCLUDE}
        projected[str(key)] = value
    return canonical(projected)


def _read_states(body: Mapping[str, Any]) -> dict[str, str]:
    """Per-section read state, so a section that stopped being readable is a change too."""
    states: dict[str, str] = {}
    read = body.get("read") or {}
    if isinstance(read, Mapping):
        for row in read.get("sections") or []:
            if isinstance(row, Mapping) and row.get("section"):
                states[str(row["section"])] = str(row.get("state") or "")
    return states


def _diff_bodies(before: Mapping[str, Any], after: Mapping[str, Any],
                 older: Mapping[str, Any], newer: Mapping[str, Any]) -> dict[str, Any]:
    """Added / removed / changed over assets, claims, evidence, refusals and read state."""
    changes: list[dict[str, Any]] = []
    at = newer.get("captured_at")
    for kind, key_fn in (("ASSET", _asset_key), ("CLAIM", _claim_key),
                         ("EVIDENCE", _evidence_key), ("REFUSAL", _refusal_key)):
        left = {key_fn(row): row for row in _collection(before, kind)}
        right = {key_fn(row): row for row in _collection(after, kind)}
        for key in sorted(set(right) - set(left)):
            changes.append({"kind": kind, "change": "ADDED", "subject": key,
                            "evidence_ids": _evidence_ids(right[key]), "at": at})
        for key in sorted(set(left) - set(right)):
            changes.append({"kind": kind, "change": "REMOVED", "subject": key,
                            "evidence_ids": _evidence_ids(left[key]), "at": at})
        for key in sorted(set(left) & set(right)):
            if _shape(left[key]) != _shape(right[key]):
                changes.append({
                    "kind": kind, "change": "CHANGED", "subject": key,
                    "before": _shape(left[key]), "after": _shape(right[key]),
                    "evidence_ids": sorted(set(_evidence_ids(left[key]))
                                           | set(_evidence_ids(right[key]))),
                    "at": at})
    for section, state in sorted(_read_states(after).items()):
        previous_state = _read_states(before).get(section)
        if previous_state and previous_state != state:
            changes.append({"kind": "READ", "change": "CHANGED", "subject": section,
                            "before": previous_state, "after": state, "at": at})
    return {
        "comparable": True,
        "older": dict(older),
        "newer": dict(newer),
        "changes": changes,
        "counts": _change_counts(changes),
        "unchanged": not changes,
    }


def _change_counts(changes: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for change in changes:
        key = f"{change['kind']}:{change['change']}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))
