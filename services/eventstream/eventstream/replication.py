"""Cross-region event-log replication (lossless, tamper-evident).

Design (honest scope): the bus is a single-writer append-only log per topic
per directory. Horizontal scale works like this:

- ONE primary region per topic accepts writes (role marker in the log dir).
- Replica regions receive the primary's logs via :class:`Replicator`, which
  tails the source JSONL, VERIFIES every envelope (HMAC + payload hash) and
  appends only strictly-sequenced, verified lines to the target. Tampered
  lines are never shipped; sequence gaps abort replication (never skip —
  lossless guarantee).
- Failover = promote the replica (flip the role marker); the promoted bus
  continues sequence numbering from the replicated state automatically
  (the bus rebuilds its last-seq from the log files on load).
- When the old primary returns, it comes back as a replica and ships its
  gap back — replication direction follows the write role.

The write-role marker (``write_role.json`` in the log dir) is enforced by
:meth:`StreamBus.publish` — a replica-dir bus refuses writes, which prevents
split-brain double-writes. No marker file means primary (back-compat).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from eventstream.envelope import verify_envelope
from eventstream.topics import validate_topic


class ReplicationGapError(RuntimeError):
    """Source sequence does not continue the target's — replication stopped."""


class TamperedEventError(RuntimeError):
    """An envelope failed signature/hash verification — never shipped."""


def write_role(log_dir: Path | str) -> str:
    path = Path(log_dir) / "write_role.json"
    if not path.exists():
        return "primary"
    try:
        return str(json.loads(path.read_text()).get("role") or "primary")
    except (json.JSONDecodeError, OSError):
        return "primary"


def set_write_role(log_dir: Path | str, role: str) -> None:
    if role not in {"primary", "replica"}:
        raise ValueError("role must be 'primary' or 'replica'")
    path = Path(log_dir)
    path.mkdir(parents=True, exist_ok=True)
    (path / "write_role.json").write_text(
        json.dumps({"role": role, "set_at": time.time()}, separators=(",", ":")) + "\n")


class Replicator:
    """Ships verified lines from a source bus dir into a target bus dir.

    State (offsets) lives in ``target_dir/.replication.json`` keyed by
    ``<source_id>:<topic>``, so replication resumes and stays idempotent.
    """

    def __init__(self, source_dir: Path | str, target_dir: Path | str,
                 secret: str, *, source_id: str | None = None):
        self.source_dir = Path(source_dir)
        self.target_dir = Path(target_dir)
        self.secret = secret
        self.source_id = source_id or self.source_dir.resolve().name
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.target_dir / ".replication.json"
        self.state: dict[str, Any] = {}
        if self.state_path.exists():
            try:
                self.state = json.loads(self.state_path.read_text())
            except json.JSONDecodeError:
                self.state = {}

    # -- state -------------------------------------------------------------
    def _key(self, topic: str) -> str:
        return f"{self.source_id}:{topic}"

    def _offset(self, topic: str) -> int:
        return int(self.state.get(self._key(topic), {}).get("byte_offset", 0))

    def _save(self, topic: str, byte_offset: int, shipped: int) -> None:
        self.state[self._key(topic)] = {
            "byte_offset": byte_offset, "shipped_total": shipped,
            "last_shipped_at": time.time(),
        }
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, sort_keys=True))
        tmp.replace(self.state_path)

    # -- shipping ----------------------------------------------------------
    def ship_once(self, topic: str) -> int:
        """Copy every complete, verified source line that continues the
        target's sequence. Returns the number of events shipped."""
        validate_topic(topic)
        # Fork protection is the sequence-continuation check below: a target
        # that wrote its own history cannot be merged unless the source
        # continues that exact sequence (failover-back converges cleanly).
        source_file = self.source_dir / f"{topic}.jsonl"
        if not source_file.exists():
            return 0
        target_file = self.target_dir / f"{topic}.jsonl"
        offset = self._offset(topic)
        raw = source_file.read_bytes()
        if len(raw) < offset:
            # the source log shrank below our shipped offset: history was
            # rewritten upstream — never guess, abort (reseed the target)
            raise ReplicationGapError(
                f"source log shrank ({len(raw)} < {offset} bytes); "
                "history rewritten — replication aborted")
        if len(raw) <= offset:
            return 0
        chunk = raw[offset:]
        # torn tail: an incomplete last line is not yet durable on the source
        if chunk and not chunk.endswith(b"\n"):
            chunk = chunk[: chunk.rfind(b"\n") + 1]
        if not chunk:
            return 0

        target_last = self._target_next_seq(topic)
        expected_next = target_last + 1  # seq of the next line
        if offset == 0 and target_last > 0:
            # converging replica: the target already holds events the source
            # also carries (shipped before a role flip). Verify-and-skip the
            # overlap so the directions can reverse after failover.
            aligned = False
            for line in raw.splitlines(keepends=True):
                try:
                    envelope = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise TamperedEventError(
                        f"unparsable line while aligning at {len(line)}") from exc
                if not verify_envelope(envelope, self.secret):
                    raise TamperedEventError(
                        f"verification failed while aligning "
                        f"(topic={topic} seq={envelope.get('seq')})")
                seq = int(envelope["seq"])
                if seq == target_last:
                    offset += len(line)  # include the final overlapped line
                    aligned = True
                    break
                offset += len(line)  # skip this verified overlap line
                if seq > target_last:
                    break
            if not aligned:
                raise ReplicationGapError(
                    f"cannot align: target last seq {target_last} not found "
                    f"in source '{topic}'")
            chunk = raw[offset:]
            if not chunk:
                self._save(topic, offset,
                           int(self.state.get(self._key(topic), {}).get("shipped_total", 0)))
                return 0
            if not chunk.endswith(b"\n"):
                chunk = chunk[: chunk.rfind(b"\n") + 1]
            if not chunk:
                self._save(topic, offset,
                           int(self.state.get(self._key(topic), {}).get("shipped_total", 0)))
                return 0
        shipped = 0
        accepted = bytearray()
        for line in chunk.splitlines(keepends=True):
            if not line.strip():
                offset += len(line)
                continue
            try:
                envelope = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TamperedEventError(f"unparsable line at offset {offset}") from exc
            if not verify_envelope(envelope, self.secret):
                raise TamperedEventError(
                    f"verification failed at offset {offset} "
                    f"(topic={topic} seq={envelope.get('seq')})")
            if int(envelope["seq"]) != expected_next + shipped:
                raise ReplicationGapError(
                    f"source seq {envelope['seq']} != expected "
                    f"{expected_next + shipped} on '{topic}'")
            accepted += line if line.endswith(b"\n") else line + b"\n"
            shipped += 1

        if shipped:
            with target_file.open("ab") as fh:
                fh.write(accepted)
            offset += len(accepted)
            totals = int(self.state.get(self._key(topic), {}).get("shipped_total", 0))
            self._save(topic, offset, totals + shipped)
        return shipped

    def ship_all(self, topics: list[str] | None = None) -> dict[str, int]:
        out: dict[str, int] = {}
        for topic in (topics or ["raw-events", "normalized-events", "policy-results",
                                 "attack-detections", "cbom-updates", "graph-sync",
                                 "audit-log", "alerts"]):
            try:
                out[topic] = self.ship_once(topic)
            except (ReplicationGapError, TamperedEventError):
                out[topic] = -1  # error sentinel; per-topic errors don't stall others
        return out

    # -- helpers -----------------------------------------------------------
    def _target_next_seq(self, topic: str) -> int:
        """Last durable seq on the target for this topic (from its own state
        file when present — the target bus owns truth; file scan on cold start)."""
        target_file = self.target_dir / f"{topic}.jsonl"
        if not target_file.exists():
            return 0
        size = target_file.stat().st_size
        with target_file.open("rb") as fh:
            fh.seek(max(0, size - 65536))
            tail = fh.read().splitlines()
        for line in reversed(tail):
            if not line.strip():
                continue
            try:
                return int(json.loads(line)["seq"])
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        return 0

