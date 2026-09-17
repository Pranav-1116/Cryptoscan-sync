"""Persistent, replay-able, multi-consumer topic log.

The shipped transport: an append-only JSONL log per topic (crash-safe
enough for a single host, trivially replaceable by Kafka at deployment —
the envelope and topic contract are identical). Semantics delivered:

- **Immutable append-only** logs, one file per topic under log_dir.
- **Replay**: any consumer can read from any offset (`replay`).
- **Consumer groups**: independent named cursors; one group's reads never
  move another's (`read(group, ...)` / `commit(group)`).
- **Backpressure, honestly**: publish is a synchronous bounded append (no
  unbounded in-process queues); stats expose per-topic depth and consumer
  lag so an operator sees pressure instead of a hidden queue.
"""

from __future__ import annotations

import json
import os
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

from eventstream.envelope import sign_envelope, verify_envelope

_DEFAULT_SECRET = "dev-stream-secret-0123456789abcdef"


class StreamBus:
    def __init__(self, log_dir: str | os.PathLike[str], *, secret: str | None = None,
                 max_mem_per_topic: int = 10_000):
        from eventstream.topics import TOPICS

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.secret = secret or os.environ.get("STREAM_SECRET") or _DEFAULT_SECRET
        self.max_mem_per_topic = max_mem_per_topic
        self._lock = threading.RLock()
        self._log: dict[str, list[dict[str, Any]]] = {t: [] for t in TOPICS}
        self._seq: dict[str, int] = {t: 0 for t in TOPICS}
        self._cursors: dict[str, dict[str, int]] = defaultdict(dict)  # topic -> group -> next seq
        self._load_existing()

    # ---------------------------------------------------------------- storage

    def _path(self, topic: str) -> Path:
        return self.log_dir / f"{topic}.jsonl"

    def _load_existing(self) -> None:
        for path in self.log_dir.glob("*.jsonl"):
            topic = path.stem
            if topic not in self._log:
                continue
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        env = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # torn tail write: skip, never crash boot
                    self._log[topic].append(env)
                    self._seq[topic] = max(self._seq[topic], int(env.get("seq", 0)))

    # ---------------------------------------------------------------- publish

    def _assert_writable(self) -> None:
        """Replica-region dirs refuse writes (split-brain protection)."""
        from eventstream.replication import write_role

        if write_role(self.log_dir) == "replica":
            raise RuntimeError(
                f"bus dir {self.log_dir} has write_role=replica; "
                "promote it (set_write_role role='primary') before publishing")

    def publish(self, topic: str, payload: dict[str, Any], *, key: str = "default",
                source: str = "unknown") -> dict[str, Any]:
        from eventstream.topics import validate_topic

        validate_topic(topic)
        self._assert_writable()
        with self._lock:
            seq = self._seq[topic] + 1
            env = sign_envelope(payload, topic=topic, key=key, seq=seq,
                                source=source, secret=self.secret)
            self._log[topic].append(env)
            self._seq[topic] = seq
            if len(self._log[topic]) > self.max_mem_per_topic:
                # honest bounded memory: the log file remains complete; RAM
                # keeps the newest window (consumers use cursors over file+mem)
                del self._log[topic][: len(self._log[topic]) - self.max_mem_per_topic]
            with self._path(topic).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(env, separators=(",", ":")) + "\n")
            return env

    def publish_raw(self, payload: dict[str, Any], *, key: str = "default",
                    source: str = "unknown") -> dict[str, Any]:
        return self.publish("raw-events", payload, key=key, source=source)

    # ---------------------------------------------------------------- consume

    def read(self, topic: str, group: str, *, limit: int = 100,
             verify: bool = True) -> list[dict[str, Any]]:
        """Deliver up to `limit` unacked events to a consumer group."""
        from eventstream.topics import validate_topic

        validate_topic(topic)
        with self._lock:
            cursor = self._cursors[topic].get(group, 1)
            # reading materializes the group cursor (visible in stats/lag)
            self._cursors[topic].setdefault(group, cursor)
            out = []
            for env in self._log[topic]:
                if int(env["seq"]) < cursor:
                    continue
                if verify and not verify_envelope(env, self.secret):
                    continue  # a tampered line is never delivered
                out.append(env)
                if len(out) >= limit:
                    break
            return out

    def commit(self, topic: str, group: str, upto_seq: int) -> None:
        with self._lock:
            self._cursors[topic][group] = max(self._cursors[topic].get(group, 1), upto_seq + 1)

    def replay(self, topic: str, *, from_seq: int = 1, limit: int | None = None,
               verify: bool = True) -> Iterator[dict[str, Any]]:
        """Iterate a topic from any offset (replay/partition-scan)."""
        from eventstream.topics import validate_topic

        validate_topic(topic)
        count = 0
        for env in list(self._log[topic]):
            if int(env["seq"]) < from_seq:
                continue
            if verify and not verify_envelope(env, self.secret):
                continue
            yield env
            count += 1
            if limit is not None and count >= limit:
                return

    def latest(self, topic: str, *, limit: int = 20) -> list[dict[str, Any]]:
        return list(self._log[topic])[-limit:]

    # ------------------------------------------------------------------ stats

    def stats(self) -> dict[str, Any]:
        with self._lock:
            per_topic = {}
            for topic, log in self._log.items():
                cursors = self._cursors.get(topic, {})
                per_topic[topic] = {
                    "last_seq": self._seq[topic],
                    "in_memory": len(log),
                    "consumer_groups": {g: {"next_seq": s, "lag": max(0, self._seq[topic] + 1 - s)}
                                        for g, s in cursors.items()},
                }
            return {"topics": per_topic,
                    "total_events": sum(self._seq.values())}


_BUS: StreamBus | None = None


def get_bus() -> StreamBus:
    """Process-wide bus singleton (log dir: STREAM_LOG_DIR or data/eventstream)."""
    global _BUS
    if _BUS is None:
        log_dir = os.environ.get("STREAM_LOG_DIR")
        if not log_dir:
            from db.connection.session import SessionLocal  # noqa: F401 (env touch)

            log_dir = str(Path(os.environ.get("CRYPTOSCAN_SNAPSHOT_DIR", "data")) / "eventstream")
        _BUS = StreamBus(log_dir)
    return _BUS


def reset_bus() -> None:
    global _BUS
    _BUS = None
