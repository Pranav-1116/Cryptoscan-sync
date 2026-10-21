"""Redis per-estate retained journal, atomic append and snapshot pages.

Independent stream retention/sequence prevents foreign traffic evicting an
estate's records. WATCH/MULTI keeps sequence allocation, both journals and fanout
in one Redis transaction. This is not a DB/Redis distributed transaction.
"""

import json
import random
import time
import uuid
from redis.exceptions import WatchError
from api.events.estate_replay import ReplayError, bucket

PREFIX = "zelinx:events:estate:v1:"
RETENTION = 10_000


class RedisEstateJournal:
    def __init__(self, redis, retention=RETENTION):
        self.redis, self.retention = redis, retention

    @staticmethod
    def text(value):
        return value.decode() if isinstance(value, bytes) else str(value)

    def keys(self, owner):
        key = PREFIX + bucket(owner)
        return key + ":meta", key + ":stream"

    @staticmethod
    def _refuse_if_stable(pipe, detail):
        # WATCH reads are not a snapshot: another append may commit between
        # HGETALL and XRANGE. Confirm the observed error against the watched
        # version before calling it corruption. Invalidations raise WatchError
        # into the same bounded retry path; stable corruption still refuses.
        pipe.multi()
        pipe.execute()
        raise ReplayError(detail)

    def append(self, event, *, global_stream, channel, node, global_retention):
        meta, stream = self.keys(event.get("tenant_id"))
        for attempt in range(16):
            with self.redis.pipeline() as pipe:
                try:
                    pipe.watch(meta, stream, global_stream)
                    if any(self.text(pipe.type(k)) not in ("none", "stream") for k in (stream, global_stream)):
                        self._refuse_if_stable(pipe, "Event journal type mismatch")
                    state = {self.text(k): self.text(v) for k, v in pipe.hgetall(meta).items()}
                    if not state and pipe.exists(stream):
                        self._refuse_if_stable(pipe, "Event journal metadata missing")
                    if state:
                        last = pipe.xrevrange(stream, count=1)
                        if (
                            not last
                            or int(self.text(last[0][0]).split("-")[0]) != int(state["latest"])
                            or len(state.get("epoch", "")) != 32
                        ):
                            self._refuse_if_stable(pipe, "Event journal state is incomplete")
                    sequence = int(state.get("latest", 0)) + 1
                    epoch = state.get("epoch") or uuid.uuid4().hex
                    frame = {**event, "estate_sequence": sequence, "estate_epoch": epoch, "node": node}
                    raw = json.dumps(frame, default=str, separators=(",", ":"))
                    fields = {
                        "id": str(event["id"]),
                        "ts": str(event.get("ts", "")),
                        "type": str(event.get("type", "")),
                        "source": str(event.get("source", "")),
                        "tenant_id": event.get("tenant_id") or "",
                        "payload": json.dumps(event.get("payload") or {}, default=str),
                    }
                    pipe.multi()
                    pipe.xadd(global_stream, fields, maxlen=global_retention, approximate=True)
                    pipe.xadd(stream, {"frame": raw}, id=f"{sequence}-0", maxlen=self.retention, approximate=False)
                    pipe.hset(meta, mapping={"epoch": epoch, "latest": str(sequence)})
                    pipe.publish(channel, raw)
                    pipe.execute()
                    event.update(estate_sequence=sequence, estate_epoch=epoch)
                    return
                except WatchError:
                    # Bounded jitter prevents hot writers/readers spinning in
                    # lockstep. Exhaustion remains an explicit refusal.
                    time.sleep(random.uniform(0, min(0.001 * 2**attempt, 0.05)))
                    continue
        raise ReplayError("Event journal contention; append refused")

    def page(self, owner, after, through, limit):
        meta, stream = self.keys(owner)
        for attempt in range(16):
            with self.redis.pipeline() as pipe:
                try:
                    pipe.watch(meta, stream)
                    state = {self.text(k): self.text(v) for k, v in pipe.hgetall(meta).items()}
                    first = pipe.xrange(stream, count=1)
                    if not state and first:
                        self._refuse_if_stable(pipe, "Event journal metadata missing")
                    latest = int(state.get("latest", 0))
                    epoch = state.get("epoch")
                    if state:
                        last = pipe.xrevrange(stream, count=1)
                        if (
                            latest <= 0
                            or not first
                            or not last
                            or not epoch
                            or len(epoch) != 32
                            or int(self.text(last[0][0]).split("-")[0]) != latest
                        ):
                            self._refuse_if_stable(pipe, "Retained event journal missing or corrupt")
                    oldest = int(self.text(first[0][0]).split("-")[0]) if first else 1
                    end = latest if through is None else through
                    rows = pipe.xrange(stream, min=f"{max(1, after + 1)}-0", max=f"{max(0, end)}-0", count=limit + 1)
                    pipe.multi()
                    pipe.execute()
                    records = []
                    for seq, fields in rows:
                        fields = {self.text(k): self.text(v) for k, v in fields.items()}
                        records.append((int(self.text(seq).split("-")[0]), json.loads(fields["frame"])))
                    return epoch, oldest, latest, end, records
                except WatchError:
                    # Bounded jitter prevents hot writers/readers spinning in
                    # lockstep. Exhaustion remains an explicit refusal.
                    time.sleep(random.uniform(0, min(0.001 * 2**attempt, 0.05)))
                    continue
        raise ReplayError("Event journal contention; replay refused")
