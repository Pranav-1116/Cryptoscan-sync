"""Cross-region replication (lossless failover) + point-in-time recovery."""

from __future__ import annotations

import json

import pytest

from eventstream.bus import StreamBus
from eventstream.pitr import pitr_restore, pitr_snapshot
from eventstream.replication import (
    ReplicationGapError,
    Replicator,
    TamperedEventError,
    set_write_role,
    write_role,
)

SECRET = "replication-secret-0123456789ab"


def _bus(tmp_path, name):
    return StreamBus(tmp_path / name, secret=SECRET)


def test_replica_dir_refuses_writes_split_brain(tmp_path):
    bus = _bus(tmp_path, "r1")
    set_write_role(tmp_path / "r1", "replica")
    with pytest.raises(RuntimeError, match="replica"):
        bus.publish("raw-events", {"x": 1})
    set_write_role(tmp_path / "r1", "primary")
    bus.publish("raw-events", {"x": 2})  # promotion re-enables writes
    assert write_role(tmp_path / "r1") == "primary"


def test_replication_ships_verified_lines_only(tmp_path):
    a, b = _bus(tmp_path, "region-a"), _bus(tmp_path, "region-b")
    for i in range(5):
        a.publish("raw-events", {"i": i}, source="edge")
    rep = Replicator(tmp_path / "region-a", tmp_path / "region-b", SECRET)
    assert rep.ship_once("raw-events") == 5
    # idempotent: second pass ships nothing new
    assert rep.ship_once("raw-events") == 0
    # a replica process loads the shipped log at boot
    b_loaded = _bus(tmp_path, "region-b")
    shipped = [e["payload"]["i"] for e in b_loaded.read("raw-events", "reader")]
    assert shipped == [0, 1, 2, 3, 4]
    assert [e["seq"] for e in b_loaded.read("raw-events", "reader")] == [1, 2, 3, 4, 5]
    # torn tail (half-written line) is not shipped until the writer's flush
    # completes — appending never repairs it
    with open(tmp_path / "region-a" / "raw-events.jsonl", "ab") as fh:
        fh.write(b'{"v":1,"topic":"raw-evt')  # no newline
    assert rep.ship_once("raw-events") == 0
    # the source writer finishes its flush: completes the line in place
    with open(tmp_path / "region-a" / "raw-events.jsonl", "ab") as fh:
        fh.write(b'","key":"k","seq":6,"source":"t","ts":"now","payload":{"i":5},'
                 b'"payload_hash":"0","hmac":"0"}\n')
    # the completed-but-unsigned line is tamper-checked: refused, never shipped
    with pytest.raises(TamperedEventError):
        rep.ship_once("raw-events")
    # the batch stays blocked behind the unverifiable line (atomic batches):
    # even a REAL new event ships nothing while the bad line heads the batch
    a.publish("raw-events", {"i": 5})
    with pytest.raises(TamperedEventError):
        rep.ship_once("raw-events")


def test_replication_refuses_tampered_lines(tmp_path):
    a, b = _bus(tmp_path, "region-a"), _bus(tmp_path, "region-b")
    a.publish("alerts", {"ok": True})
    rep = Replicator(tmp_path / "region-a", tmp_path / "region-b", SECRET)
    assert rep.ship_once("alerts") == 1
    # attacker appends a forged line to the source log
    evil = {"v": 1, "topic": "alerts", "key": "k", "seq": 2, "source": "evil",
            "ts": "now", "payload": {"ok": False}, "payload_hash": "0" * 64,
            "hmac": "0" * 64}
    with open(tmp_path / "region-a" / "alerts.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(evil) + "\n")
    with pytest.raises(TamperedEventError):
        rep.ship_once("alerts")
    # nothing forged landed on the target
    assert [e["seq"] for e in _bus(tmp_path, "region-b").read("alerts", "r")] == [1]


def test_replication_aborts_on_sequence_gap_never_skips(tmp_path):
    a, b = _bus(tmp_path, "region-a"), _bus(tmp_path, "region-b")
    for i in range(3):
        a.publish("raw-events", {"i": i})
    rep = Replicator(tmp_path / "region-a", tmp_path / "region-b", SECRET)
    assert rep.ship_once("raw-events") == 3
    # (a) shrunken source (history rewritten upstream) -> hard abort
    whole = (tmp_path / "region-a" / "raw-events.jsonl").read_bytes()
    (tmp_path / "region-a" / "raw-events.jsonl").write_bytes(whole[:whole.index(b"\n") + 1])
    with pytest.raises(ReplicationGapError, match="shrank"):
        rep.ship_once("raw-events")
    # (b) a genuinely skipping source: replace log with seqs 1,2,7 (gap at 3)
    a3 = StreamBus(tmp_path / "region-src2", secret=SECRET)
    a3.publish("raw-events", {"n": 1})
    a3.publish("raw-events", {"n": 2})
    src2_file = tmp_path / "region-src2" / "raw-events.jsonl"
    lines2 = src2_file.read_text().splitlines()
    forged_next = json.loads(lines2[-1])
    forged_next["seq"] = 7  # signed? no — but gap check fires BEFORE trust? no:
    # build a *validly signed* skip by writing a hand-rolled envelope chain:
    from eventstream.envelope import sign_envelope

    skip = sign_envelope({"n": 7}, topic="raw-events", key="default", seq=7,
                         source="t", secret=SECRET)
    src2_file.write_text(lines2[0] + "\n" + lines2[1] + "\n"
                         + json.dumps(skip) + "\n", encoding="utf-8")
    rep2 = Replicator(tmp_path / "region-src2", tmp_path / "region-dst2", SECRET)
    with pytest.raises(ReplicationGapError):
        rep2.ship_once("raw-events")
    # atomic batches: a failed batch persists NOTHING on the target
    assert len(_bus(tmp_path, "region-dst2").read("raw-events", "r")) == 0
    # repair the source (valid seq 3 replaces the forged skip) -> ships 3
    from eventstream.envelope import sign_envelope as _se

    fixed = _se({"n": 3}, topic="raw-events", key="default", seq=3,
                source="t", secret=SECRET)
    src2_file.write_text("\n".join([lines2[0], lines2[1],
                                     json.dumps(fixed)]) + "\n", encoding="utf-8")
    assert rep2.ship_once("raw-events") == 3
    assert len(_bus(tmp_path, "region-dst2").read("raw-events", "r")) == 3


def test_failover_region_b_continues_sequence(tmp_path):
    a, b = _bus(tmp_path, "region-a"), _bus(tmp_path, "region-b")
    for i in range(4):
        a.publish("raw-events", {"round": 1, "i": i})
    rep = Replicator(tmp_path / "region-a", tmp_path / "region-b", SECRET)
    rep.ship_once("raw-events")
    # REGION A DOWN. Promote B:
    set_write_role(tmp_path / "region-b", "primary")
    b2 = StreamBus(tmp_path / "region-b", secret=SECRET)  # loads replicated log
    env = b2.publish("raw-events", {"round": 2})
    assert env["seq"] == 5  # continuity across failover
    # when A returns as a replica, shipping B->A converges both regions
    set_write_role(tmp_path / "region-a", "replica")
    back = Replicator(tmp_path / "region-b", tmp_path / "region-a", SECRET)
    assert back.ship_once("raw-events") == 1
    a_seqs = [e["seq"] for e in StreamBus(tmp_path / "region-a", secret=SECRET)
              .read("raw-events", "r")]
    assert a_seqs == [1, 2, 3, 4, 5]


def test_pitr_snapshot_restore_replays_to_point_in_time(tmp_path):
    bus = _bus(tmp_path, "main")
    db = tmp_path / "estate.db"
    import sqlite3

    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE estate (k TEXT, v TEXT)")
    conn.execute("INSERT INTO estate VALUES ('at', 'T0')")
    conn.commit()
    bus.publish("raw-events", {"phase": "pre-snapshot"})
    snap = pitr_snapshot(db, tmp_path / "main", tmp_path / "snaps")
    # post-snapshot activity: db row + bus events with later timestamps
    conn.execute("INSERT INTO estate VALUES ('at', 'T1')")
    conn.commit()
    conn.close()
    late = _bus(tmp_path, "main")
    e1 = late.publish("raw-events", {"phase": "T1"})
    e2 = late.publish("cbom-updates", {"phase": "T2"})
    time.sleep(0.01)

    # restore to T1: db from snapshot + live-log replay up to (incl) e1
    from datetime import datetime

    upto = datetime.fromisoformat(e1["ts"]).timestamp()
    target = tmp_path / "restored"
    summary = pitr_restore(snap, tmp_path / "main", target, upto_epoch=upto,
                           secret=SECRET)
    assert summary["replayed"] == 1 and summary["beyond_recovery_point"] == 1
    restored_db = sqlite3.connect(str(target / "estate.db"))
    rows = restored_db.execute("SELECT v FROM estate").fetchall()
    restored_db.close()
    assert rows == [("T0",)]  # database is the snapshot point (T0)
    rb = StreamBus(target / "bus", secret=SECRET)
    seqs = [e["seq"] for e in rb.read("raw-events", "r")]
    assert seqs == [1, 2]  # pre-snapshot event + the T1 event
    # the T2 event (cbom-updates, beyond the recovery point) was excluded
    cbom_file = target / "bus" / "cbom-updates.jsonl"
    assert not cbom_file.exists() or not cbom_file.read_text().strip()
    # recovered bus accepts new writes with continuity
    nxt = StreamBus(target / "bus", secret=SECRET).publish("raw-events", {"again": 1})
    assert nxt["seq"] == 3


import time  # noqa: E402
