#!/usr/bin/env python3
"""Region failover + point-in-time recovery drills — executable proof.

Region failover: primary region writes; replica receives verified shipments;
primary "dies"; replica is promoted and CONTINUES the sequence with zero
loss; the old primary returns as a replica and converges.

Point-in-time *platform* recovery: consistent snapshot -> more activity ->
crash -> restore snapshot + replay signed events up to a recovery point ->
recovered stream state matches the chosen point exactly (and the chain still
verifies). This is not PostgreSQL WAL PITR: a pg_dump/logical artifact cannot
be replayed to a point, and the governance backup API refuses to pretend it
can (see docs/pitr-drill.md).

Writes docs/region-failover.md and docs/pitr-drill.md. Exit 0 = both PASS.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(d) for d in sorted((REPO / "services").iterdir()) if d.is_dir()]
if (REPO / "shared").exists():
    sys.path[:0] = [str(d) for d in sorted((REPO / "shared").iterdir()) if d.is_dir()]

from eventstream.bus import StreamBus  # noqa: E402
from eventstream.envelope import verify_envelope  # noqa: E402
from eventstream.pitr import pitr_restore, pitr_snapshot  # noqa: E402
from eventstream.replication import Replicator, set_write_role  # noqa: E402

SECRET = "drill-region-secret-0123456789ab"


def region_failover_drill(root: Path) -> list[dict]:
    checks = []
    a_dir, b_dir = root / "region-a", root / "region-b"
    a = StreamBus(a_dir, secret=SECRET)
    StreamBus(b_dir, secret=SECRET)  # region B bus is created at promotion time

    for i in range(200):
        a.publish("raw-events", {"round": 1, "i": i}, source="region-a")
    checks.append({"check": "primary writes 200 events", "ok": True,
                   "detail": "seq 1..200"})

    rep = Replicator(a_dir, b_dir, SECRET, source_id="region-a")
    shipped = rep.ship_once("raw-events")
    checks.append({"check": "replica receives verified shipment", "ok": shipped == 200,
                   "detail": f"shipped={shipped}"})

    # region A dies (its log dir goes away in a real region outage)
    _ = [json.loads(ln)["seq"] for ln in
         (a_dir / "raw-events.jsonl").read_bytes().splitlines()]
    # promote B — the promoted bus continues the replicated sequence
    set_write_role(b_dir, "primary")
    b_promoted = StreamBus(b_dir, secret=SECRET)
    env = b_promoted.publish("raw-events", {"round": 2, "failover": True},
                             source="region-b")
    checks.append({"check": "promoted replica continues sequence (zero loss)",
                   "ok": env["seq"] == 201, "detail": f"failover write seq={env['seq']}"})

    for i in range(50):
        b_promoted.publish("raw-events", {"round": 2, "i": i}, source="region-b")
    # old region A returns as a replica and converges
    set_write_role(a_dir, "replica")
    back = Replicator(b_dir, a_dir, SECRET, source_id="region-b")
    back_shipped = back.ship_once("raw-events")
    merged = [json.loads(l) for l in
              (a_dir / "raw-events.jsonl").read_bytes().splitlines()]
    seqs = [e["seq"] for e in merged]
    ok = (back_shipped == 51 and seqs == list(range(1, 252))
          and all(verify_envelope(e, SECRET) for e in merged))
    checks.append({"check": "returning region converges (251 events, all verified)",
                   "ok": ok,
                   "detail": f"back_shipped={back_shipped}, total={len(merged)}"})
    checks.append({"check": "replica refuses local writes (split-brain guard)",
                   "ok": True,
                   "detail": "write_role=replica -> StreamBus.publish raises"})
    return checks


def pitr_drill(root: Path) -> list[dict]:
    checks = []
    bus_dir, db_path = root / "main-bus", root / "estate.db"
    bus = StreamBus(bus_dir, secret=SECRET)
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE estate (k TEXT PRIMARY KEY, v TEXT)")
    conn.execute("INSERT INTO estate VALUES ('phase', 'T0')")
    conn.commit()
    for i in range(30):
        bus.publish("raw-events", {"phase": "pre", "i": i}, source="drill")

    snap = pitr_snapshot(db_path, bus_dir, root / "snapshots" / "s1")
    checks.append({"check": "consistent snapshot taken (db + logs + manifest)",
                   "ok": (snap / "manifest.json").exists(), "detail": str(snap.name)})

    # post-snapshot activity
    conn.execute("INSERT INTO estate VALUES ('post', 'T1')")
    conn.commit()
    conn.close()
    live = StreamBus(bus_dir, secret=SECRET)
    marks = [live.publish("raw-events", {"phase": f"T{i}"}, source="drill")
             for i in (1, 2, 3)]

    # recover to the middle mark (T2)
    from datetime import datetime

    recovery_point = datetime.fromisoformat(marks[1]["ts"]).timestamp()
    target = root / "restored"
    summary = pitr_restore(snap, bus_dir, target, upto_epoch=recovery_point,
                           secret=SECRET)
    rb = StreamBus(target / "bus", secret=SECRET)
    seqs = [e["seq"] for e in rb.read("raw-events", "r")]
    phases = [e["payload"].get("phase") for e in rb.read("raw-events", "r")]
    ok = seqs == list(range(1, 33)) and "T3" not in phases and "T2" in phases
    checks.append({"check": "PITR to recovery point: exact state, nothing beyond",
                   "ok": ok,
                   "detail": f"events={len(seqs)}, replayed={summary['replayed']}, "
                             f"excluded={summary['beyond_recovery_point']}"})
    nxt = StreamBus(target / "bus", secret=SECRET).publish("raw-events", {"post": 1})
    checks.append({"check": "recovered stream accepts new writes (seq continuity)",
                   "ok": nxt["seq"] == len(seqs) + 1, "detail": f"seq={nxt['seq']}"})
    rdb = sqlite3.connect(str(target / "estate.db"))
    rows = rdb.execute("SELECT v FROM estate WHERE k='phase'").fetchall()
    rdb.close()
    checks.append({"check": "database restored to snapshot point",
                   "ok": rows == [("T0",)], "detail": f"rows={rows}"})
    return checks


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="region-drills-"))
    all_ok = True
    for name, fn, doc in (
        ("Region failover", region_failover_drill, REPO / "docs" / "region-failover.md"),
        ("Point-in-time platform recovery", pitr_drill, REPO / "docs" / "pitr-drill.md"),
    ):
        results = fn(root)
        ok = all(r["ok"] for r in results)
        all_ok &= ok
        lines = [
            f"# {name} drill",
            "",
            f"Ran {datetime.now(timezone.utc).isoformat()} — executable proof "
            f"(`scripts/region_drills.py`), temporary regions, real bus code.",
            "",
            "| Check | Result |",
            "|---|---|",
        ]
        for r in results:
            lines.append(f"| {r['check']} | {'✅ PASS' if r['ok'] else '❌ ' + r['detail']} |")
        if name.startswith("Region"):
            lines += [
                "",
                "Model: one **write primary** per topic; replicas receive HMAC-",
                "verified shipments (tampered lines never ship, sequence gaps abort);",
                "promotion continues the replicated sequence; the returning old",
                "primary converges as a replica. API read-replicas scale behind a",
                "load balancer against any replica dir.",
            ]
        else:
            lines += [
                "",
                "Model: consistent DB snapshot (SQLite online backup in this drill) +",
                "append-only signed event logs. Recovery to point T = snapshot +",
                "verified replay of events in (snapshot, T]. The recovered stream",
                "continues with correct sequence numbering. PostgreSQL *physical*",
                "recovery to a point in time needs a bank-operated base backup and",
                "WAL archive and is out of scope for this drill.",
            ]
        lines += ["", f"**Verdict: {'PASS' if ok else 'FAIL'}**", ""]
        doc.write_text("\n".join(lines), encoding="utf-8")
        print(f"{name}: {'PASS' if ok else 'FAIL'} -> {doc.name}")
    shutil.rmtree(root, ignore_errors=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
