"""Point-in-time recovery for the durable trio.

Snapshot = consistent database image (SQLite online backup API) + a copy of
the append-only bus logs + a manifest. Restore to a recovery point T =
database from the snapshot + bus logs TRUNCATED to events whose timestamp is
<= T. Because the bus is append-only and every envelope is timestamped and
signed, truncation is exact: the recovered stream continues with correct
sequence numbering (the bus rebuilds its state from the log on load).

Postgres production deployments replace the file copy with pg_basebackup /
WAL archiving; the stream-side truncation-replay is identical.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from eventstream.envelope import verify_envelope

MANIFEST = "manifest.json"


def _ts_epoch(envelope: dict) -> float:
    try:
        return datetime.fromisoformat(str(envelope["ts"])).timestamp()
    except (KeyError, ValueError, TypeError):
        return 0.0


def pitr_snapshot(db_path: Path | str, bus_dir: Path | str,
                  out_dir: Path | str) -> Path:
    """Consistent snapshot: online DB image + full bus logs + manifest."""
    db_path, bus_dir, out_dir = Path(db_path), Path(bus_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    src = sqlite3.connect(str(db_path))
    dst = sqlite3.connect(str(out_dir / "estate.db"))
    src.backup(dst)
    dst.close()
    src.close()

    bus_out = out_dir / "bus"
    if bus_dir.exists():
        shutil.copytree(bus_dir, bus_out,
                        ignore=shutil.ignore_patterns("write_role.json"))

    manifest = {
        "snapshot_epoch": time.time(),
        "snapshot_iso": datetime.now(timezone.utc).isoformat(),
        "db_bytes": (out_dir / "estate.db").stat().st_size,
        "topics": sorted(f.name for f in bus_out.glob("*.jsonl")) if bus_out.exists() else [],
    }
    (out_dir / MANIFEST).write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return out_dir


def pitr_restore(snapshot_dir: Path | str, live_bus_dir: Path | str,
                 target_dir: Path | str, *,
                 upto_epoch: float | None = None,
                 secret: str | None = None) -> dict:
    """Rebuild a working environment at a recovery point.

    target = snapshot database + snapshot bus logs + (replay) events from the
    LIVE bus log whose timestamp is in ``(snapshot_epoch, upto_epoch]``.
    With ``upto_epoch=None`` everything the live log has is replayed
    (latest state). When ``secret`` is given, replayed lines are verified
    (HMAC) before being applied — tampered lines never enter recovery.
    Returns a summary.
    """
    snapshot_dir = Path(snapshot_dir)
    target_dir = Path(target_dir)
    if not (snapshot_dir / MANIFEST).exists():
        raise FileNotFoundError(f"not a snapshot dir: {snapshot_dir}")
    manifest = json.loads((snapshot_dir / MANIFEST).read_text())
    snapshot_epoch = float(manifest["snapshot_epoch"])
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(snapshot_dir / "estate.db", target_dir / "estate.db")

    # snapshot-state bus logs
    kept = dropped = replayed = 0
    src_bus = snapshot_dir / "bus"
    dst_bus = target_dir / "bus"
    dst_bus.mkdir(parents=True, exist_ok=True)
    if src_bus.exists():
        for topic_file in sorted(src_bus.glob("*.jsonl")):
            shutil.copy(topic_file, dst_bus / topic_file.name)
            kept += sum(1 for l in topic_file.read_bytes().splitlines() if l.strip())

    # replay window from the live log: (snapshot_epoch, upto_epoch]
    live_bus = Path(live_bus_dir)
    if live_bus.exists():
        for topic_file in sorted(live_bus.glob("*.jsonl")):
            out = dst_bus / topic_file.name
            for line in topic_file.read_bytes().splitlines(keepends=True):
                if not line.strip():
                    continue
                try:
                    envelope = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = _ts_epoch(envelope)
                if ts <= snapshot_epoch:
                    continue  # already in the snapshot
                if upto_epoch is not None and ts > upto_epoch:
                    dropped += 1
                    continue
                if secret is not None and not verify_envelope(envelope, secret):
                    raise ValueError(
                        f"tampered line refused during PITR replay "
                        f"(topic={topic_file.name} seq={envelope.get('seq')})")
                with out.open("ab") as fh:
                    fh.write(line if line.endswith(b"\n") else line + b"\n")
                replayed += 1
    return {"target": str(target_dir), "snapshot_events": kept,
            "replayed": replayed, "beyond_recovery_point": dropped,
            "upto_epoch": upto_epoch}
