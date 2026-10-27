#!/usr/bin/env python3
"""Restore a CryptoScan backup produced by backup_evidence.py.

Verifies the SHA-256 manifest before touching anything, restores into a
staging file, and only then swaps it into place (SQLite). Postgres restores
replay the SQL dump via psql.

Usage:
    python scripts/restore_evidence.py backups/cryptoscan-<ts>.db            # SQLite
    python scripts/restore_evidence.py backups/cryptoscan-<ts>.sql --db postgresql://...
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", help="backup file (.db or .sql)")
    parser.add_argument("--db", default=None, help="target DATABASE_URL (default: current env or sqlite default)")
    parser.add_argument("--force", action="store_true", help="skip manifest check when manifest is missing")
    args = parser.parse_args()

    backup = Path(args.backup)
    if not backup.exists():
        raise SystemExit(f"backup not found: {backup}")

    manifest_path = backup.with_suffix(backup.suffix + ".manifest.json")
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        actual = sha256_file(backup)
        if actual != manifest.get("sha256"):
            raise SystemExit(f"INTEGRITY FAILURE: sha256 mismatch — backup corrupted\n  expected {manifest.get('sha256')}\n  actual   {actual}")
        print(f"manifest ok (sha256 {actual[:16]}…)")
    elif not args.force:
        raise SystemExit("manifest missing — rerun with --force to restore anyway")

    database_url = args.db
    if database_url is None:
        import os

        database_url = os.environ.get("DATABASE_URL", "sqlite:///./data/cryptoscan.db")

    if database_url.startswith("sqlite"):
        raw = database_url.replace("sqlite:///", "", 1)
        target = Path(raw if not raw.startswith("./") else str(ROOT / raw[2:]))
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = target.with_suffix(".restore-tmp")
        shutil.copy2(backup, staging)
        # Sanity-check the copy opens as a valid SQLite database before swap.
        conn = sqlite3.connect(staging)
        try:
            tables = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            if tables < 5:
                raise SystemExit(f"restore aborted: backup has only {tables} tables — wrong file?")
        finally:
            conn.close()
        if target.exists():
            rotated = target.with_suffix(".pre-restore.bak")
            shutil.copy2(target, rotated)
            print(f"existing db rotated to {rotated}")
        staging.replace(target)
        print(f"restored SQLite database -> {target}")
        print("restart the API and worker, then run scripts/verify_evidence.py on critical scans")
        return 0

    # Postgres path
    cmd = ["psql", "--single-transaction", "--file", str(backup), database_url]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"psql restore failed: {proc.stderr[:500]}")
    print("restored Postgres database (verify with a migration check: alembic current)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
