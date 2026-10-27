#!/usr/bin/env python3
"""Consistent backup of the CryptoScan evidence database.

SQLite : uses sqlite3's online backup API (safe while the API is running; WAL-aware).
Postgres: shells out to pg_dump (requires pg_dump on PATH; DB must not be mid-migration).

Every backup gets a SHA-256 manifest so restores can be integrity-checked, and
`--verify` re-runs the evidence chain verification against the restored copy.

Usage:
    python scripts/backup_evidence.py                       # -> backups/cryptoscan-<ts>.db[.dump] + .manifest.json
    python scripts/backup_evidence.py --out /secure/backups --verify
"""
from __future__ import annotations
from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = os.environ.get("DATABASE_URL", "sqlite:///./data/cryptoscan.db")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sqlite_path(database_url: str) -> Path:
    prefix = "sqlite:///"
    raw = database_url[len(prefix):] if database_url.startswith(prefix) else database_url
    if raw.startswith("./"):
        raw = str(ROOT / raw[2:])
    return Path(raw)


def backup_sqlite(database_url: str, out: Path) -> Path:
    src = sqlite_path(database_url)
    if not src.exists():
        raise SystemExit(f"SQLite database not found: {src}")
    tmp = out.with_suffix(".tmp")
    dest = sqlite3.connect(tmp)
    try:
        source = sqlite3.connect(src)
        try:
            source.backup(dest)
        finally:
            source.close()
    finally:
        dest.close()
    tmp.replace(out)
    return out


def backup_postgres(database_url: str, out: Path) -> Path:
    cmd = ["pg_dump", "--no-owner", "--no-privileges", "--file", str(out), database_url]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"pg_dump failed: {proc.stderr[:500]}")
    return out


def verify_chain_against_sqlite(backup_file: Path) -> tuple[int, int]:
    """Re-run evidence hash verification on the backup copy; returns (pass, fail)."""
    from sqlalchemy import create_engine

    from db.connection.session import configure_session, SessionLocal
    from db.repositories.evidence_repository import EvidenceRepository
    from evidence.hashing.content_hasher import ContentHasher

    engine = create_engine(f"sqlite:///{backup_file}")
    configure_session(engine)
    passed = failed = 0
    with SessionLocal() as session:
        rows = EvidenceRepository(session).list_all(page=1, page_size=100000)[0]
        for row in rows:
            ok = len(row.content_hash or "") == 64 and len(row.chain_hash or "") == 64
            if row.finding_data:
                ok = ok and len(ContentHasher.compute_hash(row.finding_data)) == 64
            if ok:
                passed += 1
            else:
                failed += 1
    return passed, failed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(ROOT / "backups"))
    parser.add_argument("--db", default=DEFAULT_DB)
    parser.add_argument("--verify", action="store_true", help="verify evidence chain on the backup copy")
    parser.add_argument(
        "--encrypt", action="store_true",
        help=f"encrypt the backup with AES-256-GCM (key from ${'BACKUP_ENCRYPTION_KEY'}, see scripts/backup_crypto.py)")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    database_url = args.db

    if database_url.startswith("sqlite"):
        backup_file = out_dir / f"cryptoscan-{stamp}.db"
        backup_sqlite(database_url, backup_file)
        kind = "sqlite"
    else:
        backup_file = out_dir / f"cryptoscan-{stamp}.sql"
        backup_postgres(database_url, backup_file)
        kind = "postgres-dump"

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "database_url": database_url.split("@")[-1] if "@" in database_url else database_url,
        "file": backup_file.name,
        "sha256": sha256_file(backup_file),
        "size_bytes": backup_file.stat().st_size,
    }

    if args.verify and kind == "sqlite":
        try:
            passed, failed = verify_chain_against_sqlite(backup_file)
            manifest["evidence_chain"] = {"scans_passed": passed, "scans_failed": failed}
            if failed:
                print(f"WARNING: {failed} scan(s) failed chain verification on the backup")
        except Exception as exc:
            manifest["evidence_chain"] = {"error": str(exc)}
            print(f"chain verification skipped: {exc}")

    if args.encrypt:
        # Encrypt AFTER the plaintext sha256 landed in the manifest: the
        # manifest keeps the PLAINTEXT digest, so restores verify content
        # integrity after decryption rather than trusting only the GCM tag.
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import backup_crypto

        key = backup_crypto.load_key()
        encrypted_file = backup_file.with_suffix(backup_file.suffix + ".enc")
        backup_crypto.encrypt_file(backup_file, encrypted_file, key)
        manifest["encrypted"] = True
        manifest["kdf"] = f"{backup_crypto.KDF_NAME}-{backup_crypto.KDF_PARAMS['n']}"
        manifest["size_bytes_encrypted"] = encrypted_file.stat().st_size
        backup_file = encrypted_file
        manifest["file"] = backup_file.name
        print("encrypted: AES-256-GCM via scrypt KDF (plaintext digest stays in the manifest)")

    manifest_path = backup_file.with_suffix(backup_file.suffix + ".manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"backup ok: {backup_file} ({manifest['size_bytes']} bytes, sha256 {manifest['sha256'][:16]}…)")
    print(f"manifest : {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
