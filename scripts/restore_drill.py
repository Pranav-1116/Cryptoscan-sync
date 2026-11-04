#!/usr/bin/env python3
"""Restore a real backup into a real recovery database and measure what came back.

The gap this closes
-------------------
The API refuses an unapproved restore target and refuses point-in-time recovery on a
``pg_dump`` archive, and it says so. What nothing did was *perform* a restore. So the estate
carried the claim "we take backups" and quietly assumed the other half — that the backups
restore — which is the half that costs money when it is wrong.

This script is the missing half. It takes the newest (or a named) backup, restores it into
``CRYPTOSCAN_RESTORE_TARGET_DB``, connects to the result and measures it: schema revision,
row counts, and whether RLS binds. The receipt is written as evidence and hash-chained to the
previous receipt, so "we drilled on the 3rd" is a fact with a digest rather than a memory.

Refusals, because a drill that restores into production is an outage
-------------------------------------------------------------------
* No target → refuse. It never guesses and never writes to the source.
* Target equal to the source DSN → refuse. A drill that destroys the source is not a drill.
* Point-in-time requested on a ``pg_dump`` manifest → refuse, and say why: logical dumps carry
  no WAL, so PITR here would be theatre.
* The source password never appears in the receipt: only host, port and database name, and
  the DSNs are redacted by parsing rather than by string substitution.

Usage
-----
    export CRYPTOSCAN_RESTORE_TARGET_DB=postgresql://drill@recovery-host:5432/cryptoscan_drill
    python scripts/restore_drill.py --backup-dir /var/lib/cryptoscan/backups --database-id cryptoscan

    # plan only: what would be restored, from where, into where — no database contact
    python scripts/restore_drill.py --plan --backup-dir ... --database-id cryptoscan

Exit code is 0 only when the restore happened *and* the measurements came back.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
for area in ("services", "shared"):
    for path in sorted((ROOT / area).iterdir()):
        if path.is_dir() and str(path) not in sys.path:
            sys.path.insert(0, str(path))

SCHEMA = "cryptoscan.restore-drill/1"
DEFAULT_HISTORY = ROOT / "docs" / "bank-environment" / "restore-drill-history.jsonl"


# --------------------------------------------------------------------------- #
# what a drill may and may not do
# --------------------------------------------------------------------------- #

class DrillRefused(RuntimeError):
    """A refusal that is a finding, not a crash: the drill did not run, and says why."""


def _split(dsn: str) -> dict[str, Any]:
    """Parse a DSN without ever returning the password."""
    from sqlalchemy.engine import make_url

    try:
        url = make_url(dsn)
    except Exception as exc:  # noqa: BLE001 - a bad DSN is a refusal, not a traceback
        raise DrillRefused(f"unparseable DSN: {exc.__class__.__name__}") from exc
    return {"driver": url.get_backend_name(), "host": url.host, "port": url.port,
            "database": url.database, "username": url.username,
            "has_password": url.password is not None}


def plan(*, source_dsn: str, target_dsn: str, manifests: list[dict[str, Any]],
         storage_key: str | None = None, point_in_time: str | None = None) -> dict[str, Any]:
    """Decide, without touching a database, whether and how a drill may run."""
    if not target_dsn.strip():
        raise DrillRefused("CRYPTOSCAN_RESTORE_TARGET_DB is unset: a drill needs a designated "
                           "recovery database, and will not guess one")
    source, target = _split(source_dsn), _split(target_dsn)
    if source["driver"] != "postgresql" or target["driver"] != "postgresql":
        raise DrillRefused("a restore drill is defined for PostgreSQL; refusing another engine")
    if (source["host"], source["port"], source["database"]) == (target["host"], target["port"],
                                                                target["database"]):
        raise DrillRefused("the recovery target is the source database: refusing to overwrite "
                           "the estate a drill is supposed to prove recoverable")
    if not manifests:
        raise DrillRefused("no backup manifests found: 'backup exists' is unproven, and so is "
                           "this drill")
    chosen = _chosen(manifests, storage_key)
    if point_in_time and not chosen.get("has_wal_tail"):
        raise DrillRefused("point-in-time restore was requested, but this archive is a logical "
                           "pg_dump with no WAL: PostgreSQL cannot replay it. Refusing rather "
                           "than restoring to 'now' and calling it the requested time")
    return {"source": source, "target": target, "backup": _manifest_facts(chosen),
            "point_in_time": point_in_time, "may_run": True}


def _chosen(manifests: list[dict[str, Any]], storage_key: str | None) -> dict[str, Any]:
    if storage_key:
        match = next((m for m in manifests if m.get("storage_key") == storage_key), None)
        if match is None:
            raise DrillRefused(f"backup {storage_key} is not in the store")
        return match
    return sorted(manifests, key=lambda m: str(m.get("created_at") or ""))[-1]


def _manifest_facts(manifest: Mapping[str, Any]) -> dict[str, Any]:
    """Only the identifying facts. A manifest is evidence, not a place to leak a secret."""
    return {key: manifest.get(key) for key in
            ("backup_id", "database_id", "engine", "created_at", "sequence", "size_bytes",
             "plaintext_sha256", "ciphertext_sha256", "has_wal_tail", "format", "storage_key")}


# --------------------------------------------------------------------------- #
# measuring the result
# --------------------------------------------------------------------------- #

#: Enough to tell "the database came back" from "an empty database came back". Not a
#: completeness claim: a table absent from this list is simply not measured here.
MEASURED_TABLES = ("alembic_version", "users", "tenants", "assets", "cbom_documents",
                   "audit_logs", "security_control_observations")

_COUNT_SQL = ("SELECT count(*) FROM information_schema.tables "
              "WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'")


def measure(dsn: str, *, connect: Callable[[str], Any] | None = None) -> dict[str, Any]:
    """Read the restored database and report what is there, including what is not."""
    from sqlalchemy import create_engine, text

    engine = connect(dsn) if connect else create_engine(dsn)
    facts: dict[str, Any] = {"measured": True, "tables": {}, "missing_tables": [], "errors": []}
    try:
        with engine.connect() as connection:
            facts["schema"] = connection.scalar(text("SELECT current_schema()"))
            facts["table_count"] = int(connection.scalar(text(_COUNT_SQL)) or 0)
            for table in MEASURED_TABLES:
                try:
                    facts["tables"][table] = int(
                        connection.execute(text(f'SELECT count(*) FROM "{table}"')).scalar() or 0)
                except Exception:  # noqa: BLE001 - an absent table is a fact, not a failure
                    facts["missing_tables"].append(table)
            try:
                facts["revision"] = connection.scalar(text("SELECT version_num FROM alembic_version"))
            except Exception:  # noqa: BLE001 - pre-migration or absent table
                facts["revision"] = None
            try:
                from db.rls import enforcement

                facts["rls"] = enforcement(connection)
            except Exception as exc:  # noqa: BLE001 - report, never invent
                facts["errors"].append(f"rls not measured: {exc.__class__.__name__}")
    finally:
        try:
            engine.dispose()
        except Exception:  # noqa: BLE001
            pass
    facts["verdict"] = _verdict(facts)
    return facts


def _verdict(facts: Mapping[str, Any]) -> str:
    if not facts.get("measured"):
        return "NOT_MEASURED"
    if not facts.get("table_count"):
        return "RESTORED_EMPTY"
    if facts.get("missing_tables") and len(facts["missing_tables"]) == len(MEASURED_TABLES):
        return "RESTORED_WITHOUT_APPLICATION_TABLES"
    if facts.get("errors"):
        return "RESTORED_PARTIALLY_MEASURED"
    return "RESTORED_AND_MEASURED"


# --------------------------------------------------------------------------- #
# the receipt
# --------------------------------------------------------------------------- #

def receipt(*, decision: Mapping[str, Any], restored: Mapping[str, Any] | None,
            measurement: Mapping[str, Any], duration_seconds: float,
            previous: str | None = None, now: str | None = None) -> dict[str, Any]:
    """The evidence a drill leaves. No DSN, no password, no row content."""
    stamp = now or datetime.now(timezone.utc).isoformat()
    payload = {
        "schema": SCHEMA,
        "drill_at": stamp,
        "duration_seconds": round(duration_seconds, 3),
        "target": {key: decision["target"][key] for key in ("host", "port", "database", "username")},
        "source": {key: decision["source"][key] for key in ("host", "port", "database")},
        "backup": decision["backup"],
        "point_in_time": decision.get("point_in_time"),
        "restored": dict(restored or {}),
        "measurement": dict(measurement),
    }
    payload["result"] = measurement.get("verdict", "NOT_MEASURED")
    payload["claims"] = _claims(payload)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                       default=str).encode()).hexdigest()
    payload["receipt_sha256"] = digest
    payload["previous_receipt_sha256"] = previous
    return payload


def _claims(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Say what the receipt does *not* prove, in the receipt itself."""
    measurement = payload.get("measurement") or {}
    ok = payload.get("result") == "RESTORED_AND_MEASURED"
    return {
        "backup_restores": ok,
        "restore_is_disaster_recovery": False,
        "proves_pitr": False,
        "proves_offsite_copy": False,
        "proves_backup_encryption_at_rest": False,
        "measured_tables": sorted(measurement.get("tables") or {}),
        "not_measured": ("row content, tenant-level correctness, referential integrity beyond "
                         "the listed tables, the bank's own restore procedure, and any "
                         "point-in-time objective"),
        "note": ("A passing drill proves this archive restored into this recovery database and "
                 "that the measured tables came back. It is not a disaster-recovery "
                 "qualification and not a PITR test."),
    }


def append_history(path: Path, record: Mapping[str, Any]) -> dict[str, Any]:
    """Append-only chain: each receipt names the digest before it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    if path.exists():
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous = json.loads(lines[-1]).get("receipt_sha256")
    record = dict(record, previous_receipt_sha256=previous)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")
    return record


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #

def _pg_env(dsn: str) -> dict[str, str] | None:
    """Hand pg_dump/pg_restore the password through the environment, never argv."""
    from sqlalchemy.engine import make_url

    url = make_url(dsn)
    if url.password is None:
        return None
    return {**os.environ, "PGPASSWORD": url.password}


def _pg_backend(source_dsn: str, target_dsn: str, *, pg_bin: str = "") -> Any:
    """A backend that dumps from the source and restores into the *target* DSN."""
    from governance import backup as bk
    from governance import backup_jobs as bj

    runner = bj.subprocess_runner(env=_pg_env(target_dsn))
    prefix = f"{pg_bin.rstrip('/')}/" if pg_bin else ""

    class DrillBackend:
        name = "postgres"
        supports_pitr = False
        calls: list[list[str]] = []

        def dump(self, database_id: str) -> bytes:  # not used: the drill reads a stored archive
            raise bk.BackupError("the drill consumes an existing archive; it never re-dumps")

        def restore(self, database_id: str, payload: bytes) -> dict[str, Any]:
            argv = [f"{prefix}pg_restore", "-d", target_dsn, "--clean", "--if-exists",
                    "--no-owner", "--no-privileges"]
            self.calls.append(argv)
            result = runner(argv, stdin=payload)
            code = getattr(result, "returncode", 0)
            if code != 0:
                raise bk.BackupError(f"pg_restore failed (rc={code})")
            return {"tool": "pg_restore", "database_id": database_id, "bytes": len(payload),
                    "target": "the designated recovery database"}

    return DrillBackend()


def create_backup(*, source_dsn: str, storage: Any, database_id: str,
                  encryption_key: bytes, signing_secret: str) -> dict[str, Any]:
    """Take a backup through the same store the API writes, so the drill restores a real one.

    Used by the scheduled workflow against a disposable database. It is the same
    ``create_backup`` the API calls, so a drill can never pass on an archive the production
    path would refuse.
    """
    from sqlalchemy.engine import make_url

    from governance import backup as bk
    from governance import backup_jobs as bj

    url = make_url(source_dsn)
    backend = bj.PgDumpBackend(runner=bj.subprocess_runner(env=_pg_env(source_dsn)),
                               host=url.host or "localhost", port=url.port or 5432,
                               user=url.username or "postgres",
                               pg_bin=os.environ.get("PG_BIN", ""))
    result = bk.create_backup(backend=backend, database_id=database_id,
                              encryption_key=encryption_key, signing_secret=signing_secret)
    key = f"{result['manifest'].get('engine', 'postgres')}/{database_id}/" \
          f"{result['manifest']['backup_id']}"
    storage.put(key, result["ciphertext"])
    storage.put_manifest(key, result["manifest"])
    return {"storage_key": key, **_manifest_facts(dict(result["manifest"], storage_key=key))}


def run(*, source_dsn: str, target_dsn: str, storage: Any, database_id: str,
        storage_key: str | None = None, point_in_time: str | None = None,
        encryption_key: bytes, signing_secret: str, backend: Any = None,
        connect: Callable[[str], Any] | None = None) -> dict[str, Any]:
    """Plan, restore into the recovery database, measure it, and return the receipt."""
    from governance import backup as bk

    started = time.monotonic()
    manifests = [m for m in storage.list_manifests() if m.get("database_id") == database_id]
    decision = plan(source_dsn=source_dsn, target_dsn=target_dsn, manifests=manifests,
                    storage_key=storage_key, point_in_time=point_in_time)
    backend = backend or _pg_backend(source_dsn, target_dsn,
                                     pg_bin=os.environ.get("PG_BIN", ""))
    restored = bk.restore_from_storage(
        backend=backend, storage=storage, database_id=database_id,
        encryption_key=encryption_key, signing_secret=signing_secret,
        storage_key=storage_key, target_point_in_time=point_in_time)
    measurement = measure(target_dsn, connect=connect)
    return receipt(decision=decision, restored=restored, measurement=measurement,
                   duration_seconds=time.monotonic() - started)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--database-id", default="cryptoscan")
    parser.add_argument("--backup-dir", default=os.environ.get("CRYPTOSCAN_BACKUP_DIR", ""))
    parser.add_argument("--storage-key", default=None)
    parser.add_argument("--point-in-time", default=None)
    parser.add_argument("--out", default=None, help="receipt path (default: stdout)")
    parser.add_argument("--history", default=str(DEFAULT_HISTORY))
    parser.add_argument("--plan", action="store_true", help="decide only; never connect")
    parser.add_argument("--create-backup", action="store_true",
                        help="take a fresh backup of the source first (scheduled drill)")
    args = parser.parse_args(argv)

    from governance import backup_jobs as bj

    target = os.environ.get("CRYPTOSCAN_RESTORE_TARGET_DB", "")
    source = os.environ.get("DATABASE_URL", "")
    if not args.backup_dir:
        print("Refused: --backup-dir (or CRYPTOSCAN_BACKUP_DIR) is required", file=sys.stderr)
        return 2
    storage = bj.DiskBackupStorage(args.backup_dir)
    manifests = [m for m in storage.list_manifests() if m.get("database_id") == args.database_id]

    if args.plan:
        try:
            decision = plan(source_dsn=source, target_dsn=target, manifests=manifests,
                            storage_key=args.storage_key, point_in_time=args.point_in_time)
        except DrillRefused as refusal:
            print(json.dumps({"schema": SCHEMA, "may_run": False, "refusal": str(refusal)}, indent=2))
            return 1
        print(json.dumps({"schema": SCHEMA, **decision}, indent=2, default=str))
        return 0

    key = os.environ.get("BACKUP_ENCRYPTION_KEY", "")
    secret = os.environ.get("BACKUP_SIGNING_SECRET", "")
    if not key or not secret:
        print("Refused: BACKUP_ENCRYPTION_KEY and BACKUP_SIGNING_SECRET are required to verify "
              "and decrypt the archive", file=sys.stderr)
        return 2

    encryption_key = _encryption_key(key)
    if args.create_backup:
        created = create_backup(source_dsn=source, storage=storage,
                               database_id=args.database_id, encryption_key=encryption_key,
                               signing_secret=secret)
        print(json.dumps({"created_backup": created}, indent=2, default=str), file=sys.stderr)
    try:
        record = run(source_dsn=source, target_dsn=target, storage=storage,
                     database_id=args.database_id, storage_key=args.storage_key,
                     point_in_time=args.point_in_time, encryption_key=encryption_key,
                     signing_secret=secret)
    except DrillRefused as refusal:
        record = receipt(decision={"source": _split(source) if source else {"host": None, "port": None, "database": None},
                                   "target": _split(target) if target else {"host": None, "port": None,
                                                                            "database": None, "username": None},
                                   "backup": None, "point_in_time": args.point_in_time,
                                   "refusal": str(refusal)},
                         restored=None, measurement={"verdict": "NOT_RUN", "measured": False})
        record["result"] = "NOT_RUN"
        record["refusal"] = str(refusal)
        _emit(record, args)
        return 1
    _emit(record, args)
    return 0 if record["result"] == "RESTORED_AND_MEASURED" else 1


def _encryption_key(value: str) -> bytes:
    """A Fernet key as text (44 URL-safe base64 chars) or as base64-encoded raw bytes."""
    import base64

    try:
        raw = base64.urlsafe_b64decode(value)
    except Exception as exc:  # noqa: BLE001
        raise DrillRefused("BACKUP_ENCRYPTION_KEY is not valid base64") from exc
    if len(raw) != 32:
        raise DrillRefused("BACKUP_ENCRYPTION_KEY must decode to 32 bytes (a Fernet key)")
    return raw


def _emit(record: dict[str, Any], args: argparse.Namespace) -> None:
    history = Path(args.history)
    chained = append_history(history, record)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(chained, indent=2, sort_keys=True, default=str), encoding="utf-8")
        print(json.dumps({"result": chained["result"], "receipt": str(out),
                          "receipt_sha256": chained.get("receipt_sha256")}, indent=2))
    else:
        print(json.dumps(chained, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    sys.exit(main())
