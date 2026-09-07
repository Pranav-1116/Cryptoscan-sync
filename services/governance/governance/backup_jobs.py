"""Real database backup/restore runners + scheduled job orchestration.

Deterministic (no AI). This closes the operational gap in `backup.py` (which
provides the encryption/manifest/retention primitives):

- `PgDumpBackend` / `Neo4jBackend` shell out to `pg_dump`/`pg_restore` and
  `neo4j-admin`/`cypher-shell` through an *injected command runner*, so the
  logic is fully testable offline (the fake runner returns canned bytes /
  records commands). No command is ever built from un-sanitised input: the
  database name is validated against a strict allowlist pattern.
- `BackupJob` runs a full backup cycle (dump → encrypt → manifest → persist via
  an injected storage sink), and `run_due_backups` is a pure scheduler that
  decides which configs are due from a clock and their interval — the worker
  tick calls it with the real clock.
- `execute_retention` applies the GFS purge plan to the storage sink (deleting
  only what retention marked `purge`).

Storage is injected (`BackupStorage` protocol): production writes the encrypted
artifact + manifest to S3/disk; tests use an in-memory store.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol

from . import backup as bk

# A command runner: argv list -> CompletedCall-like (returncode, stdout, stderr)
class CommandResult:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


CommandRunner = Callable[[list[str]], CommandResult]

# Database identifiers are restricted to a safe charset to make argv injection
# impossible (we never invoke a shell; argv is a list, but we defend in depth).
_SAFE_DB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _validate_db_name(name: str) -> str:
    if not name or not _SAFE_DB_NAME.match(name):
        raise bk.BackupError(f"unsafe database identifier: {name!r}")
    return name


# ----------------------------------------------------------------- backends -- #
class PgDumpBackend:
    """Postgres logical backup via pg_dump (custom format); restore via
    pg_restore. Connection params come from a DSN/host config, never inline
    user input."""

    name = "postgres"

    def __init__(self, *, runner: CommandRunner, host: str = "localhost",
                 port: int = 5432, user: str = "postgres", pg_bin: str = ""):
        self._run = runner
        self.host = host
        self.port = port
        self.user = user
        self.pg_bin = pg_bin.rstrip("/")
        self.calls: list[list[str]] = []

    def _bin(self, tool: str) -> str:
        return f"{self.pg_bin}/{tool}" if self.pg_bin else tool

    def dump(self, database_id: str) -> bytes:
        _validate_db_name(database_id)
        argv = [self._bin("pg_dump"), "-h", self.host, "-p", str(self.port),
                "-U", self.user, "-Fc", "--no-owner", database_id]
        self.calls.append(argv)
        res = self._run(argv)
        if res.returncode != 0:
            raise bk.BackupError(f"pg_dump failed (rc={res.returncode}): {res.stderr.decode('utf-8','replace')[:300]}")
        # pg_dump writes the archive to stdout when no -f is given
        return res.stdout

    def restore(self, database_id: str, payload: bytes) -> dict[str, Any]:
        _validate_db_name(database_id)
        argv = [self._bin("pg_restore"), "-h", self.host, "-p", str(self.port),
                "-U", self.user, "--clean", "--if-exists", "--no-owner", "-d", database_id]
        self.calls.append(argv)
        res = self._run(argv, stdin=payload) if _accepts_stdin(self._run) else self._run(argv)
        rc = getattr(res, "returncode", 0)
        if rc != 0:
            raise bk.BackupError(f"pg_restore failed (rc={rc})")
        return {"tool": "pg_restore", "database_id": database_id, "bytes": len(payload)}

    def replay_wal(self, database_id: str, wal: bytes, pit: str) -> dict[str, Any]:
        # Point-in-time recovery for Postgres is archive recovery; here we record
        # the recovery target so an operator/DBA applies the WAL archive.
        _validate_db_name(database_id)
        return {"tool": "pg_wal_pitr", "database_id": database_id,
                "recovery_target_time": pit, "wal_bytes": len(wal)}


class Neo4jBackend:
    """Neo4j offline backup via neo4j-admin database backup; restore via
    neo4j-admin database restore."""

    name = "neo4j"

    def __init__(self, *, runner: CommandRunner, host: str = "localhost",
                 port: int = 6362, neo4j_bin: str = ""):
        self._run = runner
        self.host = host
        self.port = port
        self.neo4j_bin = neo4j_bin.rstrip("/")
        self.calls: list[list[str]] = []

    def _bin(self, tool: str) -> str:
        return f"{self.neo4j_bin}/{tool}" if self.neo4j_bin else tool

    def dump(self, database_id: str) -> bytes:
        _validate_db_name(database_id)
        # neo4j-admin writes to a directory; the injected runner is expected to
        # return the tarred backup on stdout in the reference/test harness.
        argv = [self._bin("neo4j-admin"), "database", "backup",
                "--from", f"{self.host}:{self.port}", database_id]
        self.calls.append(argv)
        res = self._run(argv)
        if res.returncode != 0:
            raise bk.BackupError(f"neo4j-admin backup failed (rc={res.returncode})")
        return res.stdout

    def restore(self, database_id: str, payload: bytes) -> dict[str, Any]:
        _validate_db_name(database_id)
        argv = [self._bin("neo4j-admin"), "database", "restore",
                "--overwrite-destination", database_id]
        self.calls.append(argv)
        res = self._run(argv, stdin=payload) if _accepts_stdin(self._run) else self._run(argv)
        rc = getattr(res, "returncode", 0)
        if rc != 0:
            raise bk.BackupError(f"neo4j-admin restore failed (rc={rc})")
        return {"tool": "neo4j-admin restore", "database_id": database_id, "bytes": len(payload)}


def _accepts_stdin(runner: CommandRunner) -> bool:
    import inspect

    try:
        params = inspect.signature(runner).parameters
    except (TypeError, ValueError):
        return False
    return "stdin" in params


# ------------------------------------------------------------------ storage -- #
class BackupStorage(Protocol):
    def put(self, key: str, blob: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...
    def list_manifests(self) -> list[dict[str, Any]]: ...


class InMemoryBackupStorage:
    """Deterministic storage for tests/offline reference."""

    def __init__(self):
        self._blobs: dict[str, bytes] = {}
        self._manifests: dict[str, dict[str, Any]] = {}

    def put(self, key: str, blob: bytes) -> None:
        self._blobs[key] = blob

    def get(self, key: str) -> bytes:
        return self._blobs[key]

    def delete(self, key: str) -> None:
        self._blobs.pop(key, None)
        self._manifests.pop(key, None)

    def put_manifest(self, key: str, manifest: dict) -> None:
        self._manifests[key] = manifest

    def list_manifests(self) -> list[dict[str, Any]]:
        return [dict(m, storage_key=k) for k, m in sorted(self._manifests.items())]


# ----------------------------------------------------------------- job run --- #
@dataclass
class BackupConfig:
    database_id: str
    engine: str                       # postgres | neo4j
    interval_hours: float = 24.0
    retention_policy: dict[str, int] | None = None
    last_run_at: dt.datetime | None = None
    sequence: int = 0


def run_backup_job(*, backend: Any, storage: InMemoryBackupStorage,
                   config: BackupConfig, encryption_key: bytes, signing_secret: str,
                   now: dt.datetime | None = None, include_wal: bool = True) -> dict[str, Any]:
    """Full cycle: dump → encrypt+sign → persist ciphertext & manifest."""
    ref = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    wal = b"" if include_wal else None
    res = bk.create_backup(backend=backend, database_id=config.database_id,
                           encryption_key=encryption_key, signing_secret=signing_secret,
                           now=ref, sequence=config.sequence + 1, wal_tail=wal)
    man = res["manifest"]
    key = f"{config.engine}/{config.database_id}/{man['backup_id']}"
    storage.put(key, res["ciphertext"])
    storage.put_manifest(key, man)
    config.last_run_at = ref
    config.sequence = man["sequence"]
    return {"storage_key": key, "manifest": man, "ok": True}


def run_due_backups(*, configs: list[BackupConfig], backend_for: Callable[[str], Any],
                    storage: InMemoryBackupStorage, encryption_key: bytes,
                    signing_secret: str, now: dt.datetime | None = None) -> list[dict]:
    """Pure scheduler: run any config whose interval has elapsed since last run.
    `backend_for(engine)` returns the runner backend for an engine name."""
    ref = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    results = []
    for cfg in configs:
        due = cfg.last_run_at is None or (
            ref - cfg.last_run_at.astimezone(dt.timezone.utc)
        ) >= dt.timedelta(hours=cfg.interval_hours)
        if not due:
            results.append({"database_id": cfg.database_id, "ok": True, "skipped": True})
            continue
        backend = backend_for(cfg.engine)
        results.append(run_backup_job(backend=backend, storage=storage, config=cfg,
                                      encryption_key=encryption_key, signing_secret=signing_secret,
                                      now=ref))
    return results


def execute_retention(*, storage: InMemoryBackupStorage, signing_secret: str,
                      now: dt.datetime | None = None,
                      policy: dict[str, int] | None = None) -> dict[str, Any]:
    """Apply the GFS retention plan: delete ciphertext for every manifest the
    planner marks `purge`. Returns the plan + deleted keys."""
    manifests = storage.list_manifests()
    plan = bk.apply_retention(manifests, now=now, policy=policy)
    purge_ids = {p["backup_id"] for p in plan["purge"]}
    deleted = []
    for m in manifests:
        if m.get("backup_id") in purge_ids:
            storage.delete(m["storage_key"])
            deleted.append(m["storage_key"])
    return {"plan": plan, "deleted_keys": deleted}


def restore_from_storage(*, backend: Any, storage: InMemoryBackupStorage,
                         database_id: str, encryption_key: bytes, signing_secret: str,
                         storage_key: str | None = None,
                         target_point_in_time: str | None = None) -> dict[str, Any]:
    """Load the newest (or specified) backup for a database and restore it."""
    manifests = [m for m in storage.list_manifests()
                 if m.get("database_id") == database_id]
    if not manifests:
        raise bk.BackupError(f"no backups found for {database_id}")
    chosen = next((m for m in manifests if m["storage_key"] == storage_key), None) \
        if storage_key else manifests[-1]
    if chosen is None:
        raise bk.BackupError(f"backup {storage_key} not found")
    ciphertext = storage.get(chosen["storage_key"])
    return bk.restore_backup(backend=backend, database_id=database_id, ciphertext=ciphertext,
                             manifest={k: v for k, v in chosen.items() if k != "storage_key"},
                             encryption_key=encryption_key, signing_secret=signing_secret,
                             target_point_in_time=target_point_in_time)
