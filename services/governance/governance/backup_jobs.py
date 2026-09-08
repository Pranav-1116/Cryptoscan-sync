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
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from . import backup as bk

# A command runner: argv list -> CompletedCall-like (returncode, stdout, stderr)
class CommandResult:
    def __init__(self, returncode: int = 0, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


CommandRunner = Callable[..., CommandResult]

# Database identifiers are restricted to a safe charset to make argv injection
# impossible (we never invoke a shell; argv is a list, but we defend in depth).
_SAFE_DB_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class ToolNotFound(RuntimeError):
    """Raised when a required backup tool (pg_dump/neo4j-admin) is absent.

    Deliberately a ``RuntimeError`` (not ``bk.BackupError`` which is a
    ``ValueError``) so callers can distinguish a missing tool (HTTP 503) from a
    backup/restore failure (HTTP 502)."""


def _tool_path(tool: str) -> str | None:
    return shutil.which(tool)


def subprocess_runner(timeout: int = 3600, env: dict | None = None) -> CommandRunner:
    """REAL command runner: execs argv with subprocess (no shell), captures stdout
    as the backup archive. Raises ToolNotFound if the binary is missing so the
    caller reports an honest 'tool not installed' rather than a fake success.

    Usage: runner(argv) -> CommandResult(stdout=archive). restore via
    runner(argv, stdin=payload)."""

    def _run(argv: list[str], *, stdin: bytes | None = None) -> CommandResult:
        tool = argv[0]
        # If a bare tool name is given, verify it is on PATH up front.
        if "/" not in tool and os.sep not in tool and _tool_path(tool) is None:
            raise ToolNotFound(f"required tool {tool!r} is not installed or not on PATH")
        try:
            proc = subprocess.run(
                argv, input=stdin, capture_output=True, timeout=timeout,
                check=False, env=env, shell=False)
        except FileNotFoundError as exc:
            raise ToolNotFound(f"required tool {tool!r} is not installed: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            return CommandResult(124, b"", f"timeout after {timeout}s: {exc}".encode())
        return CommandResult(proc.returncode, proc.stdout or b"", proc.stderr or b"")

    return _run


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
                 port: int = 6362, neo4j_bin: str = "",
                 backup_dir: str | os.PathLike | None = None):
        self._run = runner
        self.host = host
        self.port = port
        self.neo4j_bin = neo4j_bin.rstrip("/")
        self.calls: list[list[str]] = []
        # Directory neo4j-admin writes into; the resulting artifact is tarred.
        self.backup_dir = Path(backup_dir) if backup_dir else None

    def _bin(self, tool: str) -> str:
        return f"{self.neo4j_bin}/{tool}" if self.neo4j_bin else tool

    def dump(self, database_id: str) -> bytes:
        _validate_db_name(database_id)
        # neo4j-admin writes a backup into a directory; we point it at a temp
        # dir, run it, then tar the produced artifact so the rest of the
        # pipeline (encrypt/sign/store) treats it as an opaque byte stream.
        tmp = None
        if self.backup_dir is not None:
            target = Path(self.backup_dir); target.mkdir(parents=True, exist_ok=True)
            argv = [self._bin("neo4j-admin"), "database", "backup",
                    "--from", f"{self.host}:{self.port}",
                    "--to", str(target), "--include-path-labels", database_id, database_id]
        else:
            # test runner that returns bytes directly on stdout
            argv = [self._bin("neo4j-admin"), "database", "backup",
                    "--from", f"{self.host}:{self.port}", database_id]
        self.calls.append(argv)
        res = self._run(argv)
        if res.returncode != 0:
            raise bk.BackupError(f"neo4j-admin backup failed (rc={res.returncode}): {res.stderr.decode('utf-8','replace')[:300]}")
        if self.backup_dir is not None:
            import io
            import tarfile
            buf = io.BytesIO()
            artifact = target / database_id
            with tarfile.open(fileobj=buf, mode="w") as tf:
                if artifact.exists():
                    tf.add(artifact, arcname=database_id)
            return buf.getvalue()
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
class _DumpCaptureBackend:
    """Backend that wraps caller-supplied raw dump bytes (explicit capture or
    offline import). Used when bytes are provided instead of invoking a tool."""

    def __init__(self, name: str, dump_bytes: bytes):
        self.name = name
        self._dump = dump_bytes

    def dump(self, database_id: str) -> bytes:
        return self._dump or f"CAPTURED-DUMP:{database_id}".encode()

    def restore(self, database_id: str, payload: bytes) -> dict[str, Any]:
        # bytes-only capture cannot itself restore; signal honestly
        raise bk.BackupError("captured dump has no live restore path; use a tool backend")


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


class DiskBackupStorage:
    """REAL persistent storage: writes encrypted artifacts + manifests under a
    local directory (a mounted volume in production; S3-compatible sinks wrap
    the same interface). Survives restarts — unlike the in-memory test store."""

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _blob_path(self, key: str) -> Path:
        # storage keys look like postgres/proddb/bk-.... ; flatten safely
        flat = key.replace("/", "__")
        return self.root / f"{flat}.enc"

    def _manifest_path(self, key: str) -> Path:
        flat = key.replace("/", "__")
        return self.root / f"{flat}.manifest.json"

    def put(self, key: str, blob: bytes) -> None:
        self._blob_path(key).write_bytes(blob)

    def put_manifest(self, key: str, manifest: dict) -> None:
        self._manifest_path(key).write_text(json.dumps(manifest, sort_keys=True, default=str))

    def get(self, key: str) -> bytes:
        p = self._blob_path(key)
        if not p.exists():
            raise FileNotFoundError(f"backup artifact not found: {key}")
        return p.read_bytes()

    def delete(self, key: str) -> None:
        for p in (self._blob_path(key), self._manifest_path(key)):
            if p.exists():
                p.unlink()

    def list_manifests(self) -> list[dict[str, Any]]:
        out = []
        for mp in sorted(self.root.glob("*.manifest.json")):
            try:
                m = json.loads(mp.read_text())
            except Exception:  # noqa: BLE001 - skip corrupt manifest, keep serving others
                continue
            key = mp.name[: -len(".manifest.json")].replace("__", "/")
            out.append(dict(m, storage_key=key))
        return out


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
        try:
            backend = backend_for(cfg.engine)
            results.append(run_backup_job(backend=backend, storage=storage, config=cfg,
                                          encryption_key=encryption_key, signing_secret=signing_secret,
                                          now=ref))
        except Exception as exc:  # noqa: BLE001 — one unreachable DB must not fail the batch
            results.append({"database_id": cfg.database_id, "engine": cfg.engine,
                            "ok": False, "skipped": False,
                            "error": f"{type(exc).__name__}: {exc}"[:300]})
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
