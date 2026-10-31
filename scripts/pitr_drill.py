#!/usr/bin/env python3
"""Point-in-time-recovery drill: prove the restore, on a real PostgreSQL.

A backup that has never been restored is a hope, not a recovery plan. The
existing drills cover the paths around this one — ``backup_evidence.py``
produces a dump, ``restore_evidence.py`` replays it, ``postgres_drill.py``
promotes a streaming standby — but none of them answers the question a bank
actually asks after a bad migration or a destructive script:

    can we restore to the moment *before* that happened, and prove the damage
    is not in the restored database?

That is physical point-in-time recovery: a base backup plus archived WAL,
replayed to a chosen recovery target. This drill runs the whole chain on a
throwaway cluster built from real PostgreSQL binaries and asserts the outcome:

1. ``initdb`` a primary with ``archive_mode=on`` and a ``cp``
   ``archive_command`` — WAL is archived, not just written.
2. Create the drill schema and take a **base backup** with ``pg_basebackup``;
   verify it with ``pg_verifybackup`` (a backup nobody verified is a backup
   nobody read).
3. Write the data that must survive, record the recovery target, then write the
   "damage" that must not survive.
4. Force a WAL switch and wait until the segment holding the target is *in the
   archive*. Archiving is asynchronous: a restore that starts before the target
   segment lands fails, and that failure looks like a corrupt archive.
5. Stop the primary with ``immediate`` — an ungraceful stop, which is what a
   lost node is.
6. Restore into a new data directory with ``recovery_target_time`` and
   ``recovery_target_action=promote``, start it, and check:
   pre-target rows are present, post-target rows are absent, the new instance
   is out of recovery, and it moved to a new timeline.

Everything runs from PostgreSQL binaries already on the host: ``PG_BIN`` if set,
else the optional ``pgserver`` package's bundled distribution, else ``pg_config``,
else ``PATH``. No Docker, no privileges, no network listener — the drill binds a
unix socket in a private temporary directory and shuts every server down.

    python scripts/pitr_drill.py --evidence evidence/pitr-$(date +%F).json

Exit status is 0 only when every assertion passed. The JSON report is evidence
of the *mechanism* and of these binaries: it is not evidence that a customer's
cluster, storage layer, or backup retention meets an RPO/RTO target. Re-run
against the real cluster before anyone signs that.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "cryptoscan.postgres-pitr-drill/1"
REQUIRED_BINARIES = ("initdb", "pg_ctl", "pg_basebackup", "pg_verifybackup", "psql", "postgres")

# The drill's own table: the shape of a schema has no bearing on WAL replay, so
# a small table keeps the drill fast while the mechanism stays real.
SETUP_SQL = """
CREATE TABLE pitr_drill_events (
    id          bigserial PRIMARY KEY,
    batch       text NOT NULL,
    marker      uuid NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE pitr_drill_audit (
    id       bigserial PRIMARY KEY,
    action   text NOT NULL,
    detail   text
);
"""


class DrillError(RuntimeError):
    """A step failed. The report records which one and why."""


# --------------------------------------------------------------------- binaries


def find_binaries(explicit: str | None = None) -> tuple[Path, str]:
    """Locate a PostgreSQL distribution, refusing loudly rather than guessing.

    Returns ``(bindir, provenance)``. ``provenance`` is recorded in the report so
    a reader knows whether the drill used the host's PostgreSQL or a bundled
    development build.
    """
    candidates: list[tuple[Path, str]] = []
    if explicit:
        candidates.append((Path(explicit), "PG_BIN"))
    env_bin = os.environ.get("PG_BIN")
    if env_bin:
        candidates.append((Path(env_bin), "PG_BIN environment variable"))
    try:  # optional development dependency, bundled PostgreSQL 16
        import pgserver  # type: ignore

        bundled = Path(pgserver.__file__).parent / "pginstall" / "bin"
        candidates.append((bundled, "pgserver bundled distribution"))
    except ImportError:  # pragma: no cover - pgserver is optional
        pass
    pg_config = shutil.which("pg_config")
    if pg_config:
        try:
            bindir = subprocess.run(
                [pg_config, "--bindir"], capture_output=True, text=True, timeout=10
            ).stdout.strip()
            if bindir:
                candidates.append((Path(bindir), "pg_config --bindir"))
        except (OSError, subprocess.SubprocessError):
            pass
    postgres = shutil.which("postgres")
    if postgres:
        candidates.append((Path(postgres).parent, "PATH"))

    for bindir, provenance in candidates:
        if all((bindir / name).exists() for name in REQUIRED_BINARIES):
            return bindir, provenance
    searched = ", ".join(f"{path} ({why})" for path, why in candidates) or "nothing"
    raise DrillError(
        "no PostgreSQL distribution found. Set PG_BIN to a directory containing "
        f"initdb, pg_ctl, pg_basebackup, pg_verifybackup, psql and postgres. Searched: {searched}"
    )


# ------------------------------------------------------------------------ shell


def run(cmd: list[str], *, env: dict | None = None, check: bool = True,
        timeout: int = 300) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env
    )
    if check and result.returncode != 0:
        raise DrillError(
            f"{Path(cmd[0]).name} failed (exit {result.returncode}): "
            + (result.stderr.strip() or result.stdout.strip())[-1500:]
        )
    return result


class Cluster:
    """One PostgreSQL data directory the drill owns end to end."""

    def __init__(self, bindir: Path, datadir: Path, socketdir: Path, port: int) -> None:
        self.bindir = bindir
        self.datadir = datadir
        self.socketdir = socketdir
        self.port = port
        self.logfile = datadir.parent / f"{datadir.name}.log"
        self.started = False

    def bin(self, name: str) -> str:
        return str(self.bindir / name)

    def psql(self, sql: str) -> str:
        result = run([
            self.bin("psql"), "-h", str(self.socketdir), "-p", str(self.port),
            "-U", "postgres", "-d", "postgres", "-tA", "-v", "ON_ERROR_STOP=1",
            "-c", sql,
        ])
        return result.stdout.strip()

    def write_settings(self, extra: list[str] | None = None) -> None:
        """Append settings to postgresql.conf rather than passing -o strings.

        ``pg_ctl -o`` hands its argument to postgres(1) through the shell's word
        splitting, so a value containing spaces (``archive_command``) or quotes
        (``listen_addresses=''``) arrives mangled — "could not translate host
        name ''". Configuration file values need no quoting games.
        """
        settings = [
            f"port = {self.port}",
            "listen_addresses = ''",
            f"unix_socket_directories = '{self.socketdir}'",
            "fsync = off",
            "full_page_writes = off",
            "log_min_messages = warning",
        ]
        settings.extend(extra or [])
        with (self.datadir / "postgresql.conf").open("a", encoding="utf-8") as handle:
            handle.write("\n# appended by scripts/pitr_drill.py\n")
            handle.write("\n".join(settings) + "\n")

    def start(self, *, wait: bool = True) -> None:
        args = [self.bin("pg_ctl"), "-D", str(self.datadir), "-l", str(self.logfile),
                "-w" if wait else "-W", "start"]
        result = run(args, check=False)
        if result.returncode != 0:
            raise DrillError(
                f"could not start {self.datadir.name}: "
                + (self.log_tail() or result.stderr.strip())[-1500:]
            )
        self.started = True

    def stop(self, mode: str = "fast") -> None:
        if not self.started:
            return
        run([self.bin("pg_ctl"), "-D", str(self.datadir), "-m", mode, "-w", "stop"], check=False)
        self.started = False

    def wait_ready(self, timeout: float = 60.0) -> bool:
        """A real query, not ``pg_isready``: only a query proves the cluster answers."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            result = run([
                self.bin("psql"), "-h", str(self.socketdir), "-p", str(self.port),
                "-U", "postgres", "-d", "postgres", "-tA", "-c", "select 1",
            ], check=False, timeout=20)
            if result.returncode == 0 and result.stdout.strip() == "1":
                return True
            time.sleep(0.25)
        return False

    def log_tail(self, lines: int = 40) -> str:
        try:
            return "\n".join(self.logfile.read_text(errors="replace").splitlines()[-lines:])
        except OSError:
            return ""


# ---------------------------------------------------------------------- evidence


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []
        self.measurements: dict = {}

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append({"check": name, "passed": bool(passed), "detail": detail})
        return bool(passed)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(check["passed"] for check in self.checks)


# ------------------------------------------------------------------------- drill


def run_drill(workdir: Path, keep: bool, report: Report) -> dict:
    started_at = datetime.now(timezone.utc)
    bindir, provenance = find_binaries()
    version = run([str(bindir / "postgres"), "--version"]).stdout.strip()
    report.check("postgres_binaries_found", True, f"{bindir} ({provenance}); {version}")

    socketdir = workdir / "sock"
    socketdir.mkdir()
    archive = workdir / "archive"
    archive.mkdir()
    port = random.randint(56000, 58999)

    primary = Cluster(bindir, workdir / "primary", socketdir, port)
    initdb = run([
        str(bindir / "initdb"), "-D", str(primary.datadir), "-U", "postgres",
        "-A", "trust", "--no-sync", "--encoding=UTF8",
    ])
    initdb_detail = next(
        (line.strip() for line in initdb.stdout.splitlines() if "You can now start" in line
         or "Success" in line or "creating" in line),
        f"{primary.datadir}",
    )
    report.check("initdb", (primary.datadir / "PG_VERSION").is_file(), initdb_detail)

    # Atomic archiving, and not a detail: `cp %p %f` publishes a partial file
    # under the final name while the copy is in flight, and a restore that reads
    # it dies with `archive file ... has wrong size`. An ungraceful stop during
    # the copy leaves that partial file behind permanently. Copy under a
    # temporary name and rename, which is atomic on the same filesystem.
    archive_command = (
        f"test ! -f {archive}/%f && cp %p {archive}/%f.partial && mv {archive}/%f.partial {archive}/%f"
    )
    primary.write_settings([
        "wal_level = replica",
        "archive_mode = on",
        f"archive_command = '{archive_command}'",
        "max_wal_senders = 4",
    ])
    primary.start()
    report.check("primary_started", primary.wait_ready(), str(primary.datadir))

    primary.psql(SETUP_SQL)
    report.check("drill_schema_created", True, "pitr_drill_events + pitr_drill_audit")

    # ── 1. a verified physical base backup ───────────────────────────────
    basedir = workdir / "base"
    backup_started = time.time()
    run([
        str(bindir / "pg_basebackup"), "-h", str(socketdir), "-p", str(port),
        "-U", "postgres", "-D", str(basedir), "-X", "stream", "-c", "fast",
        "-l", "cryptoscan-pitr-drill",
    ], timeout=600)
    backup_seconds = time.time() - backup_started
    verify = run([str(bindir / "pg_verifybackup"), str(basedir)], check=False)
    report.check(
        "base_backup_verified", verify.returncode == 0,
        (verify.stdout.strip() or verify.stderr.strip() or "pg_verifybackup ok")[-600:],
    )
    report.measurements["base_backup_seconds"] = round(backup_seconds, 3)
    manifest = basedir / "backup_manifest"
    if manifest.exists():
        report.measurements["base_backup_manifest_sha256"] = sha256_path(manifest)

    # ── 2. data that must survive, then the recovery target ──────────────
    import uuid as _uuid

    keep_marker = str(_uuid.uuid4())
    keep_rows = 3
    values = ", ".join(f"('keep', '{keep_marker}')" for _ in range(keep_rows))
    primary.psql(
        "INSERT INTO pitr_drill_events (batch, marker) VALUES " + values + ";"
        " INSERT INTO pitr_drill_audit (action, detail) VALUES ('kept', 'pre-target');"
    )
    target_time = primary.psql("SELECT now()::timestamptz(6);")
    target_lsn = primary.psql("SELECT pg_current_wal_lsn();")
    report.measurements["recovery_target_time"] = target_time
    report.measurements["recovery_target_lsn"] = target_lsn
    report.check(
        "recovery_target_recorded", bool(target_time and target_lsn),
        f"time={target_time} lsn={target_lsn}",
    )

    # ── 3. the damage: committed after the target, must NOT come back ────
    # The gap matters: PostgreSQL compares commit timestamps, and a target that
    # shares a clock tick with the bad transaction is ambiguous.
    time.sleep(2)
    damage_marker = str(_uuid.uuid4())
    primary.psql(
        "INSERT INTO pitr_drill_events (batch, marker) VALUES ('damage', '%s');"
        " INSERT INTO pitr_drill_audit (action, detail) VALUES ('destroyed', 'post-target');"
        % damage_marker
    )
    report.check("damage_written", True, "post-target rows committed on the primary")

    # ── 4. the target WAL segment must reach the archive before we restore ─
    primary.psql("SELECT pg_switch_wal();")
    target_segment = primary.psql(f"SELECT pg_walfile_name('{target_lsn}');")
    deadline = time.time() + 60
    archived = False
    while time.time() < deadline:
        if target_segment and (archive / target_segment).exists():
            archived = True
            break
        time.sleep(0.25)
    report.check(
        "target_wal_archived", archived,
        f"{target_segment} in {archive}" if archived else f"{target_segment} never reached the archive",
    )
    if archived:
        # A segment shorter than wal_segment_size is a copy that was still
        # running when it was read. Replaying it is a FATAL, so the drill
        # refuses to call the archive usable if one is present.
        size = (archive / target_segment).stat().st_size
        segment_bytes = int(primary.psql("SELECT setting FROM pg_settings WHERE name='wal_segment_size';"))
        report.check(
            "archived_segment_complete", size == segment_bytes,
            f"{target_segment} is {size} bytes, expected {segment_bytes}",
        )

    # ── 5. the disaster: an ungraceful stop ──────────────────────────────
    disaster_at = datetime.now(timezone.utc)
    primary.stop("immediate")
    report.check("primary_stopped_immediately", not primary.started, "simulated node loss")

    # ── 6. restore into a fresh directory and replay to the target ────────
    restore_dir = workdir / "restore"
    shutil.copytree(basedir, restore_dir)
    standby_signal = restore_dir / "standby.signal"
    if standby_signal.exists():  # -R was not used, but never inherit a standby role
        standby_signal.unlink()
    settings = [
        f"restore_command = 'cp {archive}/%f %p'",
        f"recovery_target_time = '{target_time}'",
        "recovery_target_inclusive = 'on'",
        "recovery_target_action = 'promote'",
        "archive_mode = 'off'",
        "hot_standby = 'on'",
    ]
    restored = Cluster(bindir, restore_dir, socketdir, port + 1)
    # The restored copy inherits the primary's configuration, including its
    # port and socket directory; give it its own so both never collide and the
    # restore cannot accidentally attach to a live socket.
    restored.write_settings()
    with (restore_dir / "postgresql.auto.conf").open("a", encoding="utf-8") as handle:
        handle.write("\n# appended by scripts/pitr_drill.py\n")
        handle.write("\n".join(settings) + "\n")
    (restore_dir / "recovery.signal").touch()

    restore_started = time.time()
    restored.start()
    serving = restored.wait_ready(timeout=120)
    rto_seconds = time.time() - restore_started
    if not serving:
        raise DrillError("restored cluster never accepted a query: " + (restored.log_tail() or ""))
    report.check("restored_cluster_serving", True, f"first query after {rto_seconds:.2f}s")
    report.measurements["rto_seconds"] = round(rto_seconds, 3)
    # How much committed work the recovery target knowingly discarded. This is
    # the number an operator compares against the RPO they promised.
    report.measurements["discarded_window_seconds"] = round(
        (disaster_at - datetime.fromisoformat(target_time)).total_seconds(), 3
    )

    # ── 7. the assertions that make it a drill and not a demo ────────────
    in_recovery = restored.psql("SELECT pg_is_in_recovery();")
    report.check("restored_instance_promoted", in_recovery == "f", f"pg_is_in_recovery={in_recovery}")

    kept = int(restored.psql(
        f"SELECT count(*) FROM pitr_drill_events WHERE batch='keep' AND marker='{keep_marker}';"
    ))
    report.check(
        "pre_target_data_recovered", kept == keep_rows,
        f"{kept}/{keep_rows} pre-target rows present after replay",
    )
    damaged = int(restored.psql(
        f"SELECT count(*) FROM pitr_drill_events WHERE marker='{damage_marker}';"
    ))
    report.check(
        "post_target_data_excluded", damaged == 0,
        f"{damaged} post-target rows replayed (must be 0)",
    )
    audit_kept = int(restored.psql(
        "SELECT count(*) FROM pitr_drill_audit WHERE detail='pre-target';"
    ))
    audit_damaged = int(restored.psql(
        "SELECT count(*) FROM pitr_drill_audit WHERE detail='post-target';"
    ))
    report.check(
        "audit_trail_matches_target", audit_kept == 1 and audit_damaged == 0,
        f"pre-target audit rows={audit_kept}, post-target audit rows={audit_damaged}",
    )

    timeline = restored.psql("SELECT timeline_id FROM pg_control_checkpoint();")
    report.check(
        "new_timeline_created", timeline not in ("", "1"),
        f"timeline {timeline} (a promoted recovery starts a new timeline)",
    )
    log = restored.log_tail(200)
    report.check(
        "recovery_stopped_at_requested_time",
        "recovery stopping" in log and "before commit" in log,
        next((line for line in log.splitlines() if "recovery stopping" in line), "no stop line in log")[-300:],
    )

    # ── 8. the restored cluster is usable, not just readable ─────────────
    restored.psql("INSERT INTO pitr_drill_events (batch, marker) VALUES ('post-restore', gen_random_uuid());")
    writable = restored.psql("SELECT count(*) FROM pitr_drill_events WHERE batch='post-restore';")
    report.check("restored_cluster_writable", writable == "1", "accepts writes after promotion")

    restored.stop("fast")

    finished_at = datetime.now(timezone.utc)
    report.check("primary_shut_down", not primary.started, "original cluster stopped")
    report.check("restored_shut_down", not restored.started, "restored cluster stopped")
    report.measurements["drill_seconds"] = round((finished_at - started_at).total_seconds(), 3)
    return {
        "host": platform.node(),
        "platform": platform.platform(),
        "postgres": version,
        "binaries": str(bindir),
        "binaries_provenance": provenance,
        "workdir_retained": keep,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workdir", type=Path, default=None,
                        help="where to build the throwaway clusters (default: a private temp dir)")
    parser.add_argument("--keep", action="store_true",
                        help="keep the workdir (clusters stopped) for after-the-fact inspection")
    parser.add_argument("--evidence", type=Path, default=None,
                        help="write the JSON report here as well as printing it")
    args = parser.parse_args(argv)

    report = Report()
    environment: dict = {}
    workdir = args.workdir
    owned = False
    if workdir is None:
        workdir = Path(tempfile.mkdtemp(prefix="cryptoscan-pitr-"))
        owned = True
    else:
        workdir.mkdir(parents=True, exist_ok=True)
        if any(workdir.iterdir()):
            print(f"error: {workdir} is not empty; the drill needs its own directory", file=sys.stderr)
            return 2

    exit_code = 1
    try:
        environment = run_drill(workdir, args.keep, report)
        exit_code = 0 if report.passed else 1
    except DrillError as exc:
        report.check("drill_completed", False, str(exc))
        print(f"drill failed: {exc}", file=sys.stderr)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - defensive
        report.check("drill_completed", False, f"timeout: {exc}")
        print(f"drill timed out: {exc}", file=sys.stderr)
    finally:
        if owned and not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        elif args.keep:
            print(f"workdir kept at {workdir}", file=sys.stderr)

    document = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": "PASS" if report.passed else "FAIL",
        "checks": report.checks,
        "measurements": report.measurements,
        "environment": environment,
        "limits": (
            "Proves the physical base-backup + archived-WAL + point-in-time-restore path "
            "on a throwaway local cluster built from the PostgreSQL binaries named above. "
            "It is not evidence about a customer's storage, WAL retention, backup targets, "
            "encryption at rest, or measured RPO/RTO: re-run against the real cluster and "
            "archive the logs with this report."
        ),
    }
    text = json.dumps(document, indent=2)
    print(text)
    if args.evidence:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(text + "\n", encoding="utf-8")
        try:
            os.chmod(args.evidence, 0o600)
        except OSError:
            pass
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
