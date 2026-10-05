#!/usr/bin/env python3
"""Run a real two-PostgreSQL disaster-recovery qualification drill.

This is deliberately not a simulator. It requires two reachable PostgreSQL
instances, a primary/standby relationship, and an operator-supplied promotion
command. Without those inputs it produces a PREFLIGHT/SKIP report rather than
claiming DR success.

The drill verifies:

* both instances are reachable and have the expected primary/standby roles;
* WAL replication is visible on the primary;
* a unique drill marker reaches the standby (measured RPO);
* an explicitly acknowledged promotion command makes the standby writable;
* promotion-to-health time is measured as RTO;
* audit/evidence row counts and the drill marker survive promotion;
* supplied API and worker recovery probes return healthy after node loss.

Examples:
    DR_PRIMARY_DSN='postgresql://...' \
    DR_STANDBY_DSN='postgresql://...' \
    DR_PROMOTE_COMMAND='ssh standby sudo pg_ctlcluster 16 main promote' \
    python scripts/postgres_drill.py --execute-promotion \
      --acknowledge-destructive --api-url https://scan.bank.example/api/v1/readyz

A promotion is never run unless both ``--execute-promotion`` and
``--acknowledge-destructive`` are supplied. The report is evidence only when
the operator archives the JSON, command output and database/provider logs.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


class Db:
    def __init__(self, conn: Any, driver: str):
        self.conn = conn
        self.driver = driver

    def query(self, sql: str, params: tuple[Any, ...] = ()) -> list[tuple]:
        cur = self.conn.cursor()
        try:
            cur.execute(sql, params)
            if cur.description is None:
                return []
            return cur.fetchall()
        finally:
            cur.close()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        cur = self.conn.cursor()
        try:
            cur.execute(sql, params)
        finally:
            cur.close()

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        """Clear a failed transaction so the connection is usable again.

        Both poll loops below probe for something that does not exist yet. In
        PostgreSQL the first such error aborts the transaction, and every
        later statement on that connection raises InFailedSqlTransaction until
        someone rolls back -- so without this a poll can never recover, no
        matter how quickly the thing it is waiting for appears.
        """
        try:
            self.conn.rollback()
        except Exception:  # noqa: BLE001 - connection already gone; the caller retries
            pass

    def close(self) -> None:
        self.conn.close()


def safe_command(command: str | None) -> str | None:
    if not command:
        return None
    # Record the operator action while removing URI passwords and obvious
    # secret assignments from the evidence artifact.
    masked = re.sub(r"(://[^:/\s]+:)[^@\s]+(@)", r"\1[redacted]\2", command)
    masked = re.sub(r"(?i)(password|secret|token|pin)=\S+", r"\1=[redacted]", masked)
    return masked[:1000]


def connect(dsn: str) -> Db:
    """Load psycopg3 first, then psycopg2, without bundling a DB driver."""
    try:
        import psycopg  # type: ignore

        return Db(psycopg.connect(dsn, connect_timeout=10), "psycopg")
    except ImportError:
        pass
    try:
        import psycopg2  # type: ignore

        return Db(psycopg2.connect(dsn, connect_timeout=10), "psycopg2")
    except ImportError as exc:
        raise RuntimeError("install psycopg or psycopg2 to run a real PostgreSQL drill") from exc


def one(db: Db, sql: str, params: tuple[Any, ...] = ()) -> Any:
    rows = db.query(sql, params)
    return rows[0][0] if rows else None


def check(name: str, ok: bool, detail: str, results: list[dict]) -> None:
    # "status" mirrors ok/FAIL so downstream artifact evaluators (e.g.
    # scripts/bank_readiness.py) can read the outcome from a standard field
    # instead of inferring it from booleans.
    row = {"check": name, "ok": bool(ok), "status": "PASS" if ok else "FAIL", "detail": detail}
    results.append(row)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")


def table_exists(db: Db, name: str) -> bool:
    return bool(one(db, "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=%s", (name,)))


def counts(db: Db) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for table in ("audit_log", "evidence_records", "scans", "scan_jobs"):
        if not table_exists(db, table):
            out[table] = None
            continue
        try:
            out[table] = int(one(db, f"SELECT count(*) FROM public.{table}") or 0)
        except Exception:
            out[table] = None
    return out


def replication_rows(db: Db) -> list[dict[str, Any]]:
    rows = db.query(
        "SELECT application_name, client_addr::text, state, sync_state, "
        "sent_lsn::text, write_lsn::text, flush_lsn::text, replay_lsn::text "
        "FROM pg_stat_replication"
    )
    return [
        {
            "application_name": r[0], "client_addr": r[1], "state": r[2],
            "sync_state": r[3], "sent_lsn": r[4], "write_lsn": r[5],
            "flush_lsn": r[6], "replay_lsn": r[7],
        }
        for r in rows
    ]


def health(url: str, timeout: float) -> tuple[bool, str]:
    """Prove the API serves the PROMOTED database, not merely that it runs.

    This accepted any status < 400 from any URL. Two ways that passed a
    failed failover:

    * Pointed at /healthz. Until 776bb1e that probe touched the database,
      so liveness incidentally proved the estate was readable. That commit
      correctly made liveness independent of PostgreSQL -- a liveness probe
      that depends on the database causes restart storms during an outage
      -- which silently reduced this check to "uvicorn is running". A
      promotion that left the API pointed at the dead primary would still
      have been recorded as "API ready after failover".
    * Pointed at /readyz but never reading the body. Readiness answers 503
      when the database is unreachable, so the status alone is a real
      signal, but a degraded body that still returns 200 would pass.

    So a liveness URL is refused outright -- it cannot answer this
    question, and accepting it would produce DR evidence that looks
    stronger than the check behind it -- and the body must name the
    database as ok when it reports one.
    """
    path = urllib.parse.urlparse(url).path.rstrip("/")
    if path.endswith("/healthz") or path.endswith("/health"):
        return False, (
            f"{url} is a liveness probe and cannot prove failover: since 776bb1e "
            "it stays 200 through a database outage by design. Point "
            "--api-url/DR_API_READY_URL at /readyz."
        )
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            raw = response.read(8192)
            if response.status >= 400:
                return False, f"HTTP {response.status}"
            try:
                body = json.loads(raw.decode("utf-8", "replace"))
            except (ValueError, UnicodeDecodeError):
                body = None
            if isinstance(body, dict) and "database" in body:
                db_state = str(body.get("database", "")).lower()
                if db_state not in {"ok", "up", "ready"}:
                    return False, f"HTTP {response.status} but database={body.get('database')!r}"
                return True, f"HTTP {response.status} database={db_state}"
            # No database field to assert on: report what came back rather
            # than implying the probe verified more than it did.
            return True, f"HTTP {response.status} (no database field in body)"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def wait_for_marker(db: Db, token: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    last_error_type = None
    while time.monotonic() < deadline:
        try:
            if one(db, "SELECT 1 FROM dr_drill_markers WHERE marker=%s", (token,)):
                return True
        except Exception as exc:
            last_error_type = type(exc).__name__
            # The table has not replicated yet. That aborts the transaction,
            # so clear it or every remaining poll fails as
            # InFailedSqlTransaction and the marker can never be observed.
            db.rollback()
        time.sleep(1.0)
    if last_error_type:
        print(f"standby marker poll ended after transient {last_error_type}", file=sys.stderr)
    return False


def wait_until_writable(db: Db, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    last_error_type = None
    while time.monotonic() < deadline:
        try:
            if one(db, "SELECT pg_is_in_recovery()") is False:
                return True
        except Exception as exc:
            last_error_type = type(exc).__name__
            # Same reason as wait_for_marker: a refused connection or an
            # aborted transaction during promotion must not poison the rest
            # of the poll.
            db.rollback()
        time.sleep(1.0)
    if last_error_type:
        print(f"standby writable poll ended after transient {last_error_type}", file=sys.stderr)
    return False


def verify_evidence_invariants(db: Db, results: list[dict], phase: str) -> None:
    """Check the deployed schema's audit/evidence invariants without guessing.

    The exact application schema varies by release, so the check discovers
    columns from PostgreSQL rather than hard-coding an ORM model. A table is
    still mandatory: a DR restore without audit/evidence data is not a valid
    CryptoScan restore.
    """
    for table in ("audit_log", "evidence_records"):
        exists = table_exists(db, table)
        check(f"{phase}:{table} present", exists, table, results)
        if not exists:
            continue
        cols = {str(row[0]) for row in db.query(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=%s", (table,)
        )}
        check(f"{phase}:{table} has timestamp", bool(cols & {"created_at", "timestamp", "occurred_at"}),
              "columns=" + ",".join(sorted(cols)[:30]), results)
        hash_cols = sorted(c for c in cols if "hash" in c.lower() or "chain" in c.lower())
        required_hash_cols = [c for c in hash_cols if c.lower() not in {"previous_hash"}]
        if required_hash_cols:
            nulls = {column: int(one(db, f"SELECT count(*) FROM public.{table} WHERE {column} IS NULL") or 0) for column in required_hash_cols}
            check(f"{phase}:{table} hash fields complete", all(value == 0 for value in nulls.values()), json.dumps(nulls), results)
        else:
            check(f"{phase}:{table} hash fields declared", False, "no non-previous hash/chain column discovered", results)
        if table == "audit_log" and {"chain_sequence", "previous_hash", "entry_hash"} <= cols:
            sequence = db.query("SELECT chain_sequence, previous_hash FROM public.audit_log WHERE chain_sequence IS NOT NULL ORDER BY chain_sequence")
            numbers = [int(row[0]) for row in sequence]
            contiguous = not numbers or numbers == list(range(numbers[0], numbers[-1] + 1))
            # Genesis convention: the application's chain writer links the
            # first entry to a documented all-zeros sentinel (db.repositories.
            # user_repository.GENESIS_HASH) or leaves it empty. A chain whose
            # first row carries a *real* previous hash starts mid-chain, which
            # means rows were lost or the table was spliced.
            genesis_values = (None, "", "0" * 64)
            first_previous_empty = not sequence or sequence[0][1] in genesis_values
            check(f"{phase}:audit chain continuity", contiguous and first_previous_empty, f"rows={len(numbers)} first_previous_empty={first_previous_empty}", results)


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    md = path.with_suffix(".md")
    lines = [
        "# PostgreSQL disaster-recovery drill",
        "",
        f"Run: `{report['started_at']}`  |  Mode: `{report['mode']}`  |  Verdict: **{report['verdict']}**",
        "",
        "This report is valid only with the two PostgreSQL instance logs, the",
        "promotion command output and the archived release/configuration digest.",
        "It is not a simulation or a substitute for an auditor-witnessed drill.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for item in report["checks"]:
        lines.append(f"| {item['check']} | {'PASS' if item['ok'] else 'FAIL'} | {item['detail']} |")
    lines += ["", f"**RPO seconds:** `{report.get('rpo_seconds')}`", f"**RTO seconds:** `{report.get('rto_seconds')}`", ""]
    md.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--primary-dsn", default=os.getenv("DR_PRIMARY_DSN"))
    ap.add_argument("--standby-dsn", default=os.getenv("DR_STANDBY_DSN"))
    ap.add_argument("--promote-command", default=os.getenv("DR_PROMOTE_COMMAND"),
                    help="operator-approved command that promotes the standby")
    ap.add_argument("--execute-promotion", action="store_true")
    ap.add_argument("--acknowledge-destructive", action="store_true")
    ap.add_argument("--api-url", default=os.getenv("DR_API_READY_URL"),
                    help="API readiness URL after promotion; required for qualification")
    ap.add_argument("--worker-health-command", default=os.getenv("DR_WORKER_HEALTH_COMMAND"),
                    help="operator command that proves the worker reconnects after failover")
    ap.add_argument("--restore-command", default=os.getenv("DR_RESTORE_COMMAND"),
                    help="operator-approved pg_restore/restore command targeting the clean DSN")
    ap.add_argument("--clean-restore-dsn", default=os.getenv("DR_CLEAN_RESTORE_DSN"),
                    help="DSN for an empty database restored by --restore-command")
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--require-promotion", action="store_true",
                    help="return failure unless the promotion and post-failover checks run")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)

    started = datetime.now(timezone.utc).isoformat()
    results: list[dict] = []
    report: dict[str, Any] = {
        "schema": "cryptoscan.postgres-drill/1",
        "started_at": started,
        "mode": "promotion" if args.execute_promotion else "preflight",
        "checks": results,
        "commands": {
            "promotion": safe_command(args.promote_command),
            "restore": safe_command(args.restore_command),
            "worker_health": safe_command(args.worker_health_command),
        },
        "rpo_seconds": None,
        "rto_seconds": None,
    }
    output = args.out or ROOT / "docs" / "dr-evidence" / f"postgres-drill-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"

    if not args.primary_dsn or not args.standby_dsn:
        check("two DSNs supplied", False, "DR_PRIMARY_DSN and DR_STANDBY_DSN are required; no DR claim made", results)
        report["verdict"] = "FAIL"
        write_report(output, report)
        return 1

    primary = standby = restore_db = None
    try:
        primary = connect(args.primary_dsn)
        standby = connect(args.standby_dsn)
        check("primary reachable", True, primary.driver, results)
        check("standby reachable", True, standby.driver, results)

        primary_recovery = bool(one(primary, "SELECT pg_is_in_recovery()"))
        standby_recovery = bool(one(standby, "SELECT pg_is_in_recovery()"))
        check("primary is writable", not primary_recovery, f"pg_is_in_recovery={primary_recovery}", results)
        check("standby is in recovery", standby_recovery, f"pg_is_in_recovery={standby_recovery}", results)
        check("wal_level is replica/logical", str(one(primary, "SHOW wal_level")) in {"replica", "logical"}, str(one(primary, "SHOW wal_level")), results)

        reps = replication_rows(primary)
        streaming = [r for r in reps if r.get("state") == "streaming"]
        check("primary reports streaming standby", bool(streaming), json.dumps(reps, default=str)[:500], results)

        marker = f"cryptoscan-dr-{uuid.uuid4().hex}"
        primary.execute("CREATE TABLE IF NOT EXISTS dr_drill_markers (marker text PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now())")
        primary.execute("INSERT INTO dr_drill_markers(marker) VALUES (%s)", (marker,))
        primary.commit()
        marker_started = time.monotonic()
        marker_ok = wait_for_marker(standby, marker, args.timeout)
        replication_seconds = round(time.monotonic() - marker_started, 3)
        report["rpo_seconds"] = 0.0 if marker_ok else None
        check("drill marker replicated", marker_ok, f"marker={marker}; replication_seconds={replication_seconds}", results)
        before_counts = counts(primary)
        report["before_counts"] = before_counts
        check("audit/evidence tables inspected", any(v is not None for v in before_counts.values()), json.dumps(before_counts), results)
        verify_evidence_invariants(primary, results, "primary")

        if not args.execute_promotion:
            check("controlled promotion executed", False, "preflight only; run with --execute-promotion --acknowledge-destructive", results)
        elif not args.acknowledge_destructive:
            check("promotion acknowledgement", False, "refusing destructive operation without --acknowledge-destructive", results)
        elif not args.promote_command:
            check("promotion command supplied", False, "DR_PROMOTE_COMMAND/--promote-command is required", results)
        else:
            promotion_started = time.monotonic()
            command = shlex.split(args.promote_command)
            proc = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout, check=False)
            check("promotion command succeeded", proc.returncode == 0, (proc.stdout + proc.stderr).strip()[-800:], results)
            writable = wait_until_writable(standby, args.timeout)
            rto = time.monotonic() - promotion_started
            report["rto_seconds"] = round(rto, 3) if writable else None
            check("standby promoted to writable", writable, f"rto_seconds={round(rto, 3)}", results)
            if writable:
                after_counts = counts(standby)
                report["after_counts"] = after_counts
                marker_after = bool(one(standby, "SELECT 1 FROM dr_drill_markers WHERE marker=%s", (marker,)))
                check("marker survives promotion", marker_after, marker, results)
                for table, before in before_counts.items():
                    after = after_counts.get(table)
                    if before is not None and after is not None:
                        check(f"{table} count not lost", after >= before, f"before={before} after={after}", results)
                if args.api_url:
                    ok, detail = health(args.api_url, min(args.timeout, 15.0))
                    check("API ready after failover", ok, detail, results)
                else:
                    check("API recovery probe supplied", False, "--api-url/DR_API_READY_URL is required for qualification", results)
                if args.worker_health_command:
                    w = subprocess.run(shlex.split(args.worker_health_command), capture_output=True, text=True, timeout=args.timeout, check=False)
                    check("worker recovery command", w.returncode == 0, (w.stdout + w.stderr).strip()[-500:], results)
                else:
                    check("worker recovery probe supplied", False, "--worker-health-command/DR_WORKER_HEALTH_COMMAND is required for qualification", results)

        if not args.restore_command or not args.clean_restore_dsn:
            check("clean restore executed", False, "--restore-command and --clean-restore-dsn are required; no restore claim made", results)
        else:
            clean_target = connect(args.clean_restore_dsn)
            clean_marker_before = table_exists(clean_target, "dr_drill_markers") and bool(one(clean_target, "SELECT 1 FROM dr_drill_markers WHERE marker=%s", (marker,)))
            check("clean restore target has no drill marker", not clean_marker_before, marker, results)
            clean_target.close()
            restore_started = time.monotonic()
            restore_proc = subprocess.run(shlex.split(args.restore_command), capture_output=True, text=True, timeout=args.timeout, check=False)
            check("clean restore command succeeded", restore_proc.returncode == 0, "restore output withheld; elapsed=%.3fs" % (time.monotonic() - restore_started), results)
            if restore_proc.returncode == 0:
                restore_db = connect(args.clean_restore_dsn)
                check("clean restore reachable", True, restore_db.driver, results)
                clean_marker = bool(one(restore_db, "SELECT 1 FROM dr_drill_markers WHERE marker=%s", (marker,)))
                check("clean restore contains drill marker", clean_marker, marker, results)
                verify_evidence_invariants(restore_db, results, "clean_restore")
    except Exception as exc:
        check("drill execution", False, f"{type(exc).__name__}: {exc}", results)
    finally:
        for db in (restore_db, standby, primary):
            if db is not None:
                try:
                    db.close()
                except Exception as exc:
                    print(f"database close warning: {type(exc).__name__}", file=sys.stderr)

    if args.require_promotion and not args.execute_promotion:
        report["verdict"] = "FAIL"
    else:
        report["verdict"] = "PASS" if all(item["ok"] for item in results) else "FAIL"
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    write_report(output, report)
    print(f"DR verdict: {report['verdict']} -> {output}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
