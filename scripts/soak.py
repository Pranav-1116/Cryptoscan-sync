#!/usr/bin/env python3
"""Soak the running stack and record evidence.

A soak is not a load test: it runs *representative* work for a long time and
watches for the things that only show up over hours — memory creep, leaked
connections, a queue that stops draining, a chain that stops verifying, an
SSE stream that stalls. Every cycle exercises the real pipeline end to end:

  1. queue a scan through the API (Redis job queue → worker → 12 stages)
  2. wait for COMPLETED; record the wall time and the stage the job died on
  3. verify the scan's evidence chain (SHA-256 content/chain/manifest)
  4. read the dashboards a human would (stats, findings, drift, CBOM)
  5. materialise + export the Technology BOM (signed export)
  6. read the SSE stream for a few seconds and count real events
  7. sample process RSS / open fds / DB connections / Redis memory / queue depth

Every cycle appends one JSON line to ``<out>/cycles.jsonl``; ``summary.json``
is rewritten after each cycle so a dashboard (or a person) can look at any
time. ``scripts/soak_report.py`` turns the directory into a Markdown report.

    python scripts/soak.py --hours 168 --out docs/soak-evidence/2026-09-23
    python scripts/soak.py --cycles 3 --out /tmp/soak-smoke      # quick check

Honest by construction: a cycle that cannot complete is recorded as a failure
with the reason, never skipped; the summary reports failure counts and the
worst latencies, not just the averages.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


import argparse
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Api:
    def __init__(self, base: str, username: str, password: str, timeout: float = 15.0):
        self.base = base.rstrip("/")
        self.username, self.password = username, password
        self.timeout = timeout
        self.token: str | None = None

    def _req(self, method: str, path: str, body: dict | None = None, raw: bool = False,
             headers: dict | None = None, timeout: float | None = None):
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"Content-Type": "application/json"}
        if self.token:
            hdrs["Authorization"] = f"Bearer {self.token}"
        hdrs.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=hdrs)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                payload = resp.read()
                status = resp.status
                resp_headers = dict(resp.headers)
        except urllib.error.HTTPError as exc:
            payload, status, resp_headers = exc.read(), exc.code, dict(exc.headers or {})
        ms = (time.perf_counter() - started) * 1000
        if raw:
            return status, payload, ms, resp_headers
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = {"_raw": payload[:200].decode(errors="replace")}
        return status, parsed, ms, resp_headers

    def login(self) -> None:
        status, body, _ms, _h = self._req("POST", "/api/v1/auth/login",
                                          {"username": self.username, "password": self.password})
        if status != 200 or not body or not body.get("token"):
            raise RuntimeError(f"login failed: {status} {body}")
        self.token = body["token"]

    def get(self, path: str, **kw):
        status, body, ms, headers = self._req("GET", path, **kw)
        if status == 401:  # session expired mid-soak: re-login once
            self.login()
            status, body, ms, headers = self._req("GET", path, **kw)
        return status, body, ms, headers

    def post(self, path: str, body: dict | None = None, **kw):
        status, out, ms, headers = self._req("POST", path, body, **kw)
        if status == 401:
            self.login()
            status, out, ms, headers = self._req("POST", path, body, **kw)
        return status, out, ms, headers


# ----------------------------------------------------------------- sampling

def _read_pid(stage: Path, name: str) -> int | None:
    try:
        return int((stage / "run" / f"{name}.pid").read_text().strip())
    except Exception as _handler_exc:
        logger.debug(
            "expected_exception_boundary",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


def _proc_sample(pid: int | None) -> dict:
    if not pid:
        return {"alive": False}
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        rss_kb = next((int(l.split()[1]) for l in status.splitlines() if l.startswith("VmRSS:")), 0)
        threads = next((int(l.split()[1]) for l in status.splitlines() if l.startswith("Threads:")), 0)
        fds = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        return {"alive": True, "pid": pid, "rss_mb": round(rss_kb / 1024, 1), "fds": fds, "threads": threads}
    except Exception:
        return {"alive": False, "pid": pid}


def _pg_sample(url: str) -> dict:
    try:
        import sqlalchemy as sa

        eng = sa.create_engine(url, pool_pre_ping=True)
        with eng.connect() as conn:
            conns = conn.execute(sa.text("select count(*) from pg_stat_activity where datname = current_database()")).scalar()
            size = conn.execute(sa.text("select pg_database_size(current_database())")).scalar()
            counts = {}
            for table in ("scans", "evidence_records", "scan_jobs", "monitor_events", "drift_events", "audit_log"):
                try:
                    counts[table] = conn.execute(sa.text(f"select count(*) from {table}")).scalar()
                except Exception:
                    conn.rollback()
            dead = conn.execute(sa.text("select coalesce(sum(n_dead_tup),0) from pg_stat_user_tables")).scalar()
        eng.dispose()
        return {"connections": conns, "size_mb": round(size / 1048576, 1), "rows": counts, "dead_tuples": int(dead)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:200]}


def _redis_sample(url: str, queue_key: str) -> dict:
    try:
        import redis

        r = redis.Redis.from_url(url, socket_timeout=3)
        info = r.info("memory")
        clients = r.info("clients")
        return {"used_memory_mb": round(info["used_memory"] / 1048576, 2),
                "connected_clients": clients["connected_clients"],
                "queue_depth": r.llen(queue_key)}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)[:200]}


# ------------------------------------------------------------------- cycle

def run_cycle(api: Api, args, cycle_no: int, stage: Path) -> dict:
    rec: dict = {"cycle": cycle_no, "started_at": now(), "steps": {}, "failures": []}
    t0 = time.perf_counter()

    def fail(step: str, why: str) -> None:
        rec["failures"].append({"step": step, "why": why[:400]})

    # 1. queue a scan
    status, body, ms, _ = api.post("/api/v1/scans/trigger", {"repo_url": args.target, "branch": "main"})
    rec["steps"]["trigger"] = {"status": status, "ms": round(ms, 1)}
    job_id = (body or {}).get("job_id") if status in (200, 202) else None
    if not job_id:
        fail("trigger", f"HTTP {status}: {body}")

    # 2. wait for the job
    scan_id = None
    if job_id:
        deadline = time.time() + args.job_timeout
        final = None
        while time.time() < deadline:
            status, job, _ms, _ = api.get(f"/api/v1/jobs/{job_id}")
            if status == 200 and job and job.get("status") in ("COMPLETED", "FAILED"):
                final = job
                break
            time.sleep(2)
        if final is None:
            fail("job", f"job {job_id} did not finish within {args.job_timeout}s")
            rec["steps"]["job"] = {"status": "TIMEOUT", "job_id": job_id}
        else:
            prog = final.get("progress") or {}
            rec["steps"]["job"] = {
                "status": final.get("status"), "job_id": job_id, "scan_id": final.get("scan_id"),
                "stage": prog.get("current_stage"), "error": (final.get("error_message") or "")[:300],
                "wall_s": _job_wall(final),
            }
            if final.get("status") != "COMPLETED":
                fail("job", f"{final.get('status')} at {prog.get('current_stage')}: {final.get('error_message')}")
            scan_id = final.get("scan_id")

    # 3. verify the chain
    if scan_id:
        status, ver, ms, _ = api.get(f"/api/v1/scans/{scan_id}/verify")
        ok = status == 200 and bool(ver) and ver.get("chain_intact") is True and ver.get("result") == "PASS"
        rec["steps"]["verify"] = {"status": status, "ms": round(ms, 1), "records": (ver or {}).get("records"),
                                  "chain_intact": (ver or {}).get("chain_intact"), "result": (ver or {}).get("result")}
        if not ok:
            fail("verify", f"HTTP {status}: {ver}")

    # 4. dashboards
    reads = {}
    for name, path in (
        ("stats", "/api/v1/stats/summary"),
        ("scans", "/api/v1/scans?page_size=20"),
        ("findings", "/api/v1/findings?page_size=50"),
        ("drift", "/api/v1/drift?page_size=20"),
        ("jobs", "/api/v1/jobs?page_size=20"),
        ("monitor", "/api/v1/monitor/status"),
        ("scope", "/api/v1/platform/scope"),
        ("capabilities", "/api/v1/platform/capabilities"),
        ("health", "/readyz"),
        ("metrics", "/metrics"),
    ):
        status, _body, ms, _ = api.get(path)
        reads[name] = {"status": status, "ms": round(ms, 1)}
        if status >= 500 or status == 0:
            fail(f"read:{name}", f"HTTP {status}")
    rec["steps"]["reads"] = reads

    # 5. technology BOM: live view + signed export
    status, bom, ms, _ = api.get("/api/v1/technology-bom")
    rec["steps"]["bom_live"] = {"status": status, "ms": round(ms, 1),
                                "components": (bom or {}).get("total_components") if isinstance(bom, dict) else None}
    if status >= 500:
        fail("bom_live", f"HTTP {status}")
    status, exp, ms, headers = api.get("/api/v1/technology-bom/export?fmt=cyclonedx&layer=all")
    signed = isinstance(exp, dict) and bool(exp.get("signature_hmac") or exp.get("integrity_sha256"))
    rec["steps"]["bom_export"] = {"status": status, "ms": round(ms, 1), "signed": signed}
    if status >= 500 or (status == 200 and not signed):
        fail("bom_export", f"HTTP {status}, signed={signed}")

    # 6. SSE: does the stream deliver?
    rec["steps"]["sse"] = _sse_probe(api, seconds=args.sse_seconds)
    if rec["steps"]["sse"].get("error"):
        fail("sse", rec["steps"]["sse"]["error"])

    # 7. resources
    env = _staging_env(stage)
    rec["resources"] = {
        "api": _proc_sample(_read_pid(stage, "api")),
        "worker": _proc_sample(_read_pid(stage, "worker")),
        "monitor": _proc_sample(_read_pid(stage, "monitor")),
        "postgres": _pg_sample(env.get("DATABASE_URL", "")) if env.get("DATABASE_URL") else {},
        "redis": _redis_sample(env.get("REDIS_URL", ""), env.get("SCAN_JOB_QUEUE_KEY", "cryptoscan:jobs:queue"))
        if env.get("REDIS_URL") else {},
    }
    for name in ("api", "worker", "monitor"):
        if not rec["resources"][name].get("alive"):
            fail(f"process:{name}", "not running")

    rec["ok"] = not rec["failures"]
    rec["cycle_s"] = round(time.perf_counter() - t0, 1)
    rec["finished_at"] = now()
    return rec


def _job_wall(job: dict) -> float | None:
    try:
        s = datetime.fromisoformat(job["started_at"].replace("Z", "+00:00"))
        e = datetime.fromisoformat(job["completed_at"].replace("Z", "+00:00"))
        return round((e - s).total_seconds(), 3)
    except Exception as _handler_exc:
        logger.debug(
            "expected_exception_boundary",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None


def _sse_probe(api: Api, seconds: float) -> dict:
    """Read the event stream for a few seconds; count frames and real events."""
    req = urllib.request.Request(api.base + "/api/v1/events/stream",
                                 headers={"Authorization": f"Bearer {api.token}", "Accept": "text/event-stream"})
    frames = events = 0
    first_ms = None
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=seconds + 5) as resp:
            resp.fp.raw._sock.settimeout(1.0)  # type: ignore[attr-defined]
            while time.perf_counter() - started < seconds:
                try:
                    line = resp.readline()
                except Exception as _handler_exc:
                    logger.debug(
                        "expected_exception_boundary",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    continue
                if not line:
                    break
                frames += 1
                if first_ms is None:
                    first_ms = round((time.perf_counter() - started) * 1000, 1)
                if line.startswith(b"data:"):
                    events += 1
        return {"frames": frames, "events": events, "first_frame_ms": first_ms, "seconds": seconds}
    except Exception as exc:  # noqa: BLE001
        return {"frames": frames, "events": events, "error": f"{type(exc).__name__}: {exc}"[:200]}


def _staging_env(stage: Path) -> dict:
    env: dict[str, str] = {}
    f = stage / "staging.env"
    if f.is_file():
        for line in f.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    return env


# ----------------------------------------------------------------- summary

def summarize(out: Path, started_at: str, meta: dict) -> dict:
    cycles = [json.loads(l) for l in (out / "cycles.jsonl").read_text().splitlines() if l.strip()]
    ok = [c for c in cycles if c.get("ok")]
    job_walls = [c["steps"]["job"]["wall_s"] for c in cycles
                 if c["steps"].get("job", {}).get("wall_s") is not None]
    read_ms = [v["ms"] for c in cycles for v in c["steps"].get("reads", {}).values()]
    verify = [c["steps"].get("verify", {}) for c in cycles if c["steps"].get("verify")]
    rss = {n: [c["resources"][n].get("rss_mb") for c in cycles if c.get("resources", {}).get(n, {}).get("rss_mb")]
           for n in ("api", "worker", "monitor")}
    fds = {n: [c["resources"][n].get("fds") for c in cycles if c.get("resources", {}).get(n, {}).get("fds")]
           for n in ("api", "worker", "monitor")}
    pg_conns = [c["resources"]["postgres"].get("connections") for c in cycles
                if c.get("resources", {}).get("postgres", {}).get("connections") is not None]
    queue = [c["resources"]["redis"].get("queue_depth") for c in cycles
             if c.get("resources", {}).get("redis", {}).get("queue_depth") is not None]
    failures: dict[str, int] = {}
    for c in cycles:
        for f in c.get("failures", []):
            failures[f["step"]] = failures.get(f["step"], 0) + 1

    def pct(xs, p):
        if not xs:
            return None
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]

    first, last = (cycles[0]["started_at"], cycles[-1]["finished_at"]) if cycles else (started_at, now())
    elapsed_h = round((datetime.fromisoformat(last) - datetime.fromisoformat(first)).total_seconds() / 3600, 2) if cycles else 0
    return {
        "meta": meta,
        "started_at": started_at, "updated_at": now(), "elapsed_hours": elapsed_h,
        "cycles": len(cycles), "cycles_ok": len(ok), "cycles_failed": len(cycles) - len(ok),
        "failure_counts": failures,
        "scans": {"completed": sum(1 for c in cycles if c["steps"].get("job", {}).get("status") == "COMPLETED"),
                  "failed": sum(1 for c in cycles if c["steps"].get("job", {}).get("status") == "FAILED"),
                  "timed_out": sum(1 for c in cycles if c["steps"].get("job", {}).get("status") == "TIMEOUT"),
                  "wall_s_p50": pct(job_walls, 50), "wall_s_p95": pct(job_walls, 95), "wall_s_max": max(job_walls) if job_walls else None},
        "evidence_chain": {"verified": sum(1 for v in verify if v.get("chain_intact") is True),
                           "broken": sum(1 for v in verify if v.get("chain_intact") is False),
                           "records_total": sum(v.get("records") or 0 for v in verify)},
        "api_reads": {"count": len(read_ms), "ms_p50": pct(read_ms, 50), "ms_p95": pct(read_ms, 95),
                      "ms_p99": pct(read_ms, 99), "ms_max": max(read_ms) if read_ms else None,
                      "errors_5xx": sum(1 for c in cycles for v in c["steps"].get("reads", {}).values() if v["status"] >= 500)},
        "sse": {"probes": sum(1 for c in cycles if c["steps"].get("sse")),
                "with_frames": sum(1 for c in cycles if (c["steps"].get("sse") or {}).get("frames", 0) > 0),
                "errors": sum(1 for c in cycles if (c["steps"].get("sse") or {}).get("error"))},
        "rss_mb": {n: {"first": xs[0], "last": xs[-1], "max": max(xs),
                       "growth_pct": round((xs[-1] - xs[0]) / xs[0] * 100, 1) if xs[0] else None}
                   for n, xs in rss.items() if xs},
        "fds": {n: {"first": xs[0], "last": xs[-1], "max": max(xs)} for n, xs in fds.items() if xs},
        "postgres_connections": {"min": min(pg_conns), "max": max(pg_conns)} if pg_conns else None,
        "queue_depth": {"max": max(queue), "last": queue[-1]} if queue else None,
        "postgres_last": cycles[-1]["resources"].get("postgres") if cycles else None,
        "redis_last": cycles[-1]["resources"].get("redis") if cycles else None,
    }


# -------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default=os.environ.get("SOAK_API", "http://127.0.0.1:8010"))
    ap.add_argument("--username", default=os.environ.get("SOAK_USERNAME", "admin"))
    ap.add_argument("--password", default=os.environ.get("SOAK_PASSWORD") or os.environ.get("STAGING_ADMIN_PASSWORD", ""))
    ap.add_argument("--staging-dir", default=os.environ.get("CRYPTOSCAN_STAGING_DIR", "/tmp/cryptoscan-staging"))
    ap.add_argument("--target", default=os.environ.get("SOAK_TARGET", ""), help="authorized repo_url to scan each cycle")
    ap.add_argument("--hours", type=float, default=None, help="run for this long (default: forever / --cycles)")
    ap.add_argument("--cycles", type=int, default=None, help="stop after N cycles")
    ap.add_argument("--interval", type=float, default=300, help="seconds between cycle starts")
    ap.add_argument("--job-timeout", type=float, default=600)
    ap.add_argument("--sse-seconds", type=float, default=6)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if not args.target:
        ap.error("--target or SOAK_TARGET is required; no bundled source is available")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stage = Path(args.staging_dir)
    if not args.password:
        args.password = _staging_env(stage).get("STAGING_ADMIN_PASSWORD", "")
    api = Api(args.api, args.username, args.password)
    api.login()

    started_at = now()
    meta = {"api": args.api, "target": args.target, "interval_s": args.interval,
            "hours_requested": args.hours, "cycles_requested": args.cycles,
            "git": _git_head(), "host": os.uname().nodename, "python": sys.version.split()[0]}
    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    stop = {"now": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__("now", True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("now", True))

    deadline = time.time() + args.hours * 3600 if args.hours else None
    n = 0
    while not stop["now"]:
        n += 1
        cycle_start = time.time()
        try:
            rec = run_cycle(api, args, n, stage)
        except Exception as exc:  # noqa: BLE001 — the harness itself must not die
            rec = {"cycle": n, "started_at": now(), "ok": False, "steps": {},
                   "failures": [{"step": "harness", "why": f"{type(exc).__name__}: {exc}"[:400]}], "finished_at": now()}
        with (out / "cycles.jsonl").open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        summary = summarize(out, started_at, meta)
        (out / "summary.json").write_text(json.dumps(summary, indent=2))
        flag = "ok " if rec.get("ok") else "FAIL"
        job = rec["steps"].get("job", {})
        print(f"[{now()}] cycle {n:>4} {flag} job={job.get('status')} wall={job.get('wall_s')}s "
              f"verify={rec['steps'].get('verify', {}).get('chain_intact')} "
              f"api_rss={rec.get('resources', {}).get('api', {}).get('rss_mb')}MB "
              f"worker_rss={rec.get('resources', {}).get('worker', {}).get('rss_mb')}MB "
              f"fails={[f['step'] for f in rec.get('failures', [])]}", flush=True)
        if args.cycles and n >= args.cycles:
            break
        if deadline and time.time() >= deadline:
            break
        sleep_for = max(0.0, args.interval - (time.time() - cycle_start))
        end = time.time() + sleep_for
        while time.time() < end and not stop["now"]:
            time.sleep(min(5.0, end - time.time()))
    summary = summarize(out, started_at, meta)
    summary["ended_at"] = now()
    summary["stopped_by"] = "signal" if stop["now"] else "limit"
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("cycles", "cycles_ok", "cycles_failed", "elapsed_hours", "failure_counts")}))
    return 0 if summary["cycles_failed"] == 0 else 1


def _git_head() -> str:
    try:
        import subprocess

        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
