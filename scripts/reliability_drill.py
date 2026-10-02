#!/usr/bin/env python3
"""Reliability and failure behaviour against a running stack.

update.md section 4: "This is the difference from 'works in a demo' to 'safe
to operate'." It asks for timeouts and resource limits, idempotency, restart
and recovery, and load/soak.

This covers the first three. Load/soak is deliberately not here: section 4
wants 24-72 hours against the target topology, and a laptop run that finishes
in minutes would produce numbers that look like a capacity qualification and
are not one. scripts/soak.py and scripts/load_test.py exist for that, and
they need the real environment.

    bash scripts/run_local_stack.sh up
    python scripts/reliability_drill.py --out docs/readiness-evidence/reliability.json

Every check drives the live stack and reads the result back from PostgreSQL
or the API. The report carries its own limits in a `scope` field.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _req(method: str, url: str, token: str | None = None, body: Any = None,
         timeout: float = 60.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw.strip().startswith(("{", "[")) else raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, raw
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def _psql(container: str, user: str, sql: str) -> str:
    out = subprocess.run(
        ["docker", "exec", "-u", "postgres", container, "psql", "-U", user, "-tAc", sql],
        capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


class Drill:
    def __init__(self, args):
        self.api = args.api.rstrip("/")
        self.db = args.db_container
        self.db_user = args.db_user
        self.redis = args.redis_container
        self.target = args.target
        self.checks: list[dict] = []
        self.token: str | None = None

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {str(detail)[:110]}")
        return bool(ok)

    def login(self, user: str, pw: str) -> bool:
        s, b = _req("POST", f"{self.api}/api/v1/auth/login", body={"username": user, "password": pw})
        self.token = b.get("token") if isinstance(b, dict) else None
        return self.check("auth: session established", s == 200 and bool(self.token), f"HTTP {s}")

    def _scan(self, target: str | None = None) -> tuple[str | None, float]:
        """Trigger a scan, wait for terminal state. Returns (scan_id, seconds)."""
        started = time.monotonic()
        s, b = _req("POST", f"{self.api}/api/v1/scans/trigger", self.token,
                    {"repo_url": target or self.target, "branch": "main"})
        if s not in (200, 202) or not isinstance(b, dict):
            return None, time.monotonic() - started
        job = b.get("job_id")
        for _ in range(240):
            _s, j = _req("GET", f"{self.api}/api/v1/jobs/{job}", self.token)
            if isinstance(j, dict) and j.get("status") in ("COMPLETED", "FAILED"):
                return (j.get("scan_id") if j.get("status") == "COMPLETED" else None,
                        time.monotonic() - started)
            time.sleep(1)
        return None, time.monotonic() - started

    # ---- idempotency ------------------------------------------------------ #
    def idempotency(self) -> None:
        """The same scan twice must add history, not corrupt it."""
        first, t1 = self._scan()
        second, t2 = self._scan()
        self.check("idempotency: both runs complete", bool(first and second),
                   f"{t1:.1f}s then {t2:.1f}s")
        if not (first and second):
            return

        self.check("idempotency: each run gets its own scan id", first != second,
                   f"{first[:8]} != {second[:8]}")

        a = int(_psql(self.db, self.db_user,
                      f"SELECT count(*) FROM evidence_records WHERE scan_id='{first}'") or 0)
        b = int(_psql(self.db, self.db_user,
                      f"SELECT count(*) FROM evidence_records WHERE scan_id='{second}'") or 0)
        self.check("idempotency: identical input yields identical finding counts",
                   a == b and a > 0, f"{a} vs {b}")

        # Evidence hashes must be stable across runs of the same input: the
        # same code should hash the same, or drift detection is meaningless.
        ha = _psql(self.db, self.db_user,
                   f"SELECT md5(string_agg(content_hash, ',' ORDER BY content_hash)) "
                   f"FROM evidence_records WHERE scan_id='{first}'")
        hb = _psql(self.db, self.db_user,
                   f"SELECT md5(string_agg(content_hash, ',' ORDER BY content_hash)) "
                   f"FROM evidence_records WHERE scan_id='{second}'")
        self.check("idempotency: evidence content hashes are stable across runs",
                   bool(ha) and ha == hb, f"{ha[:16]}... vs {hb[:16]}...")

        # Known open issue, kept failing on purpose rather than relaxed.
        #
        # A scan of jjwt stores 3067 evidence rows for 3049 distinct
        # content hashes: 18 observations (0.6%) are recorded twice at the
        # same file:line. It is deterministic -- the same 18 every run, which
        # is why the hash-stability check above passes -- and most likely two
        # detection paths (AST and regex) agreeing on one line. The smaller
        # SNB fixture shows zero.
        #
        # Not silently tolerated here because the inflated number is what
        # reaches finding counts, compliance percentages and CBOM component
        # totals. Whether the right answer is a unique index on
        # (scan_id, content_hash) or merging at emission is a product
        # decision, so the drill reports it and leaves it visible.
        dupes = int(_psql(self.db, self.db_user,
                          "SELECT count(*) FROM (SELECT scan_id, content_hash FROM evidence_records "
                          "GROUP BY 1,2 HAVING count(*) > 1) d") or 0)
        self.check("idempotency: no duplicate content_hash within a scan",
                   dupes == 0,
                   f"{dupes} duplicated (scan_id, content_hash) pairs — known open issue, "
                   f"inflates finding counts")

    # ---- limits and refusals ---------------------------------------------- #
    def limits(self) -> None:
        """Bad or oversized input must be refused, not crash the service."""
        cases = [
            ("a path outside the source roots", {"repo_url": "/etc", "branch": "main"}),
            ("a nonexistent path", {"repo_url": "/no/such/tree", "branch": "main"}),
            ("an empty target", {"repo_url": "", "branch": "main"}),
            ("a traversal attempt", {"repo_url": "../../../../etc/shadow", "branch": "main"}),
        ]
        for label, body in cases:
            s, b = _req("POST", f"{self.api}/api/v1/scans/trigger", self.token, body, timeout=60)
            # Refused outright, or accepted and then failed honestly. What
            # must not happen is a 5xx, or a silent success.
            refused = s in (400, 403, 404, 422)
            self.check(f"limits: {label} is refused", refused, f"HTTP {s}")

        s, _ = _req("GET", f"{self.api}/health", timeout=20)
        self.check("limits: API still healthy after bad input", s == 200, f"HTTP {s}")

    def timeouts(self) -> None:
        """A network probe against a black hole must time out, not hang."""
        started = time.monotonic()
        # 198.51.100.0/24 is TEST-NET-2 (RFC 5737): routable-looking, nothing
        # answers. A probe that lacks a timeout hangs here forever.
        s, b = _req("POST", f"{self.api}/api/v1/network-scans", self.token,
                    {"hosts": ["198.51.100.42:443"], "live": True, "timeout": 5},
                    timeout=90)
        elapsed = time.monotonic() - started
        self.check("timeouts: an unreachable TLS target returns rather than hanging",
                   s != 0 and elapsed < 80, f"HTTP {s} after {elapsed:.1f}s")
        # The host does not exist, so the probe must say so. Asserting on the
        # recorded status rather than on string absence: an earlier version
        # searched the body for the IP, which is present either way, so it
        # could not distinguish "probed and unreachable" from "reported fine".
        probes = (b.get("probes") or b.get("findings") or []) if isinstance(b, dict) else []
        statuses = {str(p.get("status") or p.get("severity") or "").upper()
                    for p in probes if isinstance(p, dict)}
        telemetry = (b.get("probe_telemetry") or {}) if isinstance(b, dict) else {}
        claimed_ok = telemetry.get("ok", 0)
        self.check(
            "timeouts: the unreachable host is not recorded as a successful probe",
            claimed_ok == 0,
            f"probe_telemetry.ok={claimed_ok} statuses={sorted(statuses)[:4]}",
        )

    # ---- restart and recovery --------------------------------------------- #
    def worker_restart(self) -> None:
        """Killing the worker mid-flight must not lose or duplicate the job."""
        before = int(_psql(self.db, self.db_user, "SELECT count(*) FROM scans") or 0)
        pid = subprocess.run(["pgrep", "-f", "worker.main"],
                             capture_output=True, text=True).stdout.split()
        if not pid:
            self.check("restart: worker process found", False, "no worker running")
            return
        self.check("restart: worker process found", True, f"pid {pid[0]}")

        s, b = _req("POST", f"{self.api}/api/v1/scans/trigger", self.token,
                    {"repo_url": self.target, "branch": "main"})
        job = b.get("job_id") if isinstance(b, dict) else None
        time.sleep(1)
        subprocess.run(["kill", "-9", pid[0]], capture_output=True)
        self.check("restart: worker killed mid-scan", True, f"SIGKILL {pid[0]}")

        # Bring it back the way the stack script does.
        env = {k: v for k, v in __import__("os").environ.items()}
        env.update({
            "PYTHONPATH": ":".join(str(p) for p in sorted(ROOT.glob("services/*/"))
                                   + list(sorted(ROOT.glob("shared/*/")))),
            "ENVIRONMENT": "development",
            "DATABASE_URL": env.get("DATABASE_URL", ""),
        })
        subprocess.Popen([sys.executable, "-m", "worker.main"], cwd=str(ROOT), env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)
        alive = bool(subprocess.run(["pgrep", "-f", "worker.main"],
                                    capture_output=True, text=True).stdout.strip())
        self.check("restart: worker comes back", alive, "")

        # The job must reach a terminal state, not sit QUEUED forever.
        terminal = None
        for _ in range(180):
            _s, j = _req("GET", f"{self.api}/api/v1/jobs/{job}", self.token)
            if isinstance(j, dict) and j.get("status") in ("COMPLETED", "FAILED"):
                terminal = j.get("status")
                break
            time.sleep(1)
        self.check("restart: the in-flight job reaches a terminal state",
                   terminal is not None, f"status={terminal}")

        after = int(_psql(self.db, self.db_user, "SELECT count(*) FROM scans") or 0)
        self.check("restart: the killed job did not produce duplicate scan rows",
                   after - before <= 1, f"scans {before} -> {after}")

    def db_outage(self) -> None:
        """Readiness must drop while PostgreSQL is away, and recover."""
        subprocess.run(["docker", "pause", self.db], capture_output=True, timeout=60)
        try:
            time.sleep(2)
            s, _ = _req("GET", f"{self.api}/healthz", timeout=25)
            self.check("db outage: liveness stays up (the process is fine)",
                       s == 200, f"HTTP {s}")
            s2, b2 = _req("GET", f"{self.api}/readyz", timeout=25)
            self.check("db outage: readiness drops so a load balancer drains it",
                       s2 == 503, f"HTTP {s2}")
        finally:
            subprocess.run(["docker", "unpause", self.db], capture_output=True, timeout=60)
            time.sleep(3)
        for _ in range(60):
            s3, _ = _req("GET", f"{self.api}/readyz", timeout=20)
            if s3 == 200:
                break
            time.sleep(1)
        self.check("db outage: readiness returns after the database comes back",
                   s3 == 200, f"HTTP {s3}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--api", default="http://127.0.0.1:8010")
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="cryptoscan")
    p.add_argument("--db-container", default="cryptoscan-local-db")
    p.add_argument("--db-user", default="cryptoscan")
    p.add_argument("--redis-container", default="cryptoscan-local-redis")
    p.add_argument("--target", default=str(ROOT / "_tmp" / "snbchk" / "src"))
    p.add_argument("--skip-destructive", action="store_true",
                   help="skip worker kill and database pause")
    p.add_argument("--out")
    args = p.parse_args()

    d = Drill(args)
    if not d.login(args.username, args.password):
        print("\nCannot continue without a session. Is the stack up?", file=sys.stderr)
        return 2

    d.idempotency()
    d.limits()
    d.timeouts()
    if not args.skip_destructive:
        d.worker_restart()
        d.db_outage()

    failed = [c for c in d.checks if not c["ok"]]
    verdict = "PASS" if not failed else "FAIL"
    report = {
        "schema": "cryptoscan.reliability-drill/1",
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "checks": d.checks,
        "passed": len(d.checks) - len(failed),
        "failed": len(failed),
        "verdict": verdict,
        "scope": (
            "Covers update.md section 4's idempotency, limits/timeouts and "
            "restart/recovery on one host. It does NOT cover load and soak: "
            "that section asks for 24-72 hours against the target topology, "
            "and a run that finishes in minutes on a laptop would produce "
            "numbers resembling a capacity qualification without being one. "
            "Use scripts/soak.py and scripts/load_test.py in the real "
            "environment for that."
        ),
    }
    print(f"\nReliability: {verdict} ({report['passed']}/{len(d.checks)} checks)")
    print(report["scope"])
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"-> {out}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
