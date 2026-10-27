#!/usr/bin/env python3
"""Explicit read-only selected-estate HTTP workload; no scan, key minting or retry.
Credentials are read from an existing environment variable, never CLI arguments,
report files or logs. Run only against an operator-approved disposable workload.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # Never forward credentials to another origin or login page.


def run(base, estate, token, duration, workers):
    until = time.monotonic() + duration
    lock = threading.Lock()
    samples, counts, sizes, scope_mismatches = [], {}, [], 0
    def worker(_):
        nonlocal scope_mismatches
        opener = urllib.request.build_opener(NoRedirect())
        while time.monotonic() < until:
            request = urllib.request.Request(base + "/api/v1/assurance/operator-decisions?limit=25", headers={
                "Authorization": "Bearer " + token, "X-Tenant-ID": estate, "Accept": "application/json"})
            started = time.perf_counter(); size, status, mismatch = 0, 0, False
            try:
                with opener.open(request, timeout=15) as response:
                    status = response.status
                    data = response.read(4 * 1048576 + 1); size = len(data)
                    if size > 4 * 1048576:
                        status = 0
                    elif status == 200:
                        body = json.loads(data)
                        mismatch = body.get("estate_id") != estate
                        if mismatch: status = 0
            except urllib.error.HTTPError as exc:
                status = exc.code; exc.close()
            except (OSError, ValueError):
                status = 0
            elapsed = (time.perf_counter() - started) * 1000
            with lock:
                counts[status] = counts.get(status, 0) + 1
                if len(samples) < 10000:
                    samples.append(elapsed); sizes.append(size)
                if mismatch: scope_mismatches += 1
            # Bounded offered load and no retry storm after a 429.
            time.sleep(1.0 if status == 429 else .1)
    with ThreadPoolExecutor(workers) as pool:
        list(pool.map(worker, range(workers)))
    ordered = sorted(samples)
    total = sum(counts.values())
    errors = sum(n for status, n in counts.items() if status != 200)
    return {"schema": "cryptoscan.operator-http-workload/1", "created_at": datetime.now(timezone.utc).isoformat(),
        "target_origin": base, "estate_id": estate, "duration_requested_seconds": duration, "workers": workers,
        "requests": total, "by_status": counts, "http_throttled": counts.get(429, 0), "failed_or_throttled": errors,
        "scope_mismatches": scope_mismatches, "latency_samples": len(samples), "samples_truncated": total > len(samples),
        "sample_p95_ms": ordered[max(0, int(len(ordered) * .95 + .9999) - 1)] if ordered else None,
        "response_bytes_sample_total": sum(sizes), "capacity_qualified": False,
        "not_measured": ["Upstream provider throttling (HTTP 429 here measures this API only)", "Parser/container resources",
            "Redis contention/fault recovery", "Actual browser endurance", "PostgreSQL storage retention growth"]}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", required=True); ap.add_argument("--tenant-id", required=True)
    ap.add_argument("--token-env", default="CRYPTOSCAN_WORKLOAD_TOKEN")
    ap.add_argument("--seconds", type=int, default=60); ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    parsed = urllib.parse.urlsplit(args.base_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
            or parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}):
        ap.error("use a credential-free HTTPS origin (HTTP is loopback-only)")
    if not 1 <= args.seconds <= 3600 or not 1 <= args.workers <= 32 or not re.fullmatch(r"[a-zA-Z0-9._-]{1,36}", args.tenant_id):
        ap.error("duration 1..3600s, workers 1..32 and a bounded estate identifier required")
    token = os.environ.get(args.token_env, "")
    if not token or args.out.exists():
        ap.error("existing authorized token env and a new output filename required")
    report = run(args.base_url.rstrip("/"), args.tenant_id, token, args.seconds, args.workers)
    data = (json.dumps(report, indent=2) + "\n").encode()
    with args.out.open("xb") as stream:
        os.chmod(args.out, 0o600); stream.write(data)
    print(json.dumps({"report": str(args.out), "sha256": hashlib.sha256(data).hexdigest(), "capacity_qualified": False}))
    return 1 if report["failed_or_throttled"] or not report["requests"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
