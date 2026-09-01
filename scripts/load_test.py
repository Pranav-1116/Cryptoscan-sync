#!/usr/bin/env python3
"""Load test for a running CryptoScan API — bank-estate-shaped traffic.

Mixed workload against one base URL:

- N virtual users, each looping: dashboard status poll, monitor targets list,
  payment summary, occasional synchronous scan-now probe;
- reports latency percentiles, throughput, and error rate;
- honest exit: nonzero if error rate exceeds the threshold.

This is a capacity probe for the API tier, not a scanner benchmark — scan
throughput is measured by ``scripts/benchmark_scan.py``.
"""

from __future__ import annotations

from _bootstrap import bootstrap  # noqa: E402

bootstrap()

import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable

DEFAULT_URL = "http://localhost:8010"


class Result:
    def __init__(self) -> None:
        self.latencies: list[float] = []
        self.errors = 0
        self.throttled = 0
        self.requests = 0
        self.lock = threading.Lock()

    def record(self, elapsed: float, status: int) -> None:
        with self.lock:
            self.requests += 1
            if status == 429:
                self.throttled += 1
            elif not 200 <= status < 500:
                self.errors += 1
            if status != 429:  # throttled responses are not latency-representative
                self.latencies.append(elapsed)


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[index]


def make_client(base_url: str, token: str) -> Callable[[str, str | None], tuple[int, float]]:
    def call(path: str, method: str = "GET") -> tuple[int, float]:
        request = urllib.request.Request(base_url + path, method=method)
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        request.add_header("Content-Type", "application/json")
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                response.read()
                return response.status, time.perf_counter() - started
        except urllib.error.HTTPError as exc:
            exc.read()
            return exc.code, time.perf_counter() - started
        except Exception:
            return 0, time.perf_counter() - started

    return call


def login(base_url: str, username: str, password: str) -> str:
    request = urllib.request.Request(
        base_url + "/api/v1/auth/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read()).get("token", "")


def worker(call: Callable, result: Result, stop_at: float, scan_target_id: str | None) -> None:
    paths = [
        "/api/v1/monitor/status",
        "/api/v1/monitor/targets",
        "/api/v1/payment-crypto/summary",
        "/api/v1/stats/overview",
    ]
    iteration = 0
    while time.time() < stop_at:
        path = paths[iteration % len(paths)]
        if scan_target_id and iteration % 8 == 7:
            status, elapsed = call(f"/api/v1/monitor/targets/{scan_target_id}/scan-now", "POST")
        else:
            status, elapsed = call(path)
        result.record(elapsed, status)
        iteration += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--users", type=int, default=10, help="concurrent virtual users")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="")
    parser.add_argument("--scan-target", default="", help="monitor target id for scan-now probes")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    args = parser.parse_args()

    if not args.password:
        print("--password required (read API credentials from your secret store)", file=sys.stderr)
        return 2
    token = login(args.url, args.username, args.password)
    if not token:
        print("login failed", file=sys.stderr)
        return 2

    call = make_client(args.url, token)
    result = Result()
    stop_at = time.time() + args.duration
    threads = [
        threading.Thread(target=worker, args=(call, result, stop_at, args.scan_target or None), daemon=True)
        for _ in range(args.users)
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - started

    error_rate = result.errors / result.requests if result.requests else 1.0
    # NOTE: rate limiting is active in production mode (600 req/min/identity);
    # a high throttled_429 share means the *budget* was the ceiling, not capacity.
    print(json.dumps({
        "requests": result.requests,
        "duration_s": round(wall, 1),
        "throughput_rps": round(result.requests / wall, 1),
        "errors": result.errors,
        "error_rate": round(error_rate, 4),
        "throttled_429": result.throttled,
        "latency_ms": {
            "p50": round(percentile(result.latencies, 0.50) * 1000, 1),
            "p90": round(percentile(result.latencies, 0.90) * 1000, 1),
            "p99": round(percentile(result.latencies, 0.99) * 1000, 1),
            "max": round(max(result.latencies) * 1000, 1) if result.latencies else 0,
        },
        "mean_ms": round(statistics.fmean(result.latencies) * 1000, 1) if result.latencies else 0,
    }, indent=2))
    return 0 if error_rate <= args.max_error_rate else 1


if __name__ == "__main__":
    raise SystemExit(main())
