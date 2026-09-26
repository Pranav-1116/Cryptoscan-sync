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
        self.by_status: dict[int, int] = {}
        self.lock = threading.Lock()

    def record(self, elapsed: float, status: int) -> None:
        with self.lock:
            self.requests += 1
            self.by_status[status] = self.by_status.get(status, 0) + 1
            if status == 429:
                self.throttled += 1
            elif not 200 <= status < 400:
                # 401/403/404 are errors for a load test: an identity that stops
                # working under load or a probe path that does not exist must
                # not be reported as capacity.
                self.errors += 1
            if status != 429:  # throttled responses are not latency-representative
                self.latencies.append(elapsed)


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[index]


def make_client(base_url: str, token: str, api_key: str = "") -> Callable[[str, str | None], tuple[int, float]]:
    def call(path: str, method: str = "GET") -> tuple[int, float]:
        request = urllib.request.Request(base_url + path, method=method)
        if api_key:
            request.add_header("X-API-Key", api_key)  # own rate-limit identity per virtual user
        elif token:
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
    for attempt in range(5):
        request = urllib.request.Request(
            base_url + "/api/v1/auth/login",
            data=json.dumps({"username": username, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.loads(response.read()).get("token", "")
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < 4:
                time.sleep(3.0 * (attempt + 1))  # burst-limiter cooldown
                continue
            raise
    return ""


def _json(base_url: str, path: str, token: str, method: str, body: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        base_url + path, data=json.dumps(body).encode() if body is not None else None, method=method,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def create_vu_keys(base_url: str, token: str, n: int) -> list[tuple[str, str]]:
    """One machine API key per virtual user, so each VU has its own 600 req/min bucket.

    Sharing the admin session across N users makes the *identity* bucket, not the
    API, the ceiling (every request beyond 600/min is a 429). Keys are read-only,
    scoped to the probe paths, expire in 1 h and are revoked at the end of the run.
    """
    keys: list[tuple[str, str]] = []
    expires = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    for i in range(n):
        status, body = _json(base_url, "/api/v1/api-keys", token, "POST", {
            "name": f"loadtest-vu-{i:03d}-{int(time.time())}", "roles": ["viewer"], "allowed_methods": ["GET", "POST"],
            "scopes": ["/monitor", "/payment-crypto", "/stats"], "expires_at": expires,
        })
        if status != 201 or "raw_key" not in body:
            print(f"api-key create failed for VU {i}: HTTP {status} {body}", file=sys.stderr)
            break
        keys.append((body["id"], body["raw_key"]))
    return keys


def revoke_vu_keys(base_url: str, token: str, keys: list[tuple[str, str]]) -> None:
    for key_id, _ in keys:
        _json(base_url, f"/api/v1/api-keys/{key_id}", token, "DELETE")


def worker(call: Callable, result: Result, stop_at: float, scan_target_id: str | None, rps: float = 0.0) -> None:
    paths = [
        "/api/v1/monitor/status",
        "/api/v1/monitor/targets",
        "/api/v1/payment-crypto/summary",
        "/api/v1/stats/summary",
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
        if rps > 0:  # pace each virtual user like a real client (default 8 rps < 600/min budget)
            time.sleep(max(0.0, 1.0 / rps - elapsed))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--users", type=int, default=10, help="concurrent virtual users")
    parser.add_argument("--duration", type=float, default=30.0, help="seconds")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="")
    parser.add_argument("--scan-target", default="", help="monitor target id for scan-now probes")
    parser.add_argument("--max-error-rate", type=float, default=0.01)
    parser.add_argument("--rps-per-user", type=float, default=8.0,
                        help="pace each VU (0 = unpaced). 8 rps keeps a VU under its 600/min identity budget, "
                             "so throughput scales with --users and 429s mean real saturation")
    parser.add_argument("--identity", choices=["api-keys", "shared-session", "sessions"], default="api-keys",
                        help="api-keys: one machine key per VU (default, measures capacity); "
                             "shared-session: all VUs on the admin token (measures the per-identity budget, expect 429s); "
                             "sessions: one login per VU, staggered for the 5/min login limiter")
    args = parser.parse_args()

    if not args.password:
        print("--password required (read API credentials from your secret store)", file=sys.stderr)
        return 2
    token = login(args.url, args.username, args.password)
    if not token:
        print("login failed", file=sys.stderr)
        return 2

    result = Result()
    clients: list[Callable] = []
    vu_keys: list[tuple[str, str]] = []
    if args.identity == "api-keys":
        vu_keys = create_vu_keys(args.url, token, args.users)
        if len(vu_keys) != args.users:
            revoke_vu_keys(args.url, token, vu_keys)
            print("could not mint one API key per VU (admin role needed); try --identity sessions", file=sys.stderr)
            return 2
        clients = [make_client(args.url, "", raw) for _, raw in vu_keys]
    elif args.identity == "shared-session":
        clients = [make_client(args.url, token) for _ in range(args.users)]
    else:
        # one session per virtual user. The login limiter allows 5/min per
        # source IP (brute-force protection) — stagger logins to fit the
        # budget; never weaken or bypass the platform's own defenses.
        tokens = [token]
        for i in range(1, args.users):
            user_token = login(args.url, args.username, args.password)
            if not user_token:
                print(f"login {i + 1}/{args.users} throttled; reduce --users", file=sys.stderr)
                return 2
            tokens.append(user_token)
            if i < args.users - 1:
                time.sleep(13.0)  # login window: 5/min per IP
        clients = [make_client(args.url, tok) for tok in tokens]
    stop_at = time.time() + args.duration  # soak clock starts after setup
    threads = [
        threading.Thread(target=worker, args=(call, result, stop_at, args.scan_target or None, args.rps_per_user), daemon=True)
        for call in clients
    ]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    wall = time.perf_counter() - started
    if vu_keys:
        revoke_vu_keys(args.url, token, vu_keys)

    error_rate = result.errors / result.requests if result.requests else 1.0
    # NOTE: rate limiting is active in production mode (600 req/min/identity);
    # a high throttled_429 share means the *budget* was the ceiling, not capacity.
    print(json.dumps({
        "identity": args.identity,
        "users": args.users,
        "rps_per_user": args.rps_per_user,
        "requests": result.requests,
        "duration_s": round(wall, 1),
        "throughput_rps": round(result.requests / wall, 1),
        "errors": result.errors,
        "error_rate": round(error_rate, 4),
        "throttled_429": result.throttled,
        "by_status": dict(sorted(result.by_status.items())),
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
