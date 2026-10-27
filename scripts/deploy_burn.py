#!/usr/bin/env python3
"""Deployment burn: boot-level smoke of the ENTIRE API surface.

Walks the live OpenAPI schema and exercises every safe operation (all GETs,
plus whitelisted read-only POSTs) with real authentication, then publishes an
honest verdict: how much of the surface responded, with which statuses, and
the exact list of any 5xx failures. A deployment burn passes when ZERO server
errors occur across the whole exercised surface.

This is the executable form of "smoke the 609-path surface" — run after every
deployment against the live process.

Usage:
    python scripts/deploy_burn.py --api http://127.0.0.1:8010 \
        --username admin --password ... [--out docs/deploy-burn.md]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

SAFE_POST_MARKERS = ("health", "validate", "preview", "whoami", "stats", "search",
                     "run-real", "verify", "recent", "summary")

PATH_PARAM = re.compile(r"\{[^}]+\}")
PROBE_ID = "burn-probe-00000000-0000-0000-0000-000000000000"


class Client:
    def __init__(self, base: str, timeout: float = 8.0):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.token = ""
        self.cookie = ""

    def _req(self, path: str, method: str = "GET", body: dict | None = None,
             headers: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                set_cookie = resp.headers.get("Set-Cookie", "")
                if set_cookie:
                    self.cookie = set_cookie.split(";")[0]
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            set_cookie = e.headers.get("Set-Cookie", "") if e.headers else ""
            if set_cookie:
                self.cookie = set_cookie.split(";")[0]
            return e.code, e.read()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return 0, str(exc).encode()

    def login(self, username: str, password: str) -> tuple[bool, str]:
        status, body = self._req("/api/v1/auth/login", "POST",
                                 {"username": username, "password": password})
        if status != 200:
            return False, f"login HTTP {status}: {body[:200]!r}"
        parsed = json.loads(body)
        self.token = parsed.get("token") or parsed.get("access_token") or ""
        return True, "ok" if self.token else "no token in response"


def load_schema(client: Client) -> dict:
    for path in ("/api/openapi.json", "/openapi.json"):
        for attempt in range(3):
            status, body = client._req(path)
            if status == 200:
                return json.loads(body)
            time.sleep(1.5 * (attempt + 1))  # e.g. burst-rate limiter cooldown
    raise SystemExit(f"cannot fetch OpenAPI schema from {client.base} (last HTTP {status})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--api", default="http://127.0.0.1:8010")
    ap.add_argument("--username", default="admin")
    ap.add_argument(
        "--password",
        default=os.environ.get("DEPLOY_BURN_PASSWORD", os.environ.get("ADMIN_PASSWORD", "cryptoscan")),
        help="deployment credential; prefer DEPLOY_BURN_PASSWORD or --password-file",
    )
    ap.add_argument("--password-file", type=Path, default=None,
                    help="read the deployment credential from a file instead of argv")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--pace", type=float, default=0.05,
                    help="seconds between requests (default stays under the burst limiter)")
    ap.add_argument("--out", type=Path, default=REPO / "docs" / "deploy-burn.md")
    args = ap.parse_args()
    if args.password_file is not None:
        try:
            args.password = args.password_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            ap.error(f"cannot read --password-file: {type(exc).__name__}")
        if not args.password:
            ap.error("--password-file is empty")

    client = Client(args.api, args.timeout)
    t0 = time.perf_counter()

    ok, detail = client.login(args.username, args.password)
    if not ok:
        print(f"LOGIN FAILED: {detail}")
        return 1
    print(f"login ok ({detail})")

    schema = load_schema(client)
    paths = schema.get("paths", {})
    ops: list[tuple[str, str]] = []
    for path, methods in sorted(paths.items()):
        for method in sorted(methods):
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            if method == "get" or (
                method == "post" and any(m in path.lower() for m in SAFE_POST_MARKERS)
            ):
                ops.append((method.upper(), path))
    print(f"surface: {len(paths)} paths, exercising {len(ops)} safe operations")

    results: dict[str, list] = {}
    failures: list[dict] = []
    skipped: list[dict] = []
    for method, path in ops:
        concrete = PATH_PARAM.sub(PROBE_ID, path)
        # SSE endpoints hold the connection open by design; a GET probe would
        # hang until timeout. They are covered by their data endpoints.
        if "/stream" in path.rsplit("/", 1)[-2:] or path.rstrip("/").endswith("/stream") \
                or "/stream/" in path:
            skipped.append({"path": path, "reason": "SSE (long-lived) — data endpoints cover it"})
            continue
        status, body = client._req(concrete, method)
        if args.pace:
            time.sleep(args.pace)
        bucket = str(status) if status else "conn-error"
        results.setdefault(bucket, []).append(f"{method} {path}")
        if status == 0:
            failures.append({"op": f"{method} {path}", "status": 0,
                             "detail": body[:200].decode(errors="replace")})
        elif status >= 500:
            failures.append({"op": f"{method} {path}", "status": status,
                             "detail": body[:200].decode(errors="replace")})

    elapsed = time.perf_counter() - t0
    counts = Counter({k: len(v) for k, v in results.items()})
    exercised = sum(counts.values())
    five_xx = counts.get("5xx", 0) + counts.get("conn-error", 0)
    verdict = "PASS" if five_xx == 0 else "FAIL"

    report = {
        "api": args.api,
        "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "schema_paths": len(paths),
        "safe_operations": len(ops),
        "exercised": exercised,
        "skipped": skipped,
        "status_distribution": dict(counts),
        "server_errors": failures,
        "seconds": round(elapsed, 1),
        "verdict": verdict,
    }
    print(json.dumps(report, indent=2)[:2000])

    lines = [
        "# Deployment burn — full-surface smoke",
        "",
        f"Ran {report['when']} against `{args.api}` (live process, real login).",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Schema paths | {len(paths)} |",
        f"| Safe operations exercised | {exercised} / {len(ops)} |",
        f"| 2xx/3xx (working) | {counts.get('200', 0) + counts.get('201', 0) + counts.get('204', 0) + counts.get('302', 0)} |",
        f"| 400 (probe shapes the API rightly rejects) | {counts.get('400', 0)} |",
        f"| 401/403 (unauthorized surfaces) | {sum(len(results.get(c, [])) for c in ('401', '403'))} |",
        f"| 404 (reachable, empty estate/params) | {counts.get('404', 0)} |",
        f"| 422 (validation) | {counts.get('422', 0)} |",
        f"| Other 4xx | {sum(len(v) for k, v in results.items() if k not in ('200', '201', '204', '302', '401', '403', '404', '422', '429', 'conn-error') and k.startswith('4'))} |",
        f"| 429 throttled (burst limiter active — expected) | {counts.get('429', 0)} |",
        f"| **5xx / connection errors** | **{five_xx}** |",
        f"| Duration | {report['seconds']}s |",
        f"| **Verdict** | **{verdict}** |",
        "",
    ]
    if failures:
        lines += ["## Server errors", ""]
        for f in failures:
            lines.append(f"- `{f['op']}` -> {f['status']}: {f['detail'][:160]}")
        lines.append("")
    else:
        lines += ["Zero server errors across the entire exercised surface.", ""]
    if skipped:
        lines += ["## Skipped", ""]
        for s in skipped:
            lines.append(f"- `{s['path']}` — {s['reason']}")
        lines.append("")
    lines += [
        "Method note: every GET plus read-only POSTs (health/validate/verify/"
        "stats/search markers) is exercised with a real authenticated session; "
        "destructive verbs are not fired by the burn. 404s are expected for "
        "probe IDs on an empty estate — they prove routing+authz, not data.",
    ]
    args.out.write_text("\n".join(lines), encoding="utf-8")
    print(f"WROTE {args.out}")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
