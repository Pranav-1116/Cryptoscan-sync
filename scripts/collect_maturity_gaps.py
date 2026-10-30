#!/usr/bin/env python
"""Close the four carried-over maturity gaps *through the API*, and show the delta.

What this driver does — and does not do:

* it talks to a **running CryptoScan API** over HTTP. All collection happens inside
  that API process, so the evidence lands in the stored observation and every BOM,
  matrix and coverage row re-projects from it. Nothing is written to the database
  from here and no number is computed here: every table below is echoed from the
  API's own response.
* a collector that cannot run here says so and is skipped, with the reason printed.
  A gap therefore closes only when a producer exists — this script never upgrades a
  matrix row on its own.

Examples
--------
Capabilities only (no collection, safe anywhere)::

    .venv/bin/python scripts/collect_maturity_gaps.py --capabilities

Network plane against the banking sandbox's live TLS services::

    .venv/bin/python scripts/collect_maturity_gaps.py --network --targets 127.0.0.1:21000-21015

Runtime plane on this host, traced (real INVOCATION evidence)::

    .venv/bin/python scripts/collect_maturity_gaps.py --runtime --trace /bin/openssl version

Windows plane from a host's own exports::

    .venv/bin/python scripts/collect_maturity_gaps.py --windows-artifacts ./win/schannel.reg --windows-artifacts ./win/suites.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Iterable

DEFAULT_API = os.environ.get("CRYPTOSCAN_API_URL", "http://127.0.0.1:8010")


# --------------------------------------------------------------------------- #
# tiny HTTP client (stdlib only: this script must run where the app is running)
# --------------------------------------------------------------------------- #
class Api:
    def __init__(self, base: str, token: str | None = None) -> None:
        self.base = base.rstrip("/")
        self.token = token

    def _call(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=600) as response:
                raw = response.read().decode()
                return response.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, raw
        except urllib.error.URLError as exc:
            raise SystemExit(f"cannot reach {url}: {exc.reason} — is the API running?") from exc

    def get(self, path: str) -> Any:
        status, payload = self._call("GET", path)
        if status >= 400:
            raise SystemExit(f"GET {path} -> {status}: {_reason(payload)}")
        return payload

    def post(self, path: str, body: Any) -> tuple[int, Any]:
        return self._call("POST", path, body)

    def login(self, user: str, password: str) -> None:
        status, payload = self._call("POST", "/api/v1/auth/login",
                                     {"username": user, "password": password})
        if status >= 400 or not isinstance(payload, dict) or not payload.get("token"):
            raise SystemExit(f"login failed ({status}): {_reason(payload)}")
        self.token = payload["token"]


def _reason(payload: Any) -> str:
    if isinstance(payload, dict):
        detail = payload.get("detail", payload)
        if isinstance(detail, dict):
            return str(detail.get("reason") or detail.get("error") or detail)
        return str(detail)
    return str(payload)[:400]


def _expand(targets: Iterable[str]) -> list[str]:
    """``127.0.0.1:21000-21015`` -> the sixteen endpoints it names."""
    out: list[str] = []
    for item in targets:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                continue
            match = re.fullmatch(r"(.+):(\d+)-(\d+)", part)
            if match:
                host, start, end = match.group(1), int(match.group(2)), int(match.group(3))
                if end < start or end - start > 4096:
                    raise SystemExit(f"refusing target range {part}: state it explicitly")
                out.extend(f"{host}:{port}" for port in range(start, end + 1))
            else:
                out.append(part)
    return out


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #
def _row(label: str, value: Any, width: int = 34) -> str:
    return f"  {label:<{width}}{value}"


def print_capabilities(caps: dict[str, Any]) -> None:
    print("collectors available in this build")
    for entry in caps.get("collectors") or []:
        state = entry.get("state")
        detail = entry.get("state_reason") or ""
        print(_row(f"{entry['id']} [{state}]", detail or entry.get("label", "")))
        if entry.get("trace"):
            print(_row("  trace mode", f"{entry['trace']['state']} {entry['trace'].get('reason') or ''}".strip()))
    target = caps.get("target_estate") or {}
    print()
    print(_row("target estate", target.get("estate") or target.get("state")))
    if target.get("projection_id"):
        print(_row("projection", target["projection_id"]))
        print(_row("assets / evidence", f"{target.get('assets')} / {target.get('evidence')}"))


def print_collect(result: dict[str, Any]) -> None:
    print()
    print(f"collection into {result.get('estate')!r}"
          f" (merged into stored observation: {result.get('merged_into_stored_observation')})")
    for collector in result.get("collectors") or []:
        interesting = {
            key: value for key, value in collector.items()
            if key in {"targets", "negotiated", "failed", "processes", "libraries",
                       "listening_endpoints", "protocols", "suites", "certificates",
                       "refused", "files", "invocation"}
        }
        print(_row(f"collector {collector.get('id')}", json.dumps(interesting, default=str)))
    counts = result.get("counts") or {}
    print(_row("estate size", f"{counts.get('assets')} assets, {counts.get('evidence')} evidence, "
                              f"{counts.get('relationships')} relationships"))
    maturity = result.get("bom_maturity") or {}
    before, after, changed = maturity.get("before") or {}, maturity.get("after") or {}, maturity.get("changed") or {}
    print()
    print(f"  {'BOM':<10}{'before':<18}{'after':<18}changed")
    for kind, depth in after.items():
        mark = "yes" if kind in changed else ""
        print(f"  {kind:<10}{str(before.get(kind, '—')):<18}{str(depth):<18}{mark}")
    coverage = result.get("coverage") or {}
    targets = coverage.get("targets") if isinstance(coverage, dict) else None
    if targets:
        print()
        print("coverage, per collection target")
        for row in targets:
            status = row.get("status")
            print(_row(f"  {row.get('target')}",
                       f"{status} ({row.get('collected')}/{row.get('expected')})"))
            if status != "COMPLETE" and row.get("impact"):
                print(_row("", row["impact"], width=0))
    print()
    print(f"  note: {maturity.get('note')}")


def print_matrices(api: Api) -> None:
    """The three depth matrices plus the six-BOM one, exactly as the API measures them."""
    print()
    print("matrices, as the API measures them now")

    runtime = api.get("/api/v1/estate/evidence/discovery/runtime-depth")
    observed = runtime.get("observed") or {}
    print(_row("runtime depth", f"finding feed: {observed.get('state')}"
                                f" | rows {observed.get('rows')} | invocation {observed.get('invocation_rows')}"))
    estate = observed.get("estate") or {}
    if estate:
        print(_row("  estate evidence", f"{estate.get('state')} — process/library "
                                        f"{estate.get('process_library_evidence')}, invocation "
                                        f"{estate.get('invocation_evidence')}"))
    for row in runtime.get("paths") or []:
        mark = "" if row.get("depth") == row.get("declared_depth") else "  (measured)"
        print(f"    - {row['id']:<22}{row['depth']}{mark}")

    network = api.get("/api/v1/estate/evidence/discovery/network-protocols")
    rollup = network.get("rollup") or {}
    print(_row("network protocols", f"negotiated {rollup.get('negotiated')}, offered only "
                                    f"{rollup.get('offered_only')}, absent {rollup.get('absent')}"))
    for row in network.get("protocols") or []:
        mark = "" if row.get("strength") == row.get("declared_strength") else "  (measured)"
        print(f"    - {row['id']:<22}{row['strength']:<24}"
              f"{len(row.get('targets') or [])} target(s){mark}")

    windows = api.get("/api/v1/estate/evidence/discovery/windows-collector")
    verdict = windows.get("verdict") or {}
    print(_row("windows collector", f"complete={verdict.get('complete_collector')} — {verdict.get('answer')}"))
    for row in windows.get("layers") or []:
        mark = "" if row.get("state") == row.get("declared_state") else "  (measured)"
        producers = len([p for p in row.get("producers") or [] if p.get("present")])
        print(f"    - {row['id']:<24}{row['state']:<10}{row.get('establishes'):<16}"
              f"{producers} producer(s){mark}")

    maturity = api.get("/api/v1/estate/evidence/discovery/bom-maturity")
    print()
    print("  six BOMs, measured depth (strongest evidence class behind each component)")
    for row in maturity.get("boms") or []:
        by_depth = row.get("by_component_depth") or {}
        spread = ", ".join(f"{k.lower()} {v}" for k, v in sorted(by_depth.items()))
        print(f"    - {row['kind']:<10}{row['depth']:<15}{row.get('components')} components "
              f"({spread}){'  at ceiling' if row.get('at_ceiling') else ''}")

    def _names(value: Any) -> str:
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        if isinstance(value, dict):
            return str(value.get("kind") or value.get("depth") or value)
        return str(value or "")

    deepest, shallowest = maturity.get("deepest"), maturity.get("shallowest")
    if deepest:
        print(_row("  spread", f"deepest {_names(deepest)} | shallowest non-empty "
                               f"{_names(shallowest)} (EMPTY BOMs are listed above, unranked)"))
        print(f"    {maturity.get('claim')}")


# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", default=DEFAULT_API)
    parser.add_argument("--user", default=os.environ.get("CRYPTOSCAN_API_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("ADMIN_PASSWORD") or os.environ.get("CRYPTOSCAN_API_PASSWORD"))
    parser.add_argument("--token", default=os.environ.get("CRYPTOSCAN_API_TOKEN"))
    parser.add_argument("--estate", default=None, help="estate to write into (default: the stored one)")
    parser.add_argument("--scope", default=None)
    parser.add_argument("--merge", action="store_true", default=True,
                        help="merge into the newest stored observation (default)")
    parser.add_argument("--no-merge", dest="merge", action="store_false",
                        help="store this collection as its own observation instead")
    parser.add_argument("--capabilities", action="store_true", help="print what can run here and exit")
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--proc-base", default="/proc")
    parser.add_argument("--trace", nargs=argparse.REMAINDER, default=None,
                        help="command to run under the trace shim (implies --runtime)")
    parser.add_argument("--trace-timeout", type=float, default=120.0)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--targets", nargs="*", default=[], help="HOST:PORT, comma lists and PORT ranges")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--windows-artifacts", action="append", default=[])
    parser.add_argument("--windows-host", default=None)
    parser.add_argument("--no-matrices", action="store_true", help="skip the matrices section")
    args = parser.parse_args(argv)

    api = Api(args.api, args.token)
    if not api.token:
        if not args.password:
            raise SystemExit("no token: pass --token, or --password / ADMIN_PASSWORD to log in")
        api.login(args.user, args.password)

    caps = api.get("/api/v1/estate/evidence/collect/capabilities")
    print_capabilities(caps)
    if args.capabilities:
        return 0

    collectors: list[str] = []
    if args.runtime or args.trace:
        collectors.append("runtime")
    if args.network:
        collectors.append("network")
    if args.windows_artifacts:
        collectors.append("windows")
    if not collectors:
        print("\nnothing selected: pass --runtime, --network, --windows-artifacts (or --capabilities)")
        return 0

    by_id = {row["id"]: row for row in caps.get("collectors") or []}
    for name in list(collectors):
        state = (by_id.get(name) or {}).get("state")
        if name == "runtime" and state == "UNAVAILABLE":
            print(f"\nskipping runtime: {(by_id.get(name) or {}).get('state_reason')}")
            collectors.remove(name)
    if not collectors:
        return 1

    body: dict[str, Any] = {
        "collectors": collectors,
        "estate": args.estate,
        "scope": args.scope,
        "merge": args.merge,
        "proc_base": args.proc_base,
        "trace_timeout": args.trace_timeout,
    }
    if args.trace:
        body["trace_argv"] = list(args.trace)
    if args.network:
        body["targets"] = _expand(args.targets)
        body["timeout"] = args.timeout
        if not body["targets"]:
            print("\nskipping network: --network needs --targets (an empty list would look like an estate "
                  "with no endpoints)")
            collectors.remove("network")
            body["collectors"] = collectors
            if not collectors:
                return 1
    if args.windows_artifacts:
        body["artifacts"] = args.windows_artifacts
        body["windows_host"] = args.windows_host

    status, payload = api.post("/api/v1/estate/evidence/collect", body)
    if status >= 400:
        print(f"\ncollection refused ({status}): {_reason(payload)}")
        if isinstance(payload, dict) and isinstance(payload.get("detail"), dict):
            print(json.dumps(payload["detail"], indent=2))
        return 1
    print_collect(payload)
    if not args.no_matrices:
        print_matrices(api)
    return 0


if __name__ == "__main__":
    sys.exit(main())
