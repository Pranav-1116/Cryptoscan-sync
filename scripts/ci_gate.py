#!/usr/bin/env python3
"""Purpose-aware CI drift gate. Exit 1 on FAIL so a PR check can block merge."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


def _api(base: str, path: str, token: str, payload: dict | None = None) -> dict:
    url = base.rstrip("/") + path
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method="GET" if payload is None else "POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"API {exc.code} {url}: {body}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate the CryptoScan PR drift gate")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--api", default=os.environ.get("CRYPTOSCAN_API", "http://127.0.0.1:8000/api/v1"))
    parser.add_argument("--token", default=os.environ.get("CRYPTOSCAN_TOKEN", ""))
    parser.add_argument("--sarif", help="Write SARIF to this path")
    parser.add_argument("--require-baseline", action="store_true")
    parser.add_argument(
        "--profile",
        choices=["standard", "strict", "lenient"],
        default=os.environ.get("CRYPTOSCAN_GATE_PROFILE", "standard"),
        help="Enforcement posture: strict blocks warnings too, lenient only hardcoded keys/downgrades",
    )
    parser.add_argument(
        "--format",
        choices=["json", "pr-comment"],
        default="json",
        help="json for machines, pr-comment renders PR-ready markdown",
    )
    args = parser.parse_args(argv)

    if not args.token:
        print("CRYPTOSCAN_TOKEN (or --token) is required", file=sys.stderr)
        return 2

    gate = _api(
        args.api,
        "/ci/gate",
        args.token,
        {
            "scan_id": args.scan_id,
            "require_baseline": args.require_baseline,
            "profile": args.profile,
        },
    )
    if args.format == "pr-comment":
        # renderer lives with the gate logic; import is DB-free
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "drift"))
        try:
            from drift.core.gate import render_pr_comment
        except ImportError:  # standalone (curl-installed) copy: minimal local render
            def render_pr_comment(g):
                decision = str(g.get("decision") or "UNKNOWN")
                lines = [f"### CryptoScan gate: {decision}", "", str(g.get("summary") or "")]
                for item in (g.get("blocking") or [])[:25]:
                    lines.append(f"- `{item.get('code')}` {item.get('message')} ({item.get('file_path')}:{item.get('line_number')})")
                return "\n".join(lines)

        print(render_pr_comment(gate))
    else:
        json.dump({k: v for k, v in gate.items() if k != "sarif"}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(gate.get("sarif") or {}, indent=2), encoding="utf-8")
    decision = str(gate.get("decision") or "FAIL")
    return 0 if decision in {"PASS", "WARN"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
