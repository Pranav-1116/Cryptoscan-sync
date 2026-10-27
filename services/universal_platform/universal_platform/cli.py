"""Universal Platform CLI — run the combined control plane from the shell.

Deterministic, no AI. Subcommands:

    python -m universal_platform.cli discover request.json
    python -m universal_platform.cli risk [--asset ID]
    python -m universal_platform.cli blast --seed <identity>
    python -m universal_platform.cli whatif --current RSA --target ML-KEM-768
    python -m universal_platform.cli bom
    python -m universal_platform.cli drift baseline.json live.json
    python -m universal_platform.cli security request.json
    python -m universal_platform.cli evidence
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from universal_platform.engine import UniversalPlatform


def _load(path: str) -> dict[str, Any]:
    raw = sys.stdin.read() if path == "-" else Path(path).read_text()
    return json.loads(raw)


def _load_state(platform: UniversalPlatform, path: str) -> None:
    """Rehydrate a platform from a previously saved discovery report."""
    from universal_platform.assets import PlatformAsset

    state = _load(path)
    platform.discovery.assets = {
        (a["domain"], a["identity"]): PlatformAsset(
            asset_type=a["asset_type"], domain=a["domain"],
            identity=a["identity"], attributes=a.get("attributes") or {},
            sources=a.get("sources") or [], evidence=a.get("evidence") or [],
            status=a.get("status") or "ACTIVE",
            related=a.get("related") or [])
        for a in state.get("assets") or []}
    platform.discovery.relationships = state.get("relationships") or []


def _cmd_discover(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    report = platform.discover(_load(args.request))
    if args.state_out:
        Path(args.state_out).write_text(json.dumps(report, default=str, indent=2))
        print(f"state saved to {args.state_out}")
    print(f"assets:      {report['asset_count']}")
    print(f"sources:     {', '.join(report['sources_run'])}")
    print(f"relationships: {report['relationship_count']}")
    print(f"verified:    {sum(report['verified'].values())}/{len(report['verified'])}")
    for asset in report["assets"]:
        print(f"  [{asset['domain']:10s}] {asset['asset_type']:20s} {asset['identity']}")
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    return 0


def _cmd_risk(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    if args.state:
        _load_state(platform, args.state)
    result = platform.risk(args.asset)
    print(f"level={result['level']}  score={result['score']}")
    for factor, detail in result.get("factors", {}).items():
        print(f"  {factor:24s} level={detail['level']} points={detail['points']}")
    if result.get("missing_factors"):
        print("missing:", ", ".join(result["missing_factors"]))
    return 0


def _cmd_blast(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    if args.state:
        _load_state(platform, args.state)
    result = platform.blast(args.seed, args.max_depth)
    print(f"seed: {result['seed']}  affected={result['affected_count']}")
    for domain, items in result["by_domain"].items():
        print(f"  {domain:12s} {len(items)}: {', '.join(items)}")
    if result["business_services_affected"]:
        print("BUSINESS IMPACT:", ", ".join(result["business_services_affected"]))
    return 0


def _cmd_whatif(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    if args.state:
        _load_state(platform, args.state)
    result = platform.what_if(args.current, args.target,
                              args.protocols.split(",") if args.protocols else None)
    print(f"{result['current']} -> {result['target']}: "
          f"feasible={result['feasible']}")
    for name, check in result["checks"].items():
        print(f"  {name:12s} supported={check.get('supported')} {check}")
    print("plan:")
    for step in result["migration_plan"]["steps"]:
        print(f"    {step}")
    if result["honest_unknowns"]:
        print("unknown (honest):", ", ".join(result["honest_unknowns"]))
    return 0


def _cmd_bom(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    if args.state:
        _load_state(platform, args.state)
    bom = platform.bom()
    print(json.dumps(bom, indent=2, default=str))
    return 0


def _cmd_drift(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    _load(args.baseline)
    live = _load(args.live)
    result = platform.drift_check(live if isinstance(live, dict) and
                                  set(live) & {"network", "cloud", "vendor",
                                               "hardware", "crypto",
                                               "firmware", "certificate",
                                               "protocol", "pqc"}
                                  else {"crypto": live})
    print(f"drift_detected={result['drift_detected']} "
          f"total_changes={result['total_changes']}")
    for category, info in result["categories"].items():
        if info["change_count"]:
            print(f"  {category}: {info['change_count']} changes")
            for change in info["changes"]:
                print(f"    {change}")
    return 0


def _cmd_security(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    decision = platform.enforce(_load(args.request))
    print(f"allowed={decision['allowed']}")
    for violation in decision.get("violations", []):
        print(f"  BLOCKED: {violation}")
    for warning in decision.get("warnings", []):
        print(f"  warn:    {warning}")
    return 0 if decision["allowed"] else 1


def _cmd_evidence(platform: UniversalPlatform, args: argparse.Namespace) -> int:
    result = platform.evidence.verify()
    print(f"chain valid={result['valid']} records={result.get('records', 0)}")
    if result.get("head"):
        print(f"head={result['head'][:16]}…")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="universal-platform",
        description="ZELNX control plane — one system for network, cloud, "
                    "vendor, hardware and cryptography (no AI).")
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("discover", help="run the §1 discovery pipeline")
    d.add_argument("request", help="JSON file with per-domain reports")
    d.add_argument("--json", action="store_true", help="dump the full report")
    d.add_argument("--state-out", default="", help="save discovery state JSON")
    d.set_defaults(func=_cmd_discover)

    r = sub.add_parser("risk", help="§29 risk for one asset or the estate")
    r.add_argument("--asset", default="", help="asset identity (default: estate)")
    r.add_argument("--state", default="", help="discovery state JSON file")
    r.set_defaults(func=_cmd_risk)

    b = sub.add_parser("blast", help="§30 blast-radius analysis")
    b.add_argument("--seed", required=True, help="seed identity (cert/HSM/lib/…)")
    b.add_argument("--max-depth", type=int, default=10)
    b.add_argument("--state", default="", help="discovery state JSON file")
    b.set_defaults(func=_cmd_blast)

    w = sub.add_parser("whatif", help="§31 what-if migration analysis")
    w.add_argument("--current", required=True)
    w.add_argument("--target", required=True)
    w.add_argument("--protocols", default="")
    w.add_argument("--state", default="", help="discovery state JSON file")
    w.set_defaults(func=_cmd_whatif)

    bom = sub.add_parser("bom", help="§21/§22 combined CycloneDX CBOM + HBOM")
    bom.add_argument("--state", default="", help="discovery state JSON file")
    bom.set_defaults(func=_cmd_bom)

    df = sub.add_parser("drift", help="§20 baseline vs live drift")
    df.add_argument("baseline", help="baseline JSON file")
    df.add_argument("live", help="live state JSON file")
    df.set_defaults(func=_cmd_drift)

    s = sub.add_parser("security", help="§33 security-control enforcement")
    s.add_argument("request", help="scan request JSON to validate")
    s.set_defaults(func=_cmd_security)

    e = sub.add_parser("evidence", help="§23 verify the evidence chain")
    e.set_defaults(func=_cmd_evidence)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    platform = UniversalPlatform()
    return args.func(platform, args)


if __name__ == "__main__":
    raise SystemExit(main())
