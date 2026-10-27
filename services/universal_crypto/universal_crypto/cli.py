"""§36 CLI — run the Universal Cryptography Scanner from the shell.

Deterministic, no AI. Supports scanning a file/directory of source code,
a JSON scan request (full §36 pipeline input), and accuracy evaluation
over the bundled ground-truth datasets.

Examples::

    python -m universal_crypto.cli scan path/to/src --language python
    python -m universal_crypto.cli scan request.json
    python -m universal_crypto.cli scan request.json --json -o report.json
    python -m universal_crypto.cli accuracy
    python -m universal_crypto.cli accuracy --dataset certificates
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional

from universal_crypto.accuracy import AccuracyPlatform
from universal_crypto.engine import UniversalCryptoEngine


def _language_hint(path: Path) -> str:
    return {
        ".py": "python", ".java": "java", ".js": "javascript",
        ".ts": "typescript", ".c": "c", ".h": "c", ".cpp": "c++",
        ".cc": "c++", ".cs": "csharp", ".go": "go", ".rs": "rust",
        ".swift": "swift", ".kt": "kotlin", ".php": "php", ".rb": "ruby",
        ".scala": "scala", ".hs": "haskell", ".sol": "solidity",
        ".vy": "vyper", ".dart": "dart", ".json": "json", ".yaml": "yaml",
        ".yml": "yaml", ".toml": "toml", ".conf": "conf", ".pem": "pem",
        ".crt": "pem",
    }.get(path.suffix.lower(), "")


def _scan_request(
    engine: UniversalCryptoEngine,
    sources: dict[str, Any],
    policy: str,
) -> dict[str, Any]:
    request = dict(sources)
    request.setdefault("policy", policy)
    return engine.scan(request)


def _scan_paths(engine: UniversalCryptoEngine, paths: list[str],
                language: str, policy: str) -> dict[str, Any]:
    code: list[dict[str, Any]] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and _language_hint(child):
                    code.append({
                        "language": language or _language_hint(child) or "python",
                        "text": child.read_text(errors="replace"),
                        "asset_id": str(child.parent),
                        "location": str(child),
                    })
        elif path.is_file():
            code.append({
                "language": language or _language_hint(path) or "python",
                "text": path.read_text(errors="replace"),
                "asset_id": str(path.parent),
                "location": str(path),
            })
    if not code:
        print("error: no source files found", file=sys.stderr)
        raise SystemExit(1)
    return engine.scan({"source_code": code, "policy": policy})


def _print_report(report: dict[str, Any]) -> None:
    obs = report["observations"]
    print(f"observations:   {len(obs)}")
    print(f"findings:       {len(report['findings'])}")
    print(f"quantum status: {report['quantum_classifications']}")
    print(f"readiness:      {report['readiness']}")
    print(f"agility:        {report['agility']}")
    print(f"unknown crypto: {len(report['unknown_crypto'])}")
    print()
    for finding in report["findings"][:20]:
        print(f"  [{finding['band']}] {finding['algorithm']} @ {finding['where']}")
        print(f"      {finding['what']}")
        print(f"      {finding['recommendation']}")
    print()
    for algorithm, klass in sorted(report["quantum_classifications"].items()):
        print(f"  {algorithm:24s} quantum={klass['quantum_status']:18s} "
              f"priority={klass['migration_priority']}")
    print()
    print("graph:", report["graph"]["nodes"], "nodes /", len(report["graph"]["edges"]), "edges")
    if report["key_lifecycle"]["findings"]:
        print("key lifecycle:", [f["type"] for f in report["key_lifecycle"]["findings"]])


def _cmd_scan(args: argparse.Namespace) -> int:
    engine = UniversalCryptoEngine()
    if args.request:
        raw = sys.stdin.read() if args.request == "-" \
            else Path(args.request).read_text()
        sources = json.loads(raw)
        report = _scan_request(engine, sources, args.policy)
    else:
        report = _scan_paths(engine, args.path, args.language, args.policy)
    payload = json.dumps(report, indent=2, default=str, sort_keys=True)
    if args.output:
        Path(args.output).write_text(payload)
        print(f"report written to {args.output}")
    if args.json:
        print(payload)
        return 0
    _print_report(report)
    return 0


def _cmd_accuracy(args: argparse.Namespace) -> int:
    from universal_crypto.accuracy import default_detector
    platform = AccuracyPlatform()
    detector = default_detector()

    totals: dict[str, float] = {}
    datasets = platform.dataset_names()
    if args.dataset:
        datasets = [d for d in datasets if d == args.dataset]
    for name in datasets:
        result = platform.evaluate_dataset(name, detector)
        overall = result["metrics"]["overall"]
        print(f"{name:20s} prec={overall['precision']:.3f} "
              f"rec={overall['recall']:.3f} f1={overall['f1']:.3f} "
              f"fpr={overall['false_positive_rate']:.3f} "
              f"fnr={overall['false_negative_rate']:.3f} "
              f"cov={overall['coverage']:.2f}")
        for metric in ("precision", "recall", "f1", "false_positive_rate",
                       "false_negative_rate", "coverage"):
            totals.setdefault(metric, 0.0)
            totals[metric] += overall[metric]
    if len(datasets) > 1:
        count = len(datasets)
        print("-" * 72)
        print(f"{'MEAN':20s} " + " ".join(
            f"{m}={totals[m] / count:.3f}" for m in
            ("precision", "recall", "f1", "false_positive_rate",
             "false_negative_rate", "coverage")))
    return 0


def _cmd_simulate(args: argparse.Namespace) -> int:
    from universal_crypto.simulator import MigrationSimulator
    result = MigrationSimulator().simulate(
        current_algorithm=args.current, target_algorithm=args.target,
        protocol=args.protocol, library=args.library, hardware=args.hardware,
        usage=True, current_agility=args.agility)
    print(f"current:  {result['current_algorithm']} "
          f"({result['risk_impact']['current_quantum_status']})")
    print(f"target:   {result['target_algorithm']} "
          f"({result['projected_quantum_status']})")
    print(f"readiness:{result['migration_readiness']}  "
          f"compatible={result['compatible']}")
    print(f"agility:  {result['agility_current']} -> {result['agility_after']} "
          f"(delta {result['agility_delta']:+d})")
    print(f"risk:     {result['risk_impact']['risk_reduction']} reduction")
    for note in result["notes"]:
        print(f"  - {note}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="universal-crypto",
        description="Deterministic Universal Cryptography Scanner (no AI).")
    parser.add_argument("--policy", default="NIST",
                        help="weak-crypto policy: NIST/FIPS/PCI_DSS/EU/UAE/"
                             "ORG/BANK/CUSTOM (default NIST)")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan source paths or a JSON request")
    scan.add_argument("path", nargs="*", help="files/directories to scan")
    scan.add_argument("--request", help="JSON §36 scan request file")
    scan.add_argument("--language", default="",
                      help="language override (auto-detected by extension)")
    scan.add_argument("--json", action="store_true",
                      help="emit the full report as JSON on stdout")
    scan.add_argument("-o", "--output", metavar="FILE",
                      help="write the full JSON report to FILE")
    scan.set_defaults(func=_cmd_scan)

    acc = sub.add_parser("accuracy",
                         help="run the ground-truth accuracy platform")
    # choices derive from the platform itself so every bundled dataset is
    # selectable (and the list can never drift from the data again)
    acc.add_argument("--dataset",
                     choices=AccuracyPlatform().dataset_names(),
                     help="evaluate one dataset only")
    acc.set_defaults(func=_cmd_accuracy)

    sim = sub.add_parser("simulate",
                         help="what-if PQC migration projection")
    sim.add_argument("--current", required=True, help="current algorithm")
    sim.add_argument("--target", required=True, help="candidate algorithm")
    sim.add_argument("--protocol", default="", help="protocol (TLS/SSH/IPsec)")
    sim.add_argument("--library", default="", help="crypto library")
    sim.add_argument("--hardware", default="", help="hardware (HSM/TPM 2.0)")
    sim.add_argument("--agility", type=int, default=50,
                     help="current agility score (default 50)")
    sim.set_defaults(func=_cmd_simulate)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
