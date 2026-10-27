"""Command-line supply-chain gate — the same policy engine the API exposes,
usable between build and deploy:

    python -m devsecops.sbom_gate sbom.cdx.json --policy gate.json
    curl -s .../sbom/<id>/download | python -m devsecops.sbom_gate - --require-minimum-elements

Exit codes (so a pipeline can trust them):

* ``0`` — the document passed every blocker rule
* ``1`` — blocked: the policy's thresholds were crossed
* ``2`` — usage/IO error (bad arguments, unreadable file)
* ``3`` — the document could not be parsed as CycloneDX/SPDX JSON

``--json`` prints the full evaluation (policy, counts, blockers, warnings) so a
pipeline can archive the evidence rather than a log line. Warnings never change
the exit code — they are advisory by design.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from devsecops.sbom_assurance import evaluate_gate

# blocker rules a policy file may set, and the CLI flag that maps to them
FLAGS: tuple[tuple[str, str], ...] = (
    ("allow_critical", "--allow-critical"),
    ("allow_high", "--allow-high"),
    ("max_unpinned", "--max-unpinned"),
)


def load_document(source: str) -> dict[str, Any]:
    """Read an SBOM from a path or from stdin (``-``)."""
    if source == "-":
        raw = sys.stdin.read()
    else:
        with open(source, encoding="utf-8") as handle:
            raw = handle.read()
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("document is not a JSON object")
    if not (document.get("bomFormat") or document.get("spdxVersion")):
        raise ValueError("document declares neither bomFormat nor spdxVersion — not an SBOM")
    return document


def load_policy(path: str | None, args: argparse.Namespace) -> dict[str, Any]:
    policy: dict[str, Any] = {}
    if path:
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError("policy file must contain a JSON object")
        # a policy file may wrap its rules under "policy" for readability
        policy.update(loaded.get("policy") if isinstance(loaded.get("policy"), dict) else loaded)
    for key, flag in FLAGS:
        value = getattr(args, key)
        if value is not None:
            policy[key] = value
    if args.deny_license:
        policy["deny_licenses"] = list(args.deny_license)
    if args.require_minimum_elements:
        policy["require_minimum_elements"] = True
    if args.require_signed:
        policy["require_signed"] = True
    return policy


def render_text(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        f"gate: {report['verdict']}",
        f"  components: {counts['components']}  minimum elements: {counts['minimum_elements']}",
        f"  advisories: critical {counts['CRITICAL']} · high {counts['HIGH']} · "
        f"medium {counts['MEDIUM']} · low {counts['LOW']}",
    ]
    if counts.get("unpinned") is not None:
        lines.append(f"  unpinned components: {counts['unpinned']}")
    for blocker in report["blockers"]:
        lines.append(f"  BLOCK [{blocker['code']}] {blocker['detail']}")
    for warning in report["warnings"]:
        lines.append(f"  warn  [{warning['code']}] {warning['detail']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m devsecops.sbom_gate",
        description="Evaluate an SBOM against a supply-chain gate policy (offline, deterministic).",
    )
    parser.add_argument("sbom", help="CycloneDX/SPDX JSON file, or - to read from stdin")
    parser.add_argument("--policy", metavar="FILE", help="JSON policy file (same keys as DEFAULT_GATE_POLICY)")
    parser.add_argument("--allow-critical", type=int, metavar="N", help="max critical advisories before failing")
    parser.add_argument("--allow-high", type=int, metavar="N", help="max high advisories before failing")
    parser.add_argument("--max-unpinned", type=int, metavar="N", help="max unpinned components before failing")
    parser.add_argument("--unpinned", type=int, metavar="N",
                        help="unpinned component count to apply (the document itself cannot know it)")
    parser.add_argument("--deny-license", action="append", default=[], metavar="ID",
                        help="fail when a component declares this license (repeatable)")
    parser.add_argument("--require-minimum-elements", action="store_true",
                        help="fail on any NTIA minimum-elements gap instead of warning")
    parser.add_argument("--require-signed", action="store_true",
                        help="fail when the artifact is not signed (needs --signed/--unsigned)")
    parser.add_argument("--signed", dest="signed", action="store_true", default=None,
                        help="assert the document is signature-verified")
    parser.add_argument("--unsigned", dest="signed", action="store_false", default=None,
                        help="assert the document carries no verified signature")
    parser.add_argument("--json", action="store_true", help="print the full evaluation as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = load_policy(args.policy, args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"gate: cannot read policy: {exc}", file=sys.stderr)
        return 2
    try:
        document = load_document(args.sbom)
    except json.JSONDecodeError as exc:
        print(f"gate: {args.sbom} is not valid JSON: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"gate: {exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"gate: cannot read {args.sbom}: {exc}", file=sys.stderr)
        return 2
    report = evaluate_gate(document, policy=policy, unpinned=args.unpinned, signed=args.signed)
    print(json.dumps(report, indent=1, sort_keys=True) if args.json else render_text(report))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":  # pragma: no cover - thin wrapper
    raise SystemExit(main())
