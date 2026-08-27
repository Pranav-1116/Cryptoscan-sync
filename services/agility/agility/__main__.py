"""CLI for the agility engine. DB-free: score what is in a JSON file.

    python -m agility inventory.json [--simulate move_to_kms,add_crypto_tests]

File layout: {"evidence": [...], "system": {...}} or a bare evidence list.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agility.simulation import available_actions, simulate_improvements
from agility.system_score import calculate_agility_score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Six-factor crypto agility scorer (offline)")
    parser.add_argument("path", help="JSON file with evidence (+ optional system payload)")
    parser.add_argument("-o", "--output", help="Write the JSON result to this path")
    parser.add_argument(
        "--simulate",
        help=f"comma-separated actions to project: {','.join(available_actions())}",
    )
    args = parser.parse_args(argv)

    payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        evidence = payload.get("evidence") or []
        system = payload.get("system")
    else:
        evidence, system = payload, None
    result = calculate_agility_score(evidence, system)
    if args.simulate:
        actions = [item.strip() for item in args.simulate.split(",") if item.strip()]
        result["simulation"] = simulate_improvements(evidence, system, actions)

    text = json.dumps(result, indent=2, default=str)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text)
    print(
        f"# agility={result['agility_score']} category={result['category']} "
        f"sites={result['total_sites']} version={result['calculation_version']}",
        file=sys.stderr,
    )
    if "simulation" in result:
        sim = result["simulation"]
        print(
            f"# projected={sim['projected']['agility_score']} ({sim['projected']['category']}) "
            f"delta={sim['score_delta']:+d} actions={','.join(sim['actions_applied']) or '-'}",
            file=sys.stderr,
        )
        if sim["unsupported_actions"]:
            print(f"# unsupported actions ignored: {','.join(sim['unsupported_actions'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
