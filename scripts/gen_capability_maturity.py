#!/usr/bin/env python3
"""Render the capability maturity table to the console and the docs.

Source of truth: shared_models/capability_maturity.py. This writes:

- frontend/src/lib/maturity.ts     (route → tier, embedded as JSON)
- docs/CAPABILITY-MATURITY.md      (the human-readable table)

A shared_models test fails when the TS copy drifts, so run this after any
tier change:  python scripts/gen_capability_maturity.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shared" / "shared_models"))

from shared_models.capability_maturity import (  # noqa: E402
    CAPABILITIES, RETIRED_NAV_ROUTES, TIERS, counts,
)

TS_PATH = ROOT / "frontend" / "src" / "lib" / "maturity.ts"
DOC_PATH = ROOT / "docs" / "CAPABILITY-MATURITY.md"


def render_ts() -> str:
    table = {slug: entry["tier"] for slug, entry in sorted(CAPABILITIES.items())}
    blob = json.dumps(table, indent=2)
    return f'''/* GENERATED — do not edit. Source: shared_models/capability_maturity.py
 * Regenerate: python scripts/gen_capability_maturity.py
 *
 * Which console surfaces are GA, beta or preview. The Layout reads this to
 * label every page; unknown routes are "ga" (real system).
 * The API serves the same table with rationale at
 * GET /api/v1/platform/capabilities. */

export type Tier = "ga" | "beta" | "preview";

export const TIER_LABEL: Record<Tier, string> = {json.dumps({k: v["label"] for k, v in TIERS.items()})};

export const TIER_DETAIL: Record<Tier, string> = {json.dumps({k: v["detail"] for k, v in TIERS.items()}, indent=2)};

export const CAPABILITIES_JSON = {blob} as const;

export const RETIRED_NAV_ROUTES: readonly string[] = {json.dumps([f"/{s}" for s in RETIRED_NAV_ROUTES])};

/** Tier for a pathname such as "/cbom" or "/dev-sec-ops?tab=1". */
export function tierOf(pathname: string): Tier {{
  const slug = pathname.replace(/^\\/+/, "").split("/")[0].split("?")[0];
  return (CAPABILITIES_JSON as Record<string, Tier>)[slug] ?? "ga";
}}

export function tierCounts(): Record<Tier, number> {{
  const out: Record<Tier, number> = {{ ga: 0, beta: 0, preview: 0 }};
  for (const tier of Object.values(CAPABILITIES_JSON)) out[tier as Tier] += 1;
  return out;
}}
'''


def render_doc() -> str:
    c = counts()
    lines = [
        "# Capability maturity — what is GA, what is beta, what is preview",
        "",
        "> Generated from `shared_models/capability_maturity.py` by",
        "> `scripts/gen_capability_maturity.py`. Served live at",
        "> `GET /api/v1/platform/capabilities`; the console labels every page from it.",
        "",
        "The platform ships ~50 services and ~70 console surfaces. All surfaces are production-supported and",
        "generally available. Unknown routes default to",
        "**ga** (real system).",
        "",
        "The sidebar is organized into six sections: **Overview, Discovery, Intelligence,",
        "Governance, Output and Administration**. It currently has 32 menu slots and 31",
        "unique primary route paths; deep-linked routes remain in the maturity inventory",
        "without being duplicated in the sidebar. See the [Navigation & Feature",
        "Reference](NAVIGATION-FEATURE-REFERENCE.md) for the route-to-page map and",
        "role-guarded actions.",
        "",
        "| Tier | Meaning | Surfaces |",
        "|---|---|---|",
    ]
    for tier, meta in TIERS.items():
        lines.append(f"| **{meta['label']}** | {meta['detail']} | {c[tier]} |")
    lines += ["", f"Total: {sum(c.values())} surfaces.", ""]
    for tier, meta in TIERS.items():
        lines += [f"## {meta['label']} ({c[tier]})", "", "| Route | Area | Why this tier |", "|---|---|---|"]
        for slug, entry in sorted(CAPABILITIES.items(), key=lambda kv: (kv[1]["area"], kv[0])):
            if entry["tier"] == tier:
                lines.append(f"| `/{slug}` | {entry['area']} | {entry['why']} |")
        lines.append("")
    lines += [
        "## Retired sidebar entries",
        "",
        "These used to appear in the navigation but had no page behind them (they",
        "redirected to the dashboard). They are removed, and a test keeps them out:",
        "",
    ]
    lines += [f"- `/{slug}`" for slug in RETIRED_NAV_ROUTES]
    lines += [
        "",
        "## Changing a tier",
        "",
        "1. Edit `shared_models/capability_maturity.py` (tier + a real rationale).",
        "2. `python scripts/gen_capability_maturity.py`",
        "3. `pytest shared/shared_models/tests/test_capability_maturity.py`",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    TS_PATH.write_text(render_ts(), encoding="utf-8")
    DOC_PATH.write_text(render_doc(), encoding="utf-8")
    print(f"wrote {TS_PATH.relative_to(ROOT)} and {DOC_PATH.relative_to(ROOT)} — {counts()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
