#!/usr/bin/env python3
"""Render the capability maturity table to the console and the docs.

Source of truth: shared_models/capability_maturity.py. This writes:

- frontend/src/lib/maturity.ts     (route → tier + the stated limit, embedded as JSON)
- docs/CAPABILITY-MATURITY.md      (the human-readable table)

Every shipped surface is supported; ``why`` carries the limit that used to be a
"beta" badge, so the limitation survives the vocabulary change.

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
    limits = {
        slug: {"area": entry["area"], "limit": entry["why"]}
        for slug, entry in sorted(CAPABILITIES.items())
    }
    limits_blob = json.dumps(limits, indent=2)
    return f'''/* GENERATED — do not edit. Source: shared_models/capability_maturity.py
 * Regenerate: python scripts/gen_capability_maturity.py
 *
 * Support status of every console surface. Every shipped surface is "ga"; the
 * sidebar does not label pages. CAPABILITY_LIMITS carries the sentence that
 * says what each surface does not do — that is the honest part, and /scope
 * renders it. Unknown routes default down to "preview".
 * The API serves the same table with rationale at
 * GET /api/v1/platform/capabilities. */

export type Tier = "ga" | "beta" | "preview";

export const TIER_LABEL: Record<Tier, string> = {json.dumps({k: v["label"] for k, v in TIERS.items()})};

export const TIER_DETAIL: Record<Tier, string> = {json.dumps({k: v["detail"] for k, v in TIERS.items()}, indent=2)};

export const CAPABILITIES_JSON = {blob} as const;

/** route slug -> the limit stated with that surface (rendered on /scope). */
export const CAPABILITY_LIMITS = {limits_blob} as const;

export type CapabilityLimit = {{ area: string; limit: string }};

export const RETIRED_NAV_ROUTES: readonly string[] = {json.dumps([f"/{s}" for s in RETIRED_NAV_ROUTES])};

/** Tier for a pathname such as "/cbom" or "/dev-sec-ops?tab=1". */
export function tierOf(pathname: string): Tier {{
  const slug = pathname.replace(/^\\/+/, "").split("/")[0].split("?")[0];
  return (CAPABILITIES_JSON as Record<string, Tier>)[slug] ?? "preview";
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
        "# Capability record — every console surface, and what it does not do",
        "",
        "> Generated from `shared_models/capability_maturity.py` by",
        "> `scripts/gen_capability_maturity.py`. Served live at",
        "> `GET /api/v1/platform/capabilities`.",
        "",
        f"**{c['ga']} shipped surfaces, all supported.** The navigation carries no maturity",
        "badges: a product's sidebar is not the place to negotiate what is proven. What",
        "used to be a `beta` or `preview` label is now the **stated limit** column below,",
        "which is the part that actually told an operator something. A support statement",
        "and a completeness statement are different claims, and only the first one is",
        "uniform across the product.",
        "",
        "Unknown routes still default **down** to `preview`, never up: a route nobody",
        "wrote a rationale for is not something we have decided to support.",
        "",
        "The sidebar is organized into six sections: **Overview, Discovery, Intelligence,",
        "Governance, Output and Administration**. Deep-linked routes remain in this",
        "record without being duplicated in the sidebar. See the [Navigation & Feature",
        "Reference](NAVIGATION-FEATURE-REFERENCE.md) for the route-to-page map and",
        "role-guarded actions.",
        "",
        "| Route | Area | What it is, and its stated limit |",
        "|---|---|---|",
    ]
    for slug, entry in sorted(CAPABILITIES.items(), key=lambda kv: (kv[1]["area"], kv[0])):
        lines.append(f"| `/{slug}` | {entry['area']} | {entry['why']} |")
    lines += [
        "",
        "## Retired sidebar entries",
        "",
        "These used to appear in the navigation but had no page behind them (they",
        "redirected to the dashboard). They are removed, and a test keeps them out:",
        "",
    ]
    lines += [f"- `/{slug}`" for slug in RETIRED_NAV_ROUTES]
    lines += [
        "",
        "## Changing an entry",
        "",
        "1. Edit `shared_models/capability_maturity.py` (status + a real rationale).",
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
