"""The maturity table is complete, honest and in sync with the console."""
from __future__ import annotations

import json
import re
from pathlib import Path

from shared_models.capability_maturity import (
    CAPABILITIES, RETIRED_NAV_ROUTES, TIERS, capability_manifest, counts, tier_of,
)

ROOT = Path(__file__).resolve().parents[3]
APP_TSX = ROOT / "frontend" / "src" / "App.tsx"
LAYOUT_TSX = ROOT / "frontend" / "src" / "components" / "Layout.tsx"
MATURITY_TS = ROOT / "frontend" / "src" / "lib" / "maturity.ts"


def _routes_in_app() -> set[str]:
    return set(re.findall(r'path="/([a-z0-9-]+)"', APP_TSX.read_text("utf-8")))


def test_every_console_route_has_a_tier():
    missing = sorted(_routes_in_app() - set(CAPABILITIES))
    assert missing == [], f"routes with no maturity tier (defaults to preview, but say so): {missing}"


def test_every_tier_entry_names_a_real_route():
    orphans = sorted(set(CAPABILITIES) - _routes_in_app())
    assert orphans == [], f"tiers for routes App.tsx does not serve: {orphans}"


def test_tiers_are_known_and_every_entry_has_a_rationale():
    for slug, entry in CAPABILITIES.items():
        assert entry["tier"] in TIERS, slug
        assert entry["area"], slug
        assert len(entry["why"]) >= 20, f"{slug}: a tier needs a reason, not a word"


def test_unknown_routes_default_down_to_preview():
    assert tier_of("/never-heard-of-it") == "preview"
    assert tier_of("/cbom?tab=2") == "ga"
    assert tier_of("dev-sec-ops/binaries") == "ga"


def test_not_everything_is_ga():
    """The point of the table: the product does not present 70 surfaces as equal."""
    c = counts()
    assert c["ga"] < len(CAPABILITIES) * 0.6
    assert c["beta"] > 0 and c["preview"] > 0


def test_retired_nav_routes_are_gone_from_the_sidebar():
    layout = LAYOUT_TSX.read_text("utf-8")
    still_linked = [slug for slug in RETIRED_NAV_ROUTES if f'"/{slug}"' in layout]
    assert still_linked == [], f"sidebar links to routes that do not exist: {still_linked}"


def test_sidebar_links_only_to_real_routes():
    layout = LAYOUT_TSX.read_text("utf-8")
    linked = set(re.findall(r'(?:to=|to: )"/([a-z0-9-]+)"', layout))
    dead = sorted(linked - _routes_in_app())
    assert dead == [], f"sidebar links with no route: {dead}"


def test_frontend_copy_matches_the_source_of_truth():
    """frontend/src/lib/maturity.ts carries the same table (generated JSON)."""
    ts = MATURITY_TS.read_text("utf-8")
    blob = re.search(r"CAPABILITIES_JSON = (\{.*?\}) as const;", ts, re.S)
    assert blob, "maturity.ts must embed CAPABILITIES_JSON"
    theirs = json.loads(blob.group(1))
    ours = {slug: entry["tier"] for slug, entry in CAPABILITIES.items()}
    assert theirs == ours, "run: python scripts/gen_capability_maturity.py"


def test_manifest_shape():
    m = capability_manifest()
    assert m["schema_version"] == 1
    assert set(m["tiers"]) == {"ga", "beta", "preview"}
    assert m["default_for_unknown"] == "preview"
    assert all(row["route"].startswith("/") for row in m["capabilities"])
