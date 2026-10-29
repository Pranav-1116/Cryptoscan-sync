"""The capability table is complete, honest and in sync with the console.

Every shipped surface is supported; the honest part is the stated limit, which
this file requires to be present and specific for every route."""
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
    """Served console routes — redirect aliases excluded (no surface of their own)."""
    text = APP_TSX.read_text("utf-8")
    routes = set()
    for match in re.finditer(r'<Route path="/([a-z0-9-]+)" element=\{([^}]*)', text):
        slug, element = match.groups()
        if element.strip().startswith("<Navigate"):
            continue  # legacy-bookmark alias: it renders nothing, its target carries the tier
        routes.add(slug)
    return routes


def _redirect_aliases_in_app() -> dict[str, str]:
    """Legacy path -> redirect target, for the alias-target pin below."""
    aliases: dict[str, str] = {}
    for match in re.finditer(
            r'<Route path="/([a-z0-9-]+)" element=\{<Navigate to="/([a-z0-9-]+)"',
            APP_TSX.read_text("utf-8")):
        aliases[match.group(1)] = match.group(2)
    return aliases


def test_every_console_route_has_a_tier():
    missing = sorted(_routes_in_app() - set(CAPABILITIES))
    assert missing == [], f"routes with no maturity tier (defaults to preview, but say so): {missing}"


def test_every_redirect_alias_targets_a_tiered_route():
    aliases = _redirect_aliases_in_app()
    assert aliases, "expected the legacy-bookmark aliases to exist in App.tsx"
    dangling = sorted(
        target for target in aliases.values() if target not in CAPABILITIES)
    assert dangling == [], f"redirect aliases pointing at un-tiered routes: {dangling}"


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


def test_every_shipped_surface_is_supported():
    c = counts()
    assert c == {"ga": len(CAPABILITIES), "beta": 0, "preview": 0}


def test_every_surface_states_its_limit_rather_than_carrying_a_badge():
    """A support tier is uniform; the limitation is per surface, in ``why``."""
    for slug, entry in CAPABILITIES.items():
        assert len(entry["why"]) >= 20, f"{slug}: the limit needs a sentence, not a word"
        assert entry["why"].rstrip().endswith("."), slug


def test_the_console_labels_no_page():
    """The shell must not render a maturity pill or banner for any route."""
    layout = LAYOUT_TSX.read_text("utf-8")
    for banned in ("TierPill", "MaturityBanner", "tierOf", "tier-pill"):
        assert banned not in layout, f"the sidebar still renders {banned}"


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
    limits = re.search(r"CAPABILITY_LIMITS = (\{.*?\}) as const;", ts, re.S)
    assert limits, "maturity.ts must embed CAPABILITY_LIMITS"
    assert json.loads(limits.group(1)) == {
        slug: {"area": entry["area"], "limit": entry["why"]} for slug, entry in CAPABILITIES.items()
    }, "run: python scripts/gen_capability_maturity.py"


def test_manifest_shape():
    m = capability_manifest()
    assert m["schema_version"] == 1
    assert set(m["tiers"]) == {"ga", "beta", "preview"}
    assert m["default_for_unknown"] == "preview"
    assert all(row["route"].startswith("/") for row in m["capabilities"])
    # Every served row carries its limit, so /scope cannot show a bare tier.
    assert all(row["why"] for row in m["capabilities"])
