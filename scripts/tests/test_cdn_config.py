"""CDN/origin cache-policy invariants.

The policy (deploy/cdn/cache-policy.json) and the origin
(.docker/frontend/nginx.conf) must say the same thing: hashed bundles
immutable at one agreed max-age, the shell never cached WITH its full
security header set (nginx add_header inheritance drops headers the moment
a location defines its own — the shell's CSP is exactly what that bites),
and every authenticated/streaming path bypasses shared caches.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "deploy" / "cdn" / "cache-policy.json"
NGINX = ROOT / ".docker" / "frontend" / "nginx.conf"


def _policy() -> dict:
    return json.loads(POLICY.read_text())


def _location_block(text: str, name: str) -> str:
    match = re.search(rf"location {re.escape(name)} \{{(.*?)\n    \}}", text, re.S)
    assert match, f"nginx has no location {name} block"
    return match.group(1)


class TestPolicy:

    def test_every_rule_names_an_origin_and_a_cache_decision(self):
        for rule in _policy()["rules"]:
            assert rule["origin"] in ("frontend", "api")
            assert rule["cache"] in ("immutable", "never", "bypass")

    def test_authenticated_and_streaming_paths_bypass_shared_caches(self):
        rules = {r["path"]: r for r in _policy()["rules"]}
        for path in ("/api/", "/ws", "/events"):
            assert rules[path]["cache"] == "bypass", (
                f"{path} is tenant-scoped or endless — a shared cache copy "
                "is a breach or a deadlock")
            assert rules[path]["edge_ttl_seconds"] == 0

    def test_the_shell_is_never_cached(self):
        rules = {r["path"]: r for r in _policy()["rules"]}
        assert rules["/index.html"]["cache"] == "never"
        assert rules["/index.html"]["edge_ttl_seconds"] == 0
        assert rules["/"]["cache"] == "never"

    def test_immutable_names_the_agreed_max_age(self):
        rules = {r["path"]: r for r in _policy()["rules"]}
        assets = rules["/assets/"]
        assert assets["cache"] == "immutable"
        assert "immutable" in assets["cache_control"]
        assert assets["edge_ttl_seconds"] == 2592000


class TestOriginAgreesWithPolicy:

    def test_assets_are_immutable_at_the_policy_max_age(self):
        text = NGINX.read_text()
        block = _location_block(text, "/assets/")
        assert "immutable" in block
        assert "max-age=2592000" in block, (
            "origin and edge must agree on the number — drift here is a "
            "stale-bundle incident waiting for the next deploy")

    def test_the_shell_carries_its_full_security_header_set(self):
        """nginx replaces inherited add_header directives per location: the
        shell must repeat the set itself or it is served WITHOUT CSP — the
        one document where CSP governs everything after it."""
        block = _location_block(NGINX.read_text(), "= /index.html")
        for header in ("Content-Security-Policy", "X-Content-Type-Options",
                       "X-Frame-Options", "Referrer-Policy",
                       "Cache-Control"):
            assert header in block, (
                f"the SPA shell response lost {header} to add_header "
                "inheritance")
        assert "no-store" in block and "must-revalidate" in block

    def test_api_traffic_is_never_cached_at_the_origin(self):
        text = NGINX.read_text()
        for block_name in ("/api/", "/events"):
            block = _location_block(text, block_name)
            assert "proxy_cache off" in block, (
                f"{block_name} must not meet a shared cache, origin or edge")
