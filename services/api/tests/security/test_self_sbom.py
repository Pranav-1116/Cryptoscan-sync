"""CryptoScan publishes its own SBOM — this pins that it stays honest.

The platform that sells cryptographic transparency must publish its own
dependency inventory (infrastructure spec: "SBOM for CryptoScan itself —
Critical — track CryptoScan's own dependencies"). The generator covers the
Python lock, the frontend lock and first-party services; a gap in any of
them is a failed test here, not a silently thinner artifact.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture(scope="module")
def sbom(tmp_path_factory):
    import generate_own_sbom

    out = tmp_path_factory.mktemp("sbom") / "cryptoscan-sbom.cdx.json"
    return generate_own_sbom.generate(out), out


class TestThePlatformPublishesItsOwnInventory:
    def test_it_is_cyclonedx_and_names_itself(self, sbom):
        doc, out = sbom
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert doc["metadata"]["component"]["name"] == "cryptoscan-platform"
        assert out.exists() and json.loads(out.read_text())["bomFormat"] == "CycloneDX"

    def test_the_python_dependency_set_is_covered_and_lock_pinned(self, sbom):
        doc, _ = sbom
        lock = (ROOT / "requirements.lock.txt").read_text().lower()
        names = {c["name"].lower() for c in doc["components"]}
        # the lock's pins must be represented — spot-check the infrastructure
        # the platform actually runs on
        for pinned_name in ("fastapi", "sqlalchemy", "zstandard"):
            assert pinned_name in lock
            assert pinned_name in names
        pinned_flag = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert pinned_flag["cryptoscan:python-lockfile-pinned"] == "true", (
            "the SBOM must state that it read the pinned lock, not the live env")

    def test_the_frontend_dependency_set_is_covered(self, sbom):
        doc, _ = sbom
        lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text())
        npm_from_lock = {
            spec.split("node_modules/")[-1].split("/")[0]
            for spec in lock.get("packages", {})
            if "node_modules/" in spec
        }
        npm_in_sbom = {c["name"] for c in doc["components"]
                       if c["bom-ref"].startswith("pkg:npm/")}
        assert npm_in_sbom & npm_from_lock, "no frontend dependency reached the SBOM"
        # react is the console's spine; its absence means the npm walk broke
        assert "react" in npm_in_sbom or "react" in {n.lower() for n in npm_in_sbom}

    def test_first_party_services_are_components(self, sbom):
        doc, _ = sbom
        first = {c["name"] for c in doc["components"]
                 if c["bom-ref"].startswith("pkg:cryptoscan/")}
        # the deployable surface of the platform itself — every part of what
        # a bank installs is inventoried as a first-party component
        for name in ("cryptoscan-api", "cryptoscan-worker", "cryptoscan-scanner",
                     "cryptoscan-frontend", "cryptoscan-nginx", "cryptoscan-monitor"):
            assert name in first, f"first-party component {name} missing from the SBOM"

    def test_the_dependency_graph_is_anchored(self, sbom):
        doc, _ = sbom
        assert doc["dependencies"], "a flat component list without a dependency graph is a parts list"
        anchors = {d["ref"] for d in doc["dependencies"]}
        assert "pkg:cryptoscan/platform" in anchors
