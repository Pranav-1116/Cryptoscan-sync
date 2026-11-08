"""OS → SBOM/CBOM/HBOM/TechBOM projection acceptance tests
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §15 step 6).

The projections feed the shared BOM ecosystem — never a seventh
disconnected BOM. provides/uses discipline: the engine emits NO
'uses' edge, ever; a same-host co-location never creates an
application↔kernel relationship (§8). Versions the sources do not
report are unknown, never guessed.
"""

from __future__ import annotations

from pathlib import Path

from os_intelligence.bom import BOM_KINDS, RelationshipProvenance, \
    build_bom
from os_intelligence.collector import collect_linux

_FIXTURES = Path(__file__).parent / "fixtures"
_HOST = (_FIXTURES / "host-linux-sample.txt").read_text()


def _section(name: str) -> str:
    return _HOST.split(f"--- {name}")[1].split("\n---")[0]


def _fixture_inventory(tmp_path):
    root = tmp_path / "root"
    (root / "proc/sys/kernel").mkdir(parents=True)
    (root / "etc").mkdir(parents=True)
    (root / "proc/version").write_text(
        "Linux version 6.1.158+ (u@h) (gcc) #1 SMP x86_64\n")
    (root / "etc/os-release").write_text(_section("os-release"))
    (root / "proc/crypto").write_text(_section("proc-crypto"))
    (root / "proc/modules").write_text(_section("proc-modules"))
    return collect_linux("h", source_root=str(root),
                         collect_hardware_trust=False).as_dict()


class TestProvidesUsesDiscipline:
    def test_no_uses_edge_is_ever_emitted(self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        for kind in BOM_KINDS:
            for rel in build_bom(kind, inv).as_dict()["relationships"]:
                assert rel["relationship"] != "uses", \
                    f"{kind} emitted a uses edge — this engine never does"
                assert rel["relationship"] in ("provides", "contains",
                                               "anchors")

    def test_kernel_provides_implementations_with_the_honest_note(
            self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        cbom = build_bom("cbom", inv).as_dict()
        provides = [r for r in cbom["relationships"]
                    if r["relationship"] == "provides"]
        assert provides
        for r in provides:
            assert r["source"] == "kernel"
            assert "NOT a 'uses' claim" in str(r["limitations"])
            assert r["provenance"] == \
                RelationshipProvenance.DIRECTLY_OBSERVED

    def test_colocation_never_creates_relationships(self):
        inv = {
            "host_id": "h",
            "identity": {"kernel_name": "Linux", "kernel_release": "6.1"},
            "crypto_api": [{"algorithm": "aes", "driver": "aes-generic",
                            "type": "cipher", "module": "kernel"}],
            "modules": [{"name": "payments_engine_related",
                         "used_by": [], "state": "Live"}],
            "coverage": {"sources_collected": ["proc_crypto"]},
        }
        bom = build_bom("techbom", inv).as_dict()
        for rel in bom["relationships"]:
            assert rel["relationship"] != "uses"
            if rel["relationship"] == "contains":
                assert rel["source"] in ("kernel", "os", "host"), \
                    "no module-to-module or app-to-kernel edge is drawn"


class TestHonestComponents:
    def test_module_versions_never_guessed(self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        # synthetic module rows in the real format (the recorded
        # container exposes no readable /proc/modules)
        inv["modules"] = [
            {"name": "aesni_intel", "size": 1, "refcount": 0,
             "used_by": [], "state": "Live"}]
        sbom = build_bom("sbom", inv).as_dict()
        mod = [c for c in sbom["components"]
               if c["type"] == "kernel_module"][0]
        assert mod["version"] == "", "module version is never guessed"
        assert "unknown, never guessed" in str(mod["properties"]
                                               ["limitations"])
        assert "never evidence of which application" in \
            str(mod["properties"]["limitations"])

    def test_unknown_key_size_stays_unknown(self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        cbom = build_bom("cbom", inv).as_dict()
        shash = [c for c in cbom["components"]
                 if c["properties"].get("implementation_type") == "shash"]
        assert shash
        for c in shash:
            if c["properties"]["key_size_bits"] is None:
                assert "key size unknown — never guessed" in \
                    str(c["properties"]["limitations"])

    def test_algorithm_and_driver_distinct_on_components(self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        cbom = build_bom("cbom", inv).as_dict()
        sha384 = [c for c in cbom["components"]
                  if c["properties"].get("generic_algorithm_name")
                  == "sha384"]
        assert len(sha384) >= 2, "recorded host registers sha384 twice"
        drivers = {c["properties"]["implementation_driver"]
                   for c in sha384}
        assert len(drivers) > 1
        assert all("distinct" in str(c["properties"]["limitations"])
                   for c in sha384)

    def test_every_component_carries_the_decisive_field(self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        for kind in BOM_KINDS:
            for c in build_bom(kind, inv).as_dict()["components"]:
                assert c["properties"]["runtime_usage_confirmed"] is False

    def test_hbom_trust_presence_is_never_a_verdict(self):
        inv = {
            "host_id": "h",
            "hardware_trust": [
                {"subject": "tpm", "state": "unavailable",
                 "evidence_class": "unknown", "metadata": {}, "notes": []}],
            "coverage": {"sources_collected": []},
        }
        hbom = build_bom("hbom", inv).as_dict()
        tpm = hbom["components"][0]
        assert tpm["properties"]["state"] == "unavailable"
        assert "never proof of absence" in str(tpm["properties"]
                                              ["limitations"])
        assert "never a trust verdict" in str(tpm["properties"]
                                             ["limitations"])
        anchors = hbom["relationships"][0]
        assert anchors["relationship"] == "anchors"
        assert "not a trust rating" in str(anchors["limitations"])

    def test_hw_acceleration_is_an_indicator(self):
        inv = {
            "host_id": "h",
            "crypto_api": [{"algorithm": "sha256",
                            "driver": "sha256-ni", "type": "shash",
                            "hardware_accelerated": True}],
            "coverage": {"sources_collected": ["proc_crypto"]},
        }
        hbom = build_bom("hbom", inv).as_dict()
        hw = [c for c in hbom["components"]
              if c["type"] == "crypto_hardware"][0]
        assert hw["properties"]["indicator_only"] is True
        assert "INDICATOR from the driver name" in \
            str(hw["properties"]["limitations"])


class TestCoverageAndRefusal:
    def test_empty_inventory_produces_no_fabricated_components(self):
        inv = {"host_id": "h", "coverage":
               {"sources_attempted": [], "sources_collected": [],
                "sources_unavailable": [{"source": "proc_crypto",
                                         "reason": "unavailable"}]}}
        for kind in BOM_KINDS:
            bom = build_bom(kind, inv).as_dict()
            names = [c["name"] for c in bom["components"]]
            assert "unknown OS" not in names or kind == "sbom", \
                "identity-less inventories never invent an OS"
            assert bom["coverage"]["sources_unavailable"], \
                "coverage travels with the projection"

    def test_unknown_kind_is_refused_never_guessed(self):
        try:
            build_bom("vexbom", {"host_id": "h"})
        except ValueError as exc:
            assert "refused" in str(exc) or "expected one of" in str(exc)
        else:
            raise AssertionError("an unknown BOM kind must be refused")

    def test_techbom_is_the_union_with_projections_recorded(
            self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        tech = build_bom("techbom", inv).as_dict()
        assert tech["coverage"]["projections"] == ["sbom", "cbom", "hbom"]
        kinds = {c["type"] for c in tech["components"]}
        assert "kernel" in kinds and "crypto_implementation" in kinds
        assert len(tech["components"]) == len(
            {(c["type"], c["name"], c["version"])
             for c in tech["components"]}), "no duplicate components"

    def test_note_states_the_ecosystem_boundary(self, tmp_path):
        inv = _fixture_inventory(tmp_path)
        for kind in BOM_KINDS:
            note = build_bom(kind, inv).as_dict()["note"]
            assert "never proof of" in note or "NO 'uses' edge" in note
            assert "co-location" in note
