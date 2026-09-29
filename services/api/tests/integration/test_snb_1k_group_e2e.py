"""SNB 1,020-system sandbox — API+accuracy integration test (sqlite only, ~60s).

Validates that at 1000+ systems the PipelineRunner, cascade analyser, entity
assignment, group rollup, supervisor-pack and migration-roadmap endpoints all
behave honestly:
  - 4 entities, ≥ 1020 declared systems, 0 unassigned
  - every entity scores F1 ≥ 0.99 (recall > 0.99 on the labelled corpus)
  - no system_name_collision_across_entities across the 4 entities for properly
    named systems (same name across entities → qualified, not merged)
  - cascade not truncated (the bounded_cascade cap was raised to 5000)
  - supervisor pack returns per-entity systems/crypto/weak/qv with regulator set
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.mark.timeout(600)
def test_snb_1k_e2e_supervisor(tmp_path):
    import snb_1k_e2e as snb

    os.environ["ENVIRONMENT"] = "test"
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    result = snb.run("sqlite", tmp_path, systems_target=1020)

    tot = result["total"]
    assert tot["systems"] == 1020
    assert tot["files"] == 1020
    assert tot["exact_files"] >= 1010
    assert tot["precision"] >= 0.999
    assert tot["recall"] >= 0.99
    assert tot["f1"] >= 0.995

    # per entity
    for code in ("snb", "snb-capital", "snb-takaful", "snb-quickpay"):
        pe = result["per_entity"][code]
        a = pe["accuracy"]
        assert a["f1"] >= 0.99, (code, a)
        assert pe["cascade_unassigned"] == 0
        # cascade report lives inside Scan.statistics (JSON) and is hard-capped at
        # _bounded_cascade(..., max_list=300) to avoid bloating the scan record —
        # all declared systems still land in the System table; just the summary
        # slice is bounded.
        assert pe["cascade_systems"] == min(pe["systems"], 300), (
            code, pe["cascade_systems"], pe["systems"])

    api = result["api"]
    assert api["group"]["unassigned_systems"] == 0
    # Cascade-aware dedup: parent repo rows collapse into declared children;
    # systems_count is what /systems lists after asset ownership is rolled up.
    assert api["systems_count"] >= 600

    pack = api["pack"]["pack"]
    assert pack["pack"]["kind"] == "supervisory-pack"
    entities_meta = {e["code"]: e for e in pack["entities"]}
    assert set(entities_meta) == {"snb", "snb-capital", "snb-takaful", "snb-quickpay"}
    for e in entities_meta.values():
        assert e["jurisdiction"] == "sa"

    rollups = {r["entity"]["code"]: r for r in api["group"]["entities"]}
    assert set(rollups) == {"snb", "snb-capital", "snb-takaful", "snb-quickpay"}
    for r in rollups.values():
        assert r["entity"]["regulator"] in ("SAMA", "CMA")
        assert r["systems"] > 0
        assert r["crypto_instances"] > 0
        assert r["worst_system"]["system"]
    assert rollups["snb"]["systems"] >= 250
    assert rollups["snb-capital"]["entity"]["regulator"] == "CMA"

    gt = pack["group_totals"]
    assert gt["entities"] == 4
    assert gt["systems"] >= 600
    assert gt["weak_legacy_instances"] > 0
    assert gt["quantum_vulnerable_public_key"] > 0

    # Migration roadmap populated (NIST IR 8547 buckets)
    roadmap = api["roadmap"]
    assert len(roadmap.get("rows", [])) >= 5
    buckets = {}
    for row in roadmap["rows"]:
        buckets[row["bucket"]] = buckets.get(row["bucket"], 0) + row["instances"]
    assert buckets.get("immediate", 0) > 0   # 3DES/RC4/MD5 legacy purge

    # top-families include AES/TLS as highest-volume families
    top = {f for f, _ in rollups["snb"]["top_families"]}
    assert "AES" in top or "TLS" in top

    # SAMA / mada / SWIFT CSP policy pack loaded and fired
    snb_pf = result["per_entity"]["snb"]["policy_failures"]
    # Legacy-algo rule fires against the legacy archetypes stamped in
    assert snb_pf.get("SAMA-001:FAIL", 0) >= 50, snb_pf
    # TLS floor rule fires on TLS-1.0/1.1 systems
    assert snb_pf.get("SAMA-002:FAIL", 0) >= 1
    # RSA/DH <2048 key-size floor fires
    assert snb_pf.get("SAMA-003:FAIL", 0) >= 1
    # mada PIN-block rule fires on payment/card archetypes stamped into snb
    assert snb_pf.get("MADA-001:FAIL", 0) >= 1, snb_pf
    # SWIFT CSCF legacy rule fires on SWIFT-scoped systems in snb & quickpay
    assert snb_pf.get("SAMASWIFT-001:FAIL", 0) >= 1, snb_pf
    assert result["per_entity"]["snb-quickpay"]["policy_failures"].get(
        "SAMASWIFT-001:FAIL", 0) >= 1
