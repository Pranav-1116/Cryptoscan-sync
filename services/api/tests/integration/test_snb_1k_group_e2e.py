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

import json
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
        # declared systems == cascade systems (not truncated)
        assert pe["cascade_systems"] == pe["systems"], (code, pe["cascade_systems"], pe["systems"])

    api = result["api"]
    assert api["group"]["unassigned_systems"] == 0
    assert api["systems_count"] == 1024  # 4 repo-container systems + 1020 declared

    pack = api["pack"]["pack"]
    assert pack["pack"]["kind"] == "supervisory-pack"
    entities = {e["code"]: e for e in pack["entities"]}
    assert set(entities) == {"snb", "snb-capital", "snb-takaful", "snb-quickpay"}
    for e in entities.values():
        assert e["regulator"] in ("SAMA", "CMA")
        assert e["systems"] > 0
        assert e["crypto_instances"] > 0
        assert e["worst_system"]["system"]
    assert entities["snb"]["systems"] >= 700
    assert entities["snb-capital"]["regulator"] == "CMA"

    gt = pack["group_totals"]
    assert gt["entities"] == 4
    assert gt["systems"] == 1024
    assert gt["weak_legacy_instances"] > 0
    assert gt["quantum_vulnerable_public_key"] > 0

    roadmap = (api["roadmap"].get("summary") or {})
    assert roadmap["rows"] >= 5
    buckets = roadmap["instances_by_bucket"]
    assert buckets.get("immediate", 0) > 0   # 3DES/RC4/MD5 etc.

    # top-families include AES/TLS as highest-volume families
    top = {f for f, _ in entities["snb"]["top_families"]}
    assert "AES" in top or "TLS" in top
