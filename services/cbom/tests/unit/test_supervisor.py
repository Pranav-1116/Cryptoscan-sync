"""Supervisory reporting engine — roadmap bucketing + pack assembly.

The buckets are NOT re-derived here from new math: they come from
cbom.banking.quantum_vulnerability (NIST IR 8547). These tests pin that
the roadmap maps verdicts honestly and the pack carries its limits.
"""
from __future__ import annotations

from datetime import date

from cbom.supervisor import (
    BUCKET_BY_2030,
    BUCKET_BY_2035,
    BUCKET_IMMEDIATE,
    SUPERVISOR_LIMITS,
    group_roadmap,
    supervisor_pack,
)

AS_OF = date(2026, 9, 10)

_ENTITY = {"code": "bank-de", "name": "Bank DE", "jurisdiction": "DE",
           "lei": "BANKDE123456XXXXXX23"}


def _rollup(families: list[tuple[str, int]], code: str = "bank-de") -> dict:
    entity = dict(_ENTITY, code=code) if code != "bank-de" else dict(_ENTITY)
    return {"entity": entity, "top_families": families}


def _buckets_by_family(rollups):
    """(rows_list, by_family_dict, roadmap) for one call."""
    roadmap = group_roadmap(rollups, as_of=AS_OF)
    rows = roadmap["rows"]
    return rows, {row["family"]: row for row in rows}, roadmap


def test_bucket_mapping_per_nist_ir_8547():
    rows, by_family, _ = _buckets_by_family([
        _rollup([("3DES-112", 4), ("RSA-2048", 12), ("RSA-3072", 2),
                 ("ECDSA-256", 6), ("ECDSA-224", 1)]),
    ])
    assert by_family["3DES-112"]["bucket"] == BUCKET_IMMEDIATE
    assert by_family["RSA-2048"]["bucket"] == BUCKET_BY_2030
    assert by_family["RSA-2048"]["deadline"] == "2030-12-31"
    assert by_family["RSA-3072"]["bucket"] == BUCKET_BY_2035
    assert by_family["ECDSA-256"]["bucket"] == BUCKET_BY_2035
    # P-224 is the 112-bit ECC class -> earlier horizon
    assert by_family["ECDSA-224"]["bucket"] == BUCKET_BY_2030
    assert by_family["3DES-112"]["deadline"] == "2026-09-10"  # overdue now
    assert by_family["RSA-2048"]["action"].startswith("Migrate")


def test_posture_ok_and_pqc_families_produce_no_rows():
    rows, _, roadmap = _buckets_by_family([
        _rollup([("AES-256", 40), ("ML-KEM-1024", 8), ("CHACHA20", 3)]),
    ])
    assert rows == []
    assert roadmap["rows"] == []
    assert roadmap["summary"]["entities_affected"] == []
    assert roadmap["basis"].startswith("NIST IR 8547")


def test_weak_signature_hash_is_immediate_via_verdict():
    # SHA1WITHRSA: the impaired hash is disqualifying today (verdict legacy)
    _, by_family, _ = _buckets_by_family([_rollup([("SHA1WITHRSA-2048", 7)])])
    assert by_family["SHA1WITHRSA-2048"]["bucket"] == BUCKET_IMMEDIATE


def test_sort_worst_first_and_across_entities():
    rows, _, _ = _buckets_by_family([
        _rollup([("RSA-2048", 3), ("3DES-112", 9)], code="bank-de"),
        _rollup([("3DES-112", 2), ("ECDSA-256", 5)], code="bank-fr"),
    ])
    keys = [(r["bucket"], r["entity_code"], r["family"]) for r in rows]
    # immediate rows first (instances desc within bucket), then 2030, 2035
    assert keys == [
        (BUCKET_IMMEDIATE, "bank-de", "3DES-112"),
        (BUCKET_IMMEDIATE, "bank-fr", "3DES-112"),
        (BUCKET_BY_2030, "bank-de", "RSA-2048"),
        (BUCKET_BY_2035, "bank-fr", "ECDSA-256"),
    ]


def test_summary_counts_instances_and_distinct_families():
    _, _, roadmap = _buckets_by_family([
        _rollup([("3DES-112", 9), ("RSA-2048", 3), ("RSA-4096", 1)]),
    ])
    summary = roadmap["summary"]
    assert summary["rows"] == 3
    assert summary["instances_by_bucket"][BUCKET_IMMEDIATE] == 9
    assert summary["instances_by_bucket"][BUCKET_BY_2030] == 3
    assert summary["instances_by_bucket"][BUCKET_BY_2035] == 1
    assert summary["families_by_bucket"][BUCKET_BY_2035] == 1
    assert summary["entities_affected"] == ["bank-de"]


def test_empty_and_none_inputs_are_honest():
    for roadmap in (group_roadmap(None, as_of=AS_OF), group_roadmap([], as_of=AS_OF)):
        assert roadmap["rows"] == []
        assert roadmap["summary"]["rows"] == 0


def test_supervisor_pack_assembles_and_declares_limits():
    rollup = _rollup([("RSA-2048", 2)])
    roadmap = group_roadmap([rollup], as_of=AS_OF)
    pack = supervisor_pack(
        group={"totals": {"entities": 1, "crypto_instances": 2},
               "by_jurisdiction": {"DE": {"crypto_instances": 2}}},
        entity_rollups=[rollup],
        dora_summary={"total": 3, "critical": 1},
        roadmap=roadmap,
        pack_version="1.0.0",
        as_of=AS_OF,
    )
    assert pack["pack"] == {"kind": "supervisory-pack", "version": "1.0.0",
                            "generated_for": "2026-09-10"}
    assert pack["group_totals"]["entities"] == 1
    assert pack["by_jurisdiction"] == {"DE": {"crypto_instances": 2}}
    assert pack["entities"] == [{"code": "bank-de", "name": "Bank DE",
                                 "jurisdiction": "DE",
                                 "lei": "BANKDE123456XXXXXX23"}]
    assert pack["dora_register_summary"] == {"total": 3, "critical": 1}
    assert pack["migration_roadmap_summary"]["rows"] == 1
    assert pack["declared_limits"] == list(SUPERVISOR_LIMITS)
    assert len(pack["declared_limits"]) == 3
    # the honesty statement itself: no fabricated bank_to_supply content
    assert any("placeholders" in limit for limit in pack["declared_limits"])


def test_supervisor_pack_missing_sections_stay_empty_not_invented():
    pack = supervisor_pack(group=None, entity_rollups=None,
                           dora_summary=None, roadmap=None,
                           pack_version="1.0.0", as_of=AS_OF)
    assert pack["group_totals"] == {}
    assert pack["entities"] == []
    assert pack["dora_register_summary"] == {}
    assert pack["migration_roadmap_summary"] == {}
    assert pack["declared_limits"]  # the limits always travel with the pack
