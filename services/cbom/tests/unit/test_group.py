"""Group governance — LEI, entity registry, rollups, DORA register."""
from __future__ import annotations

import datetime as dt

import pytest

from cbom.group import (
    dora_register_rows,
    entity_rollup,
    group_rollup,
    load_entities,
    normalize_entity,
    save_entities,
    validate_lei,
)

_CS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _make_lei(body: str) -> str:
    """Generate an ISO 7064 MOD 97-10 valid LEI from an 18-char body."""
    b = body.upper().ljust(18, "X")[:18]
    n = int("".join(str(_CS.index(c)) for c in b) + "00")
    return b + f"{98 - (n % 97):02d}"


# --------------------------------------------------------------------------- #
# LEI (ISO 17442)
# --------------------------------------------------------------------------- #

def test_lei_roundtrip_generation_and_validation():
    lei = _make_lei("BANKDE123456")
    v = validate_lei(lei)
    assert v["valid"] is True and v["normalized"] == lei


def test_lei_tampered_check_digit_rejected():
    lei = _make_lei("BANKDE123456")
    tampered = lei[:19] + ("0" if lei[19] != "0" else "1")
    assert validate_lei(tampered)["valid"] is False
    assert "97-10" in validate_lei(tampered)["error"]


def test_lei_structure_enforced():
    for bad in ("", "ABC", "bank-de-0000000000000x", "A" * 19, "A" * 21, "!" * 20):
        assert validate_lei(bad)["valid"] is False


# --------------------------------------------------------------------------- #
# Entity registry
# --------------------------------------------------------------------------- #

def test_entity_normalization_and_rejection():
    ent = normalize_entity({"code": "De-Ret", "name": "Retail AG",
                            "jurisdiction": "EU", "lei": _make_lei("BANKDE999"),
                            "country": "de"})
    assert ent["code"] == "de-ret" and ent["jurisdiction"] == "eu"
    assert ent["lei"]  # normalized valid LEI kept
    with pytest.raises(ValueError):
        normalize_entity({"code": "bad code!", "name": "x", "jurisdiction": "eu"})
    with pytest.raises(ValueError):
        normalize_entity({"code": "ok", "name": "x", "jurisdiction": "eu", "lei": "NOTVALIDLEI00000001"})
    with pytest.raises(ValueError):
        normalize_entity({"code": "ok", "jurisdiction": "eu"})  # name missing


def test_registry_file_roundtrip(tmp_path):
    p = tmp_path / "entities.json"
    save_entities([{"code": "de-ret", "name": "Retail AG", "jurisdiction": "eu"},
                   {"code": "uk-inv", "name": "Investments", "jurisdiction": "uk"}], p)
    loaded = load_entities(p)
    assert set(loaded) == {"de-ret", "uk-inv"}
    assert loaded["uk-inv"]["jurisdiction"] == "uk"
    assert load_entities(tmp_path / "missing.json") == {}


# --------------------------------------------------------------------------- #
# Rollups
# --------------------------------------------------------------------------- #

ENT = {"code": "de-ret", "name": "Retail AG", "jurisdiction": "eu"}


def test_entity_rollup_counts_weak_and_quantum():
    assets = {
        "s1": [{"algorithm": "3DES"}, {"algorithm": "RSA", "key_size": 2048}],
        "s2": [{"algorithm": "AES", "key_size": 256}],
    }
    systems = [{"id": "s1", "name": "payments"}, {"id": "s2", "name": "web"}]
    r = entity_rollup(ENT, systems, assets)
    assert r["crypto_instances"] == 3
    assert r["weak_legacy_instances"] == 1      # 3DES
    assert r["quantum_vulnerable_public_key"] == 1  # RSA-2048
    assert r["worst_system"]["system_id"] == "s1"
    assert ("AES-256", 1) in r["top_families"]


def test_group_rollup_finds_recurring_families_and_ranks():
    e1 = entity_rollup(ENT, [{"id": "s1", "name": "a"}],
                       {"s1": [{"algorithm": "3DES"}, {"algorithm": "3DES"}]})
    e2 = entity_rollup({"code": "uk-inv", "name": "Inv", "jurisdiction": "uk"},
                       [{"id": "s9", "name": "b"}],
                       {"s9": [{"algorithm": "3DES"}]})
    g = group_rollup([e1, e2])
    assert g["totals"]["weak_legacy_instances"] == 3
    assert g["totals"]["entities"] == 2
    assert g["recurring_weak_families"][0]["family"] == "3DES"
    assert set(g["recurring_weak_families"][0]["entities"]) == {"de-ret", "uk-inv"}
    assert g["exposure_ranking"][0]["entity"] == "de-ret"  # 2 weak > 1
    assert "uk" in g["by_jurisdiction"] and "eu" in g["by_jurisdiction"]


# --------------------------------------------------------------------------- #
# DORA register
# --------------------------------------------------------------------------- #

def test_dora_rows_service_mapping_and_expiring_critical():
    vendors = [
        {"name": "Thales", "vendor_type": "hsm", "criticality": "MISSION-CRITICAL",
         "contract_end_date": dt.datetime(2026, 10, 1), "data_classifications": ["keys"]},
        {"name": "Acme", "vendor_type": "cloud", "criticality": "MEDIUM"},
        {"name": "StrISO", "vendor_type": "network", "criticality": "HIGH",
         "contract_end_date": "2026-10-15T00:00:00"},  # string dates (to_dict shape)
    ]
    reg = dora_register_rows(vendors, entity_code="de-ret")
    assert reg["total"] == 3 and reg["critical"] == 2
    assert reg["critical_expiring_180d"] == 2   # both near-end critical contracts flagged
    types = {r["provider_name"]: r["ict_service_type"] for r in reg["rows"]}
    assert types["Thales"] == "Cryptographic hardware (HSM)"
    assert types["Acme"] == "Cloud computing (IaaS/PaaS/SaaS)"
    # critical rows sort first
    assert reg["rows"][0]["function_criticality"] == "MISSION-CRITICAL"
    for row in reg["rows"]:
        assert row["bank_to_supply"]["contract_id"] == ""
        assert "exit_plan_ref" in row["bank_to_supply"]
    assert reg["regulation"].startswith("DORA")
