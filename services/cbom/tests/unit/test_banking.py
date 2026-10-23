"""Banking & Regulatory engine — pure-function tests (no DB / I/O)."""
from __future__ import annotations

from datetime import date

from cbom.banking import (
    DEPRECATED_AFTER_2030,
    DISALLOWED_AFTER_2035,
    GROVER_IMPACTED,
    assess_hsm_fleet,
    banking_overview,
    fips_validation,
    hndl_register,
    migration_roadmap,
    normalize_icsf_csv,
    normalize_racdcert,
    quantum_vulnerability,
)


def _state(cbom_rows: list[dict]) -> dict:
    return {"layers": {"cbom": {"components": cbom_rows, "count": len(cbom_rows)}}}


# --------------------------------------------------------------------------- #
# NIST IR 8547 classification
# --------------------------------------------------------------------------- #

def test_rsa_2048_is_deprecated_after_2030():
    v = quantum_vulnerability("RSA", 2048)
    assert v["quantum_vulnerable"] is True
    assert v["transition"] == DEPRECATED_AFTER_2030
    assert v["deadline"] == 2030


def test_ec_256_is_disallowed_after_2035():
    v = quantum_vulnerability("ECDSA", 256)
    assert v["quantum_vulnerable"] is True
    assert v["transition"] == DISALLOWED_AFTER_2035
    assert v["deadline"] == 2035


def test_signature_bundle_sha256withrsa_classifies_by_family():
    v = quantum_vulnerability("SHA256WithRSA", 2048)
    assert v["family"] == "RSA"
    assert v["transition"] == DEPRECATED_AFTER_2030


def test_symmetric_aes_is_grover_only_not_pqc_migration():
    v = quantum_vulnerability("AES", 256)
    assert v["quantum_vulnerable"] is False
    assert v["transition"] == GROVER_IMPACTED


def test_weak_legacy_flagged_for_purge_regardless_of_pqc():
    v = quantum_vulnerability("3DES", 112)
    assert v["quantum_vulnerable"] is True
    assert v["transition"] == GROVER_IMPACTED
    assert "purge" in v["note"].lower()


# --------------------------------------------------------------------------- #
# HNDL register
# --------------------------------------------------------------------------- #

def test_hndl_flags_long_horizon_public_key_crypto():
    state = _state([
        {"bom-ref": "crypto:1", "algorithm": "RSA", "key_size": 2048,
         "purpose": "key_exchange", "application": "payments-core", "asset": "s1"},
        {"bom-ref": "crypto:2", "algorithm": "AES", "key_size": 256,
         "purpose": "encryption", "application": "payments-core"},
    ])
    reg = hndl_register(state, horizon_years=5)
    assert reg["at_risk"] is True
    assert reg["total"] == 1
    entry = reg["entries"][0]
    assert entry["bom_ref"] == "crypto:1"
    assert entry["exposure"] == "critical"  # 10-year horizon
    assert "decrypt-later" in entry["reason"]


def test_hndl_skips_short_horizon_and_symmetric():
    state = _state([
        {"bom-ref": "crypto:1", "algorithm": "RSA", "key_size": 2048, "purpose": "authentication"},
        {"bom-ref": "crypto:2", "algorithm": "ECDSA", "key_size": 256, "purpose": "signature"},
    ])
    # Short authentication retention is filtered; signature-only ECDSA is
    # an authenticity-migration concern, not harvested ciphertext.
    reg = hndl_register(state, data_classes=[{"purpose": "authentication", "years": 1}],
                        horizon_years=5)
    assert reg["total"] == 0


# --------------------------------------------------------------------------- #
# Roadmap
# --------------------------------------------------------------------------- #

def test_roadmap_buckets_by_phase_and_counts_instances():
    state = _state([
        {"algorithm": "3DES", "purpose": "encryption"},
        {"algorithm": "RSA", "key_size": 2048, "purpose": "key_exchange", "application": "gw"},
        {"algorithm": "RSA", "key_size": 3072, "purpose": "signature"},
        {"algorithm": "AES", "key_size": 256, "purpose": "encryption"},
    ])
    rm = migration_roadmap(state, today=date(2026, 9, 10))
    by_phase = {p["phase"]: p for p in rm["phases"]}
    assert by_phase["P1"]["instance_count"] == 1  # 3DES weak legacy
    assert by_phase["P2"]["instance_count"] == 1  # RSA-2048
    assert by_phase["P3"]["instance_count"] == 1  # RSA-3072
    p2_item = by_phase["P2"]["items"][0]
    assert p2_item["family"] == "RSA" and p2_item["applications"] == ["gw"]
    assert rm["weak_legacy_instances"] == 1
    assert rm["total_in_scope"] == 3


def test_roadmap_marks_past_deadlines_overdue():
    state = _state([{"algorithm": "RSA", "key_size": 2048, "purpose": "key_exchange"}])
    rm = migration_roadmap(state, today=date(2031, 1, 1))
    p2 = next(p for p in rm["phases"] if p["phase"] == "P2")
    assert p2["items"][0]["overdue"] is True
    assert p2["items"][0]["years_left"] <= 0


# --------------------------------------------------------------------------- #
# FIPS mapping + HSM fleet
# --------------------------------------------------------------------------- #

def test_fips_family_lookup_and_conservative_default():
    got = fips_validation("OpenSSL FIPS Provider 3.0")
    assert got["status"] == "unknown" and got["source"] == "builtin"
    unk = fips_validation("libwhatever 0.9")
    assert unk["status"] == "unknown" and "CMVP" in unk["note"]


def test_fips_supplied_table_overrides_builtin():
    supplied = {"z": {"match": "icsf", "status": "validated", "cert": "1234", "note": "bank-recorded"}}
    got = fips_validation("z/OS ICSF HCR77C0", supplied=supplied)
    assert got["status"] == "declared_not_verified"
    assert got["declared_status"] == "validated"
    assert got["cert"] == "1234" and got["source"] == "supplied"


def test_hsm_fleet_declarations_do_not_establish_readiness():
    hsms = [
        {"asset_id": "hsm-1", "manufacturer": "Thales", "model": "Luna Network HSM",
         "firmware": {"version": "7.8.9"}, "hsm": {"algorithms": ["ML-KEM"]}},
        {"asset_id": "hsm-2", "manufacturer": "Utimaco", "model": "CryptoServer",
         "firmware": {"version": "4.2"}, "hsm": {}, "crypto_capabilities": {"ecc": ["P-256"]}},
    ]
    fleet = assess_hsm_fleet(hsms)
    assert fleet["total"] == 2
    assert fleet["pqc_ready"] == 0
    assert fleet["pqc_declared_not_verified"] == 1
    assert fleet["hsms"][0]["pqc_status"] == "declared_not_verified"
    assert fleet["hsms"][1]["pqc_status"] == "not_declared"
    assert "vendor" in fleet["hsms"][1]["gap"].lower()
    # A family lookup does not establish exact module/firmware validation
    assert fleet["hsms"][0]["fips"]["status"] == "unknown"


# --------------------------------------------------------------------------- #
# Mainframe ingest parsers
# --------------------------------------------------------------------------- #

RACDCERT_SAMPLE = """RACDCERT LIST SITE
Digital certificate information for site certificate PAYMENTGW:
    Status: TRUST
    Start Date: 2024/01/01 00:00:00
    Expiration Date: 2027/01/01 00:00:00
    Certificate Key Size: 2048
    Algorithm Signature: SHA256WithRSA
    Subject: CN=paymentgw.bank.example
Digital certificate information for id(CERTAUTH) label(OLDROOT):
    Status: TRUST
    Expiration Date: 2026/05/20 00:00:00
    Certificate Key Size: 1024
    Algorithm Signature: SHA1WithRSA
    Subject: CN=Old Root CA
"""


def test_normalize_racdcert_parses_certificates():
    rows = normalize_racdcert(RACDCERT_SAMPLE)
    assert len(rows) == 2
    first = rows[0]
    assert first["source"] == "racf"
    assert first["label"] == "PAYMENTGW"
    assert first["algorithm"] == "RSA"
    assert first["signature_algorithm"] == "SHA256WITHRSA"
    assert first["key_size"] == 2048
    assert first["status"] == "TRUST"
    assert first["expires"] == "2027-01-01"
    assert rows[1]["algorithm"] == "RSA" and rows[1]["key_size"] == 1024
    assert rows[1]["signature_algorithm"] == "SHA1WITHRSA"
    assert rows[1]["file_path"] == "racf://OLDROOT"


ICSF_SAMPLE = """LABEL,ALGORITHM,KEYBITS,USAGE,STATUS
PAY.ZEK.2026,AES,256,CIPHER,ACTIVE
PAY.ZEK.2023,AES,256,CIPHER,RETIRED
LEGAL.SIGN.RSA,RSA,3072,SIGN,ACTIVE
LEGACY.MAC.DES,DES,56,MAC,ACTIVE
"""


def test_normalize_icsf_csv_parses_rows_and_rejects_bad_headers():
    rows = normalize_icsf_csv(ICSF_SAMPLE)
    assert [r["label"] for r in rows] == ["PAY.ZEK.2026", "PAY.ZEK.2023", "LEGAL.SIGN.RSA", "LEGACY.MAC.DES"]
    assert rows[0]["algorithm"] == "AES" and rows[0]["key_size"] == 256
    assert rows[0]["purpose"] == "cipher" and rows[1]["status"] == "RETIRED"
    assert rows[2]["key_size"] == 3072
    assert rows[0]["file_path"] == "icsf://PAY.ZEK.2026"
    assert normalize_icsf_csv("name,alg\nx,AES") == []


# --------------------------------------------------------------------------- #
# Combined overview
# --------------------------------------------------------------------------- #

def test_banking_overview_aggregates_all_layers():
    state = _state([
        {"bom-ref": "c1", "algorithm": "RSA", "key_size": 2048, "purpose": "key_exchange"},
        {"algorithm": "DES", "purpose": "encryption"},
    ])
    hsms = [{"asset_id": "h1", "manufacturer": "Thales", "model": "Luna S",
             "hsm": {"algorithms": ["ML-KEM"]}}]
    mf = normalize_racdcert(RACDCERT_SAMPLE) + normalize_icsf_csv(ICSF_SAMPLE)
    ov = banking_overview(state, hsms=hsms, mainframe_assets=mf,
                          today=date(2026, 9, 10))
    assert ov["hndl"]["total"] == 1 and ov["hndl"]["at_risk"] is True
    assert ov["roadmap"]["total_in_scope"] == 2
    assert ov["hsm"]["pqc_ready"] == 0
    assert ov["hsm"]["pqc_declared_not_verified"] == 1
    assert ov["mainframe"]["total"] == 6
    assert ov["mainframe"]["by_source"] == {"racf": 2, "icsf": 4}
