"""International layer — jurisdiction packs, SWIFT CSP, key lifecycle, i18n."""
from __future__ import annotations

from datetime import date

from cbom.integrations import ACTION_PLAN_I18N, render_action_plan_html
from cbom.regulators import (
    JURISDICTION_PACKS,
    classify_key_state,
    jurisdiction_pack,
    key_lifecycle,
    swift_cscf_assessment,
)


def _state(cbom_rows: list[dict], certs: int = 0, fingerprint: str = "") -> dict:
    return {"fingerprint": fingerprint,
            "layers": {"cbom": {"components": cbom_rows, "count": len(cbom_rows)},
                       "certificates": {"count": certs}}}


# --------------------------------------------------------------------------- #
# Jurisdiction packs
# --------------------------------------------------------------------------- #

def test_ten_jurisdictions_with_regulators_and_artifacts():
    assert len(JURISDICTION_PACKS) >= 10
    for code, pack in JURISDICTION_PACKS.items():
        assert pack["code"] == code
        assert pack["regulators"] and pack["display"]
        assert pack["artifacts"], f"{code} must map evidence artifacts"
        assert pack["languages"]
        for m in pack["milestones"]:
            assert m["label"] and isinstance(m.get("date"), (str, type(None)))


def test_jurisdiction_pack_lookup_and_unknown():
    assert jurisdiction_pack("EU")["regulators"][0].startswith("ECB")
    assert jurisdiction_pack("atlantis") is None


def test_dora_in_force_milestone_present():
    eu = jurisdiction_pack("eu")
    dora = [m for m in eu["milestones"] if "DORA" in m["label"]]
    assert dora and dora[0]["date"] == "2025-01-17"  # applies since Jan 2025


# --------------------------------------------------------------------------- #
# SWIFT CSP / CSCF evidence mapping
# --------------------------------------------------------------------------- #

def test_cscf_gaps_when_weak_crypto_and_cleartext():
    state = _state([
        {"algorithm": "3DES", "purpose": "encryption"},
        {"algorithm": "RSA", "key_size": 2048, "purpose": "signature"},
    ])
    mf = {"cleartext_endpoints": [{"location": "cics://LEGACY"}],
          "weak_transport": [{"location": "db2://PAYDB", "below_floor": ["TLSV1"]}]}
    s = swift_cscf_assessment(state, hsm_fleet={"total": 1, "pqc_ready": 0, "custody_recorded": 0},
                              mainframe=mf)
    assert s["gaps"] >= 3
    assert s["attestation_ready"] is False
    themes = {c["theme"]: c["status"] for c in s["controls"]}
    assert themes["Cryptographic algorithm hygiene"] == "gap"
    assert themes["Transport encryption of the local infrastructure"] == "gap"


def test_cscf_unknown_when_no_data_not_gap():
    s = swift_cscf_assessment(_state([]), hsm_fleet={"total": 0}, mainframe={})
    assert any(c["status"] == "unknown" for c in s["controls"])
    assert s["unknown"] >= 1


def test_cscf_clean_estate_attests():
    state = _state([{"algorithm": "AES", "key_size": 256, "purpose": "encryption"}],
                   certs=4, fingerprint="f" * 64)
    s = swift_cscf_assessment(state, hsm_fleet={"total": 2, "pqc_ready": 2, "custody_recorded": 2},
                              mainframe={"cleartext_endpoints": [], "weak_transport": []})
    assert s["gaps"] == 0 and s["unknown"] == 0 and s["attestation_ready"] is True


# --------------------------------------------------------------------------- #
# Key lifecycle (NIST SP 800-57)
# --------------------------------------------------------------------------- #

def test_key_state_classification():
    assert classify_key_state("ACTIVE") == "active"
    assert classify_key_state("TRUST") == "active"
    assert classify_key_state("RETIRED") == "deactivated"
    assert classify_key_state("COMPROMISED") == "compromised"
    assert classify_key_state("") == "unknown"
    assert classify_key_state("WEIRD") == "unknown"


def test_lifecycle_compromised_first_and_overdue_rotation():
    keys = [
        {"label": "K1", "algorithm": "AES", "status": "ACTIVE", "activated_at": "2020-01-01",
         "file_path": "icsf://K1"},
        {"label": "K2", "algorithm": "AES", "status": "COMPROMISED", "file_path": "icsf://K2"},
        {"label": "K3", "algorithm": "RSA", "status": "RETIRED", "file_path": "racf://K3"},
    ]
    reg = key_lifecycle(keys, today=date(2026, 9, 10))
    assert reg["keys"][0]["state"] == "compromised"
    assert "IMMEDIATE ACTION" in reg["keys"][0]["detail"]
    assert reg["rotation_overdue"] == 1  # K1 active ~6.7 years > 2y ceiling
    assert reg["by_state"] == {"compromised": 1, "deactivated": 1, "active": 1}


def test_lifecycle_expiry_dates_drive_expired_state():
    keys = [
        {"label": "OLD", "algorithm": "AES", "status": "ACTIVE", "expires": "2025-01-01",
         "file_path": "icsf://OLD"},
        {"label": "SOON", "algorithm": "AES", "status": "ACTIVE", "expires": "2026-09-25",
         "file_path": "icsf://SOON"},
    ]
    reg = key_lifecycle(keys, today=date(2026, 9, 10))
    states = {k["label"]: k for k in reg["keys"]}
    assert states["OLD"]["state"] == "expired"
    assert states["SOON"]["rotation_status"] == "renewal_due"


def test_lifecycle_missing_dates_are_honest():
    reg = key_lifecycle([{"label": "X", "algorithm": "AES", "status": "ACTIVE",
                          "file_path": "icsf://X"}], today=date(2026, 9, 10))
    assert reg["keys"][0]["rotation_status"] == "record_activation_date"
    assert reg["activation_dates_missing"] == 1


# --------------------------------------------------------------------------- #
# Action plan i18n
# --------------------------------------------------------------------------- #

PLAN = {
    "framework": "ecb", "institution": "Test", "generated_at": "2026-09-10",
    "references": ["ref"], "evidence": {"snapshot_id": "S", "fingerprint": "f", "environment": "prod"},
    "assessment": {"total_crypto_instances": 1, "admission": {"decision": "PASS", "blocking": 0},
                   "hndl": {"total": 0}, "hsm_fleet": {"pqc_gap": 0},
                   "mainframe_inventory": {"total": 0}},
    "hndl_register": [], "phases": [], "attestation": "att",
}


def test_i18n_covers_ecb_languages_and_rtl():
    assert {"en", "de", "fr", "es", "it", "ar"} <= set(ACTION_PLAN_I18N)
    assert ACTION_PLAN_I18N["ar"]["rtl"] is True


def test_render_german_chrome():
    html = render_action_plan_html(PLAN, lang="de")
    assert "Maßnahmenplan zum Kryptografierisiko" in html
    assert 'lang="de"' in html
    assert "Regulatorische Referenzen" in html


def test_render_arabic_rtl_and_fallback():
    ar = render_action_plan_html(PLAN, lang="ar")
    assert 'dir="rtl"' in ar and "خطة عمل مخاطر التشفير" in ar
    fallback = render_action_plan_html(PLAN, lang="zz")
    assert "Cryptographic Risk Action Plan" in fallback
