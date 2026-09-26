"""Mainframe discovery, HSM/PKCS#11 depth, integrations & exports — unit tests."""
from __future__ import annotations

from datetime import date

from cbom.hsm_pkcs11 import (
    assess_hsm_deep,
    detect_vendor,
    key_custody_status,
    parse_cex_adapters,
    parse_pkcs11_objects,
    parse_pkcs11_slots,
    pqc_from_mechanisms,
)
from cbom.integrations import (
    fips_lookup,
    load_fips_registry,
    procurement_trust_package,
    render_action_plan_csv,
    render_action_plan_html,
    soc2_iso_crosswalk,
    to_qualys_csv,
    to_servicenow_cmdb,
)
from cbom.mainframe import (
    mainframe_assessment,
    normalize_cics_tcpservice,
    normalize_db2_tls,
    normalize_icsf_keys,
    normalize_racdcert_rich,
)

# --------------------------------------------------------------------------- #
# Mainframe: RACF rich, ICSF, DB2 TLS, CICS
# --------------------------------------------------------------------------- #

RACF = """Digital certificate information for site certificate PAYGW:
    Status: TRUST
    Expiration Date: 2026/11/01 00:00:00
    Certificate Key Size: 2048
    Algorithm Signature: SHA256WithRSA
    Key Usage: HANDSHAKE, CERTSIGN
    Subject: CN=paygw.bank
Digital certificate information for id(CERTAUTH) label(OLDPCA):
    Status: TRUST
    Expiration Date: 2030/05/20 00:00:00
    Certificate Key Size: 1024
    Algorithm Signature: SHA1WithRSA
"""


def test_racdcert_rich_parses_scope_usage_expiry():
    rows = normalize_racdcert_rich(RACF)
    assert [r["label"] for r in rows] == ["PAYGW", "OLDPCA"]
    assert rows[0]["scope"] == "site" and rows[1]["scope"] == "certauth"
    assert rows[0]["algorithm"] == "RSA"
    assert rows[0]["key_usage"] == ["Certsign", "Handshake"]
    assert rows[0]["_expiry_date"] == date(2026, 11, 1)
    assert rows[1]["key_size"] == 1024


def test_db2_tls_flags_below_floor_weak_ciphers_and_cleartext():
    rows = normalize_db2_tls(
        "[database PAYDB]\nSSL_VERSIONS = TLSv1,TLSv1.2\n"
        "SSL_CIPHERSPECS = TLS_RSA_WITH_DES_CBC_SHA,TLS_AES_256_GCM_SHA384\n"
        "SSL_SVC_LABEL = PAYCERT\n"
        "[database HRDB]\nDB2Z = x\n")
    pay = next(r for r in rows if r["database"] == "PAYDB")
    assert pay["ssl_enabled"] is True
    assert pay["below_floor"] == ["TLSV1"]
    assert pay["weak_ciphers"] == ["TLS_RSA_WITH_DES_CBC_SHA"]
    hr = next(r for r in rows if r["database"] == "HRDB")
    assert hr["ssl_enabled"] is False and "cleartext" in hr["note"]


def test_cics_tcpservice_cleartext_and_weak_ciphers():
    rows = normalize_cics_tcpservice(
        "TCPIPSERVICE(PAYMENTS) PORTNUMBER(9443) PROTOCOL(https) CERTIFICATE(PAYGW) "
        "CIPHERS(TLS_RSA_WITH_DES_CBC_SHA)\n"
        "TCPIPSERVICE(LEGACY) PORTNUMBER(2000) PROTOCOL(http)\n")
    assert [(r["service"], r["encrypted"]) for r in rows] == [("PAYMENTS", True), ("LEGACY", False)]
    assert rows[0]["weak_ciphers"] == ["TLS_RSA_WITH_DES_CBC_SHA"]
    assert rows[1]["note"].startswith("cics tcpservice LEGACY is cleartext")


def test_mainframe_assessment_aggregates_all_signals():
    findings = (
        normalize_racdcert_rich(RACF)
        + normalize_db2_tls("[database PAYDB]\nSSL_VERSIONS = TLSv1\n")
        + normalize_cics_tcpservice("TCPIPSERVICE(LEGACY) PROTOCOL(http)")
    )
    a = mainframe_assessment(findings, today=date(2026, 9, 10))
    assert a["total_findings"] == 4
    assert a["by_source"] == {"racf": 2, "db2": 1, "cics": 1}
    assert a["subsystem_coverage"] == {"racf_certificates": 2, "icsf_keys": 0,
                                       "db2_tls_configs": 1, "cics_tls_endpoints": 1}
    assert len(a["cleartext_endpoints"]) == 1          # CICS LEGACY
    assert len(a["weak_transport"]) == 1               # DB2 TLSv1
    exp = a["certificates_expiring"][0]                # PAYGW expires 2026-11-01
    assert exp["location"] == "racf://PAYGW" and exp["days_left"] <= 180
    assert any(q["algorithm"] == "RSA" for q in a["quantum_vulnerable"])


def test_icsf_delegate_still_parses():
    rows = normalize_icsf_csv_text()
    assert rows[0]["label"] == "PAY.ZEK.2026" and rows[0]["key_size"] == 256


def normalize_icsf_csv_text():
    return normalize_icsf_keys("LABEL,ALGORITHM,KEYBITS,USAGE,STATUS\nPAY.ZEK.2026,AES,256,CIPHER,ACTIVE\n")


# --------------------------------------------------------------------------- #
# HSM / PKCS#11 depth
# --------------------------------------------------------------------------- #

SLOTS = """
Slot 0 (0x80000000): Luna Network HSM
  token label        : pay-partition-01
  token manufacturer : Thales Inc.
  token model        : Luna K7
  token serial       : 21180901001
  firmware version   : 7.8.4
"""
OBJECTS = """
Slot 0:
  Private Key Object
    label:      pay-gateway-key
    ID:         a1b2c3
    Usage:      decrypt, sign
  Secret Key Object
    label:      pay-zek-master
    Usage:      encrypt, decrypt
"""


def test_pkcs11_slot_and_object_parsers():
    slots = parse_pkcs11_slots(SLOTS)
    assert slots[0]["token_model"] == "Luna K7" and slots[0]["firmware_version"] == "7.8.4"
    objs = parse_pkcs11_objects(OBJECTS)
    assert [o["label"] for o in objs] == ["pay-gateway-key", "pay-zek-master"]
    assert objs[0]["usage"] == ["decrypt", "sign"]
    assert objs[1]["kind"] == "Secret Key"


def test_vendor_detect_and_pqc_mechanisms():
    assert detect_vendor("Thales", "Luna S")["vendor"] == "thales"
    assert detect_vendor("Utimaco", "CryptoServer")["vendor"] == "utimaco"
    assert detect_vendor("IBM", "z16 CEX8S")["vendor"] == "ibm"
    assert detect_vendor("Generic", "Box")["vendor"] == "unknown"
    assert pqc_from_mechanisms("CKM_ML_KEM, CKM_AES")["pqc_status"] == "ready"
    assert pqc_from_mechanisms("CKM_RSA_PKCS, CKM_AES")["pqc_status"] == "not_declared"
    assert pqc_from_mechanisms("")["pqc_status"] == "unknown"


def test_cex_adapter_parser():
    rows = parse_cex_adapters("CEX8S.001 ONLINE crypto usage=EP11\nCEX7S 003 ACTIVE CCA\n")
    assert rows[0]["adapter"] == "CEX8S" and rows[0]["usage"] == "EP11"
    assert rows[1]["index"] == 3 and rows[1]["state"] == "ACTIVE"


def test_key_custody_conservative():
    ok = key_custody_status({"custody": "3-of-8 split knowledge quorum recorded"})
    assert ok["custody_status"] == "quorum" and ok["quorum"] == "3-of-8"
    flagged = key_custody_status({"custody": "split knowledge (quorum not recorded)"})
    assert flagged["custody_status"] == "split_knowledge"
    assert key_custody_status({"x": "y"})["custody_status"] == "unknown"


def test_assess_hsm_deep_full_fleet():
    fleet = [
        {"asset_id": "hsm-1", "manufacturer": "Thales", "model": "Luna Network HSM",
         "firmware": {"version": "7.8.4"}, "hsm": {"mechanisms": ["ML-KEM"]},
         "slots_text": SLOTS, "objects_text": OBJECTS,
         "custody": "2-of-5 split knowledge"},
        {"asset_id": "hsm-2", "manufacturer": "Utimaco", "model": "CryptoServer",
         "firmware": {"version": "4.1.0"}},
        {"asset_id": "hsm-3", "manufacturer": "IBM", "model": "z16 CEX8S",
         "cex_text": "CEX8S.001 ONLINE usage=EP11"},
    ]
    fleet_assessment = assess_hsm_deep(fleet)
    assert fleet_assessment["total"] == 3
    assert fleet_assessment["by_vendor"] == {"ibm": 1, "thales": 1, "utimaco": 1}
    first = fleet_assessment["hsms"][0]
    assert first["pqc_status"] == "ready" and first["key_objects"] == 2
    assert first["custody"]["custody_status"] == "quorum"
    second = fleet_assessment["hsms"][1]
    assert "below PQC-capable baseline 5.0" in second["firmware_advisory"]
    assert fleet_assessment["hsms"][2]["cex_adapters"][0]["adapter"] == "CEX8S"


# --------------------------------------------------------------------------- #
# FIPS registry
# --------------------------------------------------------------------------- #

def test_fips_registry_exact_and_substring_and_unknown(tmp_path):
    reg = load_fips_registry()
    assert fips_lookup("OpenSSL FIPS Provider 3.0.9", reg)["cert"] == "4282"
    partial = fips_lookup("z/OS ICSF HCR77C", reg)
    assert partial["status"] in ("unknown", "validated")
    miss = fips_lookup("whoknows-lib 1.2", reg)
    assert miss["status"] == "unknown" and "CMVP" in miss["note"]


def test_fips_registry_roundtrip(tmp_path):
    from cbom.integrations import save_fips_registry
    p = tmp_path / "reg.json"
    save_fips_registry([{"module": "Luna K7 Firmware", "vendor": "Thales",
                         "standard": "FIPS 140-3", "cert": "4701-err-no", "note": "test"}], p)
    # the note marks it a test row — the shipped registry must never carry invented certs
    reg = load_fips_registry(p)
    assert "luna k7 firmware" in reg
    assert reg["luna k7 firmware"]["source"] == "manual"


# --------------------------------------------------------------------------- #
# Action-plan renderers
# --------------------------------------------------------------------------- #

PLAN = {
    "framework": "ecb", "institution": "Test Bank",
    "generated_at": "2026-09-10T00:00:00Z",
    "references": ["ECB letter ref"],
    "evidence": {"snapshot_id": "SNAP-1", "fingerprint": "f" * 64, "environment": "prod"},
    "assessment": {"total_crypto_instances": 12,
                   "admission": {"decision": "FAIL", "blocking": 3, "warnings": 1},
                   "hndl": {"at_risk": True, "total": 2, "by_exposure": {"critical": 2}},
                   "hsm_fleet": {"total": 3, "pqc_ready": 1, "pqc_gap": 2},
                   "mainframe_inventory": {"total": 6, "by_source": {"racf": 2}}},
    "hndl_register": [
        {"algorithm": "RSA", "key_size": 2048, "purpose": "key_exchange",
         "application": "payments-core", "confidentiality_years": 10,
         "deadline": 2030, "exposure": "critical", "bom_ref": "crypto:1"},
    ],
    "phases": [
        {"phase": "P1", "title": "Purge weak legacy", "deadline": 2027,
         "action": "retire DES/3DES",
         "items": [{"family": "DES", "instances": 4, "applications": ["payments-core"]}]},
    ],
    "attestation": "Produced from the Technology BOM.",
}

OWNERS = {"payments-core": "payments-team"}


def test_action_plan_html_renders_owners_and_phases():
    html = render_action_plan_html(PLAN, OWNERS)
    assert "Test Bank" in html and "SNAP-1" in html
    assert "payments-team" in html          # owner assigned
    assert "unassigned" not in html.split("HNDL")[1].split("Phased")[0]
    assert "P1 — Purge weak legacy" in html
    assert html.strip().startswith("<!doctype html")


def test_action_plan_csv_is_a_register():
    text = render_action_plan_csv(PLAN, OWNERS)
    lines = text.strip().splitlines()
    assert lines[0].startswith("algorithm,key_size,purpose,application,owner")
    assert "payments-core,payments-team" in lines[1]
    assert len(lines) == 2


# --------------------------------------------------------------------------- #
# Integrations
# --------------------------------------------------------------------------- #

ASSET_ROWS = [
    {"label": "PAYGW", "algorithm": "RSA", "key_size": 2048, "purpose": "signature",
     "source_language": "zos-racf", "file_path": "racf://PAYGW", "expires": "2027-01-01"},
    {"label": "PAY.ZEK", "algorithm": "AES", "key_size": 256, "purpose": "cipher",
     "source_language": "zos-icsf", "file_path": "icsf://PAY.ZEK"},
]


def test_servicenow_cmdb_payload_shapes():
    out = to_servicenow_cmdb(ASSET_ROWS)
    assert out["integration"] == "servicenow" and out["count"] == 2
    assert out["records"][0]["sys_class_name"] == "cmdb_ci_certificate"
    assert out["records"][1]["sys_class_name"] == "cmdb_ci_crypto_key"
    assert out["records"][0]["u_algorithm"] == "RSA"


def test_qualys_csv_flags_weak_and_quantum_only():
    rows = ASSET_ROWS + [
        {"algorithm": "DES", "key_size": 56, "purpose": "mac", "source": "icsf", "asset": "m1"},
        {"source": "db2", "asset": "PAYDB", "ssl_enabled": False},
    ]
    text = to_qualys_csv(rows)
    lines = [l.split(",") for l in text.strip().splitlines()]
    assert lines[0][:3] == ["ASSET", "TYPE", "SERVICE"]
    results = [l[4] for l in lines[1:]]
    assert any("cleartext endpoint" in r for r in results)
    assert any("DES" in r and "deprecated_after_2030" not in r for r in results)
    # AES-256 (not vulnerable, symmetric) must NOT appear
    assert not any("AES" in r for r in results)


def test_crosswalk_and_trust_package():
    xw = soc2_iso_crosswalk()
    assert any(any("A.8.24" in ctrl for ctrl in c["iso27001"]) for c in xw["controls"])
    pkg = procurement_trust_package({"generated_at": "2026-09-10", "overview": {}})
    assert pkg["package"] == "procurement-trust-package"
    assert any("operator" in lim for lim in pkg["honest_limits"])


# --------------------------------------------------------------------------- #
# Scale — 100k+ certificates through the full pipeline
# --------------------------------------------------------------------------- #

def _synthetic_certs(n: int) -> list[dict]:
    algs = [("RSA", 2048), ("ECDSA", 256), ("AES", 256), ("3DES", 112), ("RSA", 3072)]
    return [{"bom-ref": f"crypto:{i}", "algorithm": algs[i % len(algs)][0],
             "key_size": algs[i % len(algs)][1],
             "purpose": ("key_exchange" if i % 3 == 0 else "signature"),
             "application": f"app-{i % 50}", "asset": f"host-{i % 500}"}
            for i in range(n)]


def test_scale_120k_certificates_through_pipeline():
    import time

    from cbom.banking import hndl_register, migration_roadmap

    state = {"layers": {"cbom": {"components": _synthetic_certs(120_000), "count": 120_000}}}
    t0 = time.perf_counter()
    reg = hndl_register(state)
    rm = migration_roadmap(state)
    sns = to_servicenow_cmdb(state["layers"]["cbom"]["components"][:100_000])
    elapsed = time.perf_counter() - t0
    assert reg["total"] > 0 and rm["total_in_scope"] > 0
    assert sns["count"] == 100_000
    assert elapsed < 60, f"pipeline too slow at 120k certs: {elapsed:.1f}s"
