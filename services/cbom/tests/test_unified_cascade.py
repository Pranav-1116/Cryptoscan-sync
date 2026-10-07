"""Unified cross-BOM cascade — the engine, tested as a pure function.

One target, every layer: what breaks if RSA goes away, if this certificate
is revoked, if that system is taken down. The engine sees the same snapshot
dict the digital twin sees, so these tests build that shape directly — no
DB, no API — and probe each target kind, propagation, honesty and errors.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cbom.unified_cascade import (
    MAX_DEPTH_LIMIT,
    identify_target,
    unified_cascade,
)

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)

SNAPSHOT = {
    "assets": [
        {"asset_id": "hsm-01", "algorithms": {"RSA-2048": 3},
         "libraries": {"BouncyCastle": "1.7"}, "protocols": {},
         "quantum_status": {}, "capabilities": {}, "usage": {},
         "certificates": {}, "cbom_version": 3},
        {"asset_id": "pay-02", "algorithms": {"ML-KEM": 1},
         "libraries": {"liboqs": "0.9"}, "protocols": {},
         "quantum_status": {}, "capabilities": {}, "usage": {},
         "certificates": {}, "cbom_version": 4},
    ],
    "systems": [
        {"id": "sys-pay", "name": "payment-api", "criticality": "TIER-1",
         "vendor_ids": ["v-thales"]},
        {"id": "sys-web", "name": "web-frontend", "vendor_ids": []},
        {"id": "sys-db", "name": "customer-db", "vendor_ids": []},
    ],
    "certificates": [
        {"fingerprint_sha256": "ab" * 32, "subject": "CN=payment-api",
         "issuer": "CN=acme-ca", "not_after": "2027-01-01T00:00:00+00:00",
         "expiry_status": "VALID", "renewal_status": "MONITOR",
         "public_key_algorithm": "RSA", "public_key_size": 2048},
    ],
    "vendors": [
        {"id": "v-thales", "name": "Thales", "criticality": "HIGH",
         "vendor_type": "hsm"},
    ],
    "system_vendors": [
        {"system_id": "sys-pay", "vendor_id": "v-thales",
         "dependency_type": "runtime"},
    ],
    "evidence": [
        {"id": "ev-1", "system_id": "sys-pay", "algorithm": "RSA-2048",
         "file_path": "src/Pay.java", "confidence": 0.9},
        {"id": "ev-2", "system_id": "sys-web", "algorithm": "RSA-2048",
         "file_path": "src/Web.java", "confidence": 0.9},
        {"id": "ev-3", "system_id": None, "algorithm": "ECDSA-P256",
         "file_path": "src/Unknown.java", "confidence": 0.5},
    ],
    "dependencies": [
        {"source": "sys-web", "target": "sys-pay", "type": "CALLS"},
        {"source": "sys-pay", "target": "sys-db", "type": "CALLS"},
    ],
    "network_endpoints": [
        {"host": "api.bank", "port": 443, "protocol": "tcp",
         "version": "TLSv1.2", "cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256",
         "observed": True, "certificate_subject": "CN=payment-api",
         "system_id": "sys-pay"},
        {"host": "legacy.bank", "port": 8443, "observed": False,
         "system_id": None, "certificate_subject": None},
    ],
    "hardware": [
        {"asset_id": "hsm-001", "manufacturer": "Thales", "model": "Luna 7",
         "firmware": "7.4",
         "hsm": {"manufacturer": "Thales", "model": "Luna 7",
                 "pqc_capability": "READY"}},
    ],
}


def run(target, **kwargs):
    return unified_cascade(SNAPSHOT, target=target, now=NOW, **kwargs)


# ------------------------------------------------------------ target kinds

def test_algorithm_cascade_spans_code_network_and_twin_assets():
    result = run("RSA-2048")
    assert result["verdict"] == "AFFECTED"
    assert result["target"]["kind"] == "algorithm"
    assert result["layers"]["code"]["systems"] == ["sys-pay", "sys-web"]
    assert result["layers"]["code"]["evidence_ids"] == ["ev-1", "ev-2"]
    assert result["layers"]["code"]["files"] == ["src/Pay.java", "src/Web.java"]
    # the wire: the endpoint negotiated an RSA key exchange
    assert result["layers"]["network"]["endpoints"] == ["api.bank:443"]
    # the twin: which assets carry the algorithm, which libraries serve it
    assert result["impact"]["twin_assets"] == ["hsm-01"]
    assert result["impact"]["libraries"] == ["BouncyCastle"]


def test_certificate_cascade_by_fingerprint_names_endpoints():
    result = run("ab" * 32)
    assert result["target"]["kind"] == "certificate"
    assert result["verdict"] == "AFFECTED"
    assert result["layers"]["network"]["endpoints"] == ["api.bank:443"]
    assert result["impact"]["certificate"]["not_after"] == "2027-01-01T00:00:00+00:00"
    assert result["impact"]["certificate"]["renewal_status"] == "MONITOR"


def test_certificate_cascade_by_subject():
    result = run("CN=payment-api")
    assert result["target"]["kind"] == "certificate"
    assert result["layers"]["network"]["endpoints"] == ["api.bank:443"]


def test_endpoint_cascade_reports_wire_and_owner():
    result = run("api.bank:443")
    assert result["target"]["kind"] == "endpoint"
    assert result["layers"]["network"]["tls_versions"] == ["TLSv1.2"]
    assert result["layers"]["network"]["cipher_suites"] == [
        "TLS_RSA_WITH_AES_128_GCM_SHA256"]
    assert result["layers"]["system"]["systems"] == ["sys-pay"]


def test_endpoint_cascade_by_bare_host():
    result = run("api.bank")
    assert result["target"]["kind"] == "endpoint"
    assert result["layers"]["network"]["endpoints"] == ["api.bank:443"]


def test_system_cascade_walks_graph_both_directions():
    result = run("payment-api")  # by name, not id
    assert result["target"]["kind"] == "system"
    assert result["verdict"] == "AFFECTED"
    # web-frontend calls payment-api; payment-api calls customer-db
    assert result["layers"]["system"]["dependents_by_depth"] == {"1": ["sys-web"]}
    assert result["layers"]["system"]["downstream_by_depth"] == {"1": ["sys-db"]}
    assert result["impact"]["affected_system_count"] == 3
    assert result["layers"]["code"]["algorithms"] == ["RSA-2048"]
    assert result["layers"]["vendor"]["vendors"] == ["Thales"]


def test_vendor_cascade_spans_systems_and_hardware():
    result = run("Thales")
    assert result["target"]["kind"] == "vendor"
    assert result["layers"]["system"]["systems"] == ["payment-api"]
    assert result["layers"]["hardware"]["devices"] == ["hsm-001"]
    assert result["layers"]["vendor"]["criticality"] == "HIGH"
    # the vendor's system keeps its dependents: web-frontend calls payment-api
    assert result["layers"]["system"]["dependents_by_depth"] == {"1": ["sys-web"]}
    assert "vendor-of-vendor" in " ".join(result["honest_unknowns"])


def test_device_cascade_is_inventory_honest():
    result = run("hsm-001")
    assert result["target"]["kind"] == "device"
    hardware = result["layers"]["hardware"]
    assert hardware["devices"] == ["hsm-001"]
    assert hardware["pqc_capability"] == "READY"
    # a device with no modelled crypto linkage cannot name dependents — say so
    assert hardware["inventory_only"] is True
    assert any("dependents" in u for u in result["honest_unknowns"])


def test_device_cascade_by_manufacturer():
    result = run("Luna", kind="device")
    assert result["target"]["kind"] == "device"
    assert result["layers"]["hardware"]["model"] == "Luna 7"


def test_library_cascade_names_assets_and_algorithms():
    result = run("liboqs")
    assert result["target"]["kind"] == "library"
    assert result["layers"]["code"]["assets"] == ["pay-02"]
    assert result["layers"]["code"]["algorithms"] == ["ML-KEM"]


# ------------------------------------------------------------ honesty

def test_not_found_is_a_verdict_with_unknowns():
    result = run("does-not-exist")
    assert result["verdict"] == "NOT_FOUND"
    assert result["target"]["matched"] is None
    assert result["impact"]["affected_system_count"] == 0
    assert result["honest_unknowns"]


def test_insufficient_data_when_nothing_is_affected():
    result = run("ECDSA-P256")  # evidence exists but links to no system
    assert result["verdict"] in {"AFFECTED", "INSUFFICIENT_DATA"}
    # evidence ev-3 has no system linkage: the cascade must not invent one
    assert result["layers"]["code"]["systems"] == []


def test_honest_unknowns_always_present():
    for target in ("RSA-2048", "payment-api", "Thales", "hsm-001", "api.bank:443"):
        assert run(target)["honest_unknowns"], target


def test_deterministic_and_read_only():
    first = run("payment-api")
    second = run("payment-api")
    assert first == second
    assert first["deterministic"] is True
    assert first["mutates_nothing"] is True
    # the snapshot itself must not have been mutated
    assert SNAPSHOT["systems"][0]["name"] == "payment-api"


# ------------------------------------------------------------ errors

@pytest.mark.parametrize("kwargs", [
    {"target": ""},
    {"target": "   "},
    {"target": "x", "max_depth": 0},
    {"target": "x", "max_depth": MAX_DEPTH_LIMIT + 1},
    {"target": "x", "kind": "nonsense"},
])
def test_bad_input_raises_value_error(kwargs):
    with pytest.raises(ValueError):
        unified_cascade(SNAPSHOT, now=NOW, **kwargs)


def test_max_depth_bounds_are_inclusive():
    assert run("payment-api", max_depth=1)["impact"]["max_propagation_depth"] == 1
    assert run("payment-api", max_depth=MAX_DEPTH_LIMIT)["verdict"] == "AFFECTED"


def test_identify_target_kind_hint_overrides_detection_order():
    # "Thales" is a vendor name AND a hardware manufacturer — explicit kind wins
    assert identify_target(SNAPSHOT, "Thales", "vendor")["kind"] == "vendor"
    assert identify_target(SNAPSHOT, "Thales", "device")["kind"] == "device"
    # without a hint, the more specific registry (vendor) wins
    assert identify_target(SNAPSHOT, "Thales")["kind"] == "vendor"


def test_fingerprint_wins_over_less_specific_kinds():
    # a hex fingerprint is matched as a certificate even though it contains
    # no host, system or vendor marker
    identified = identify_target(SNAPSHOT, "ab" * 32)
    assert identified["kind"] == "certificate"


def test_schema_version_stable():
    assert run("payment-api")["schema"] == "cryptoscan.unified-cascade/1"
