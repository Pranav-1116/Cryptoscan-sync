"""Second CBOM review: TLS assessment, risk dimensions, PQC deployment ladder,
X.509 signature normalization and coverage honesty.

Each test pins a behaviour the review found missing or wrong in an export:
a TLS label judged without its handshake, one risk number hiding separate
axes, "PQC ready" from a source string, ``sha256WithRSAEncryption`` read as
SHA-1, and 100% coverage despite a failed collection.
"""

from __future__ import annotations

from cbom import crypto_risk, pqc_deployment, tls_analysis
from cbom.coverage_render import inventory_coverage
from cbom.crypto_normalization import normalize


# --------------------------------------------------------------------------- #
# TLS
# --------------------------------------------------------------------------- #


def test_suite_parser_decomposes_iana_openssl_and_tls13_names():
    iana = tls_analysis.parse_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    openssl = tls_analysis.parse_suite("ECDHE-RSA-AES128-GCM-SHA256")
    for parsed in (iana, openssl):
        assert parsed["recognized"] and not parsed["tls13"]
        assert (parsed["key_exchange"], parsed["authentication"], parsed["cipher"], parsed["cipher_bits"],
                parsed["mode"]) == ("ECDHE", "RSA", "AES", 128, "GCM")
        assert parsed["aead"] and parsed["forward_secrecy"]
    tls13 = tls_analysis.parse_suite("TLS_AES_256_GCM_SHA384")
    assert tls13["tls13"] and tls13["cipher_bits"] == 256
    # TLS 1.3 suites do not name the key exchange; the parser must not invent one
    assert tls13["key_exchange"] == "(EC)DHE_OR_PSK_NEGOTIATED_SEPARATELY"
    rc4 = tls_analysis.parse_suite("RC4-MD5")
    assert rc4["cipher"] == "RC4" and not rc4["forward_secrecy"] and not rc4["aead"]


def test_a_tls_version_label_alone_is_neither_approved_nor_deprecated():
    bare = tls_analysis.assess(version="TLS 1.2")
    assert bare["configuration_level"] == "REVIEW"
    assert "not recorded" in bare["configuration_reasons"][0]
    observed = tls_analysis.assess(version="TLSv1.2", cipher_suite="ECDHE-RSA-AES128-GCM-SHA256",
                                   cert_public_key_algorithm="RSA", cert_public_key_bits=2048,
                                   cert_signature_algorithm="sha256WithRSAEncryption")
    assert observed["configuration_level"] == "NONE"
    assert observed["certificate"]["signature_digest"] == "SHA-256"


def test_prohibited_versions_and_disallowed_suites_are_high():
    old = tls_analysis.assess(version="TLSv1.0", cipher_suite="ECDHE-RSA-DES-CBC3-SHA")
    assert old["version_status"] == "PROHIBITED" and old["configuration_level"] == "HIGH"
    assert any("3DES" in why for why in old["configuration_reasons"])


def test_hybrid_pqc_group_is_recognized_only_when_recorded():
    hybrid = tls_analysis.assess(version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384", group="X25519MLKEM768")
    assert hybrid["key_exchange"]["pqc_hybrid"] is True and hybrid["key_exchange"]["group_recorded"]
    unknown = tls_analysis.assess(version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384")
    assert unknown["key_exchange"]["group_recorded"] is False
    assert not unknown["key_exchange"].get("pqc_hybrid")


# --------------------------------------------------------------------------- #
# risk dimensions
# --------------------------------------------------------------------------- #


def _risk(name, **kwargs):
    key_size = kwargs.pop("key_size", None)
    curve = kwargs.pop("curve", None)
    return crypto_risk.assess(normalize(name, key_size=key_size, curve=curve, purpose=kwargs.get("purpose")),
                              **kwargs)


def test_rsa_2048_is_classically_sound_but_quantum_exposed_on_separate_axes():
    risk = _risk("RSA", key_size=2048, purpose="KEY_EXCHANGE", criticality="CRITICAL")
    dims = risk["dimensions"]
    assert dims["classical"]["level"] == "NONE"
    assert dims["quantum"]["level"] == "HIGH" and dims["quantum"]["shor_exposed"]
    assert dims["migration_urgency"]["level"] == "HIGH"
    # a quantum-only exposure is a migration item, not a classical finding
    assert risk["priority"] == "P4"
    assert dims["deployment_verification"]["level"] == "NOT_VERIFIED"
    assert crypto_risk.RISK_MODEL_VERSION.endswith("/2.0.0")


def test_hardcoded_key_raises_the_configuration_axis_not_the_algorithm():
    dims = _risk("RSA", key_size=2048, purpose="SIGNING", hardcoded_key=True)["dimensions"]
    assert dims["configuration"]["level"] == "HIGH"
    assert dims["classical"]["level"] == "NONE"
    assert dims["migration_urgency"]["level"] == "IMMEDIATE"


def test_modern_symmetric_and_pqc_have_no_axis_raised():
    for name, size in (("AES", 256), ("ML-KEM", 768)):
        dims = _risk(name, key_size=size)["dimensions"]
        for axis in ("classical", "quantum", "configuration", "migration_urgency"):
            assert dims[axis]["level"] == "NONE", (name, axis)


def test_runtime_observation_is_the_only_verified_deployment():
    observed = _risk("AES", key_size=128, deployment_stage="RUNTIME_OBSERVED", location="tls://10.0.0.1:443")
    assert observed["dimensions"]["deployment_verification"]["level"] == "OBSERVED_AT_RUNTIME"
    # a reachable listener is recorded as the basis; internet exposure is not inferred from it
    assert observed["dimensions"]["exposure"]["basis"] == "NETWORK_ENDPOINT_OBSERVED"
    assert observed["dimensions"]["exposure"]["level"] == "NOT_RECORDED"
    source = _risk("AES", key_size=128, deployment_stage="DETECTED_IN_SOURCE", location="src/A.java")
    assert source["dimensions"]["deployment_verification"]["level"] == "NOT_VERIFIED"
    assert source["dimensions"]["exposure"]["level"] == "NOT_RECORDED"


def test_bare_tls_12_is_review_until_the_handshake_is_known():
    risk = _risk("TLS 1.2")
    assert risk["finding_status"] == "REVIEW" or risk["dimensions"]["configuration"]["level"] == "REVIEW"
    assert normalize("TLS 1.2").registry_status == "CONDITIONAL"
    assert normalize("TLS 1.3").registry_status == "ALLOWED"


# --------------------------------------------------------------------------- #
# PQC deployment ladder
# --------------------------------------------------------------------------- #


def test_pqc_found_in_source_is_never_ready():
    ladder = pqc_deployment.stage_ladder(["DETECTED_IN_SOURCE"])
    assert ladder["highest_stage"] == "SOURCE"
    assert ladder["pqc_ready"] is False
    statuses = {step["stage"]: step["status"] for step in ladder["ladder"]}
    assert statuses["NEGOTIATED"] == "NOT_ESTABLISHED"
    assert statuses["APPROVED_FOR_PRODUCTION"] == "NOT_ESTABLISHED"


def test_pqc_ready_needs_both_negotiation_and_a_recorded_approval():
    negotiated = pqc_deployment.stage_ladder(["RUNTIME_OBSERVED"], negotiated=True)
    assert negotiated["pqc_ready"] is False and negotiated["approval_recorded"] is False
    approved_only = pqc_deployment.stage_ladder(["CONFIGURED"], approval_ref="CAB-2026-114")
    assert approved_only["pqc_ready"] is False
    ready = pqc_deployment.stage_ladder(["RUNTIME_OBSERVED"], negotiated=True, approval_ref="CAB-2026-114")
    assert ready["pqc_ready"] is True and ready["highest_stage"] == "APPROVED_FOR_PRODUCTION"


# --------------------------------------------------------------------------- #
# X.509 signature algorithms
# --------------------------------------------------------------------------- #


def test_x509_signature_names_keep_their_digest():
    rsa = normalize("sha256WithRSAEncryption")
    assert (rsa.name, rsa.primitive, rsa.oid, rsa.registry_status) == (
        "SHA256withRSA", "signature", "1.2.840.113549.1.1.11", "ALLOWED")
    assert normalize("RSA-SHA256").oid == rsa.oid  # OpenSSL digest name, same algorithm
    ec = normalize("ecdsa-with-SHA256")
    assert (ec.name, ec.oid) == ("SHA256withECDSA", "1.2.840.10045.4.3.2")
    assert normalize("SHA384withECDSA").oid == "1.2.840.10045.4.3.3"
    assert normalize("rsassa-pss").oid == "1.2.840.113549.1.1.10"


def test_sha1_and_md5_certificate_signatures_are_disallowed():
    for name in ("sha1WithRSAEncryption", "RSA-MD5", "DSA-SHA1"):
        assert normalize(name).registry_status == "DISALLOWED", name


def test_plain_algorithm_names_are_not_captured_by_the_signature_branch():
    assert normalize("SHA-256").primitive == "hash"
    assert normalize("RSA").primitive == "pke"
    assert normalize("HMAC-SHA256").primitive == "mac"


def test_a_registry_minimum_is_not_reported_as_the_deployed_key_size():
    assert normalize("RSA-OAEP").key_size_bits is None
    assert normalize("RSA-OAEP", key_size=3072).name == "RSA-3072-OAEP"
    assert normalize("DES").key_size_bits == 56  # genuinely fixed size


# --------------------------------------------------------------------------- #
# coverage honesty
# --------------------------------------------------------------------------- #


def test_a_failed_collection_makes_a_current_estate_partial():
    rollup = {"systems": 3, "with_cbom": 3, "counts": {"CURRENT": 3}}
    clean = inventory_coverage(rollup, assets=10)
    assert clean["completeness"] == "COMPLETE"
    failed = inventory_coverage(rollup, assets=10, failed_jobs=1)
    assert failed["completeness"] == "PARTIAL" and failed["may_report_total"] is False
    assert any("failed" in caveat for caveat in failed["caveats"])


def test_inspection_facts_override_the_stored_status_count():
    rollup = {"systems": 4, "with_cbom": 4, "counts": {"CURRENT": 4}}
    block = inventory_coverage(rollup, assets=7, systems_inspected=2, partial_systems=1)
    assert block["systems_inspected"] == 2
    assert block["completeness"] != "COMPLETE" and block["may_report_total"] is False
