"""The VBOM dependency graph, as tests.

The module under test turns a vendor payload into an estate, projects it into a TechBOM and
answers the questions the review asked for: which product, which release, which asset, which
application, which algorithm, which business system — and how strongly each of those is
believed.

Every test here asserts something the guide claims: a level, a state, a refusal, a kept
conflict, or the rule that declaration ≠ usage.
"""

from __future__ import annotations

import pytest
from cbom import techbom as tb
from cbom import vbom_dependency as v

AS_OF = "2026-11-03"

DIGEST_JAR = "sha256:abc123def4567890abc123def4567890"

PAYLOAD = {
    "as_of": AS_OF,
    "documents": [
        {"id": "DOC-1", "title": "payShield 8.4 policy", "vendor": "Thales",
         "product": "payShield 9000", "version": "8.4", "received_at": "2024-02-20",
         "valid_until": "2026-04-01", "reviewer": "s.iyer", "revision": 3},
        {"id": "DOC-2", "title": "payShield 8.4 firmware guide", "vendor": "Thales",
         "product": "payShield 9000", "version": "8.4", "firmware": "8.4",
         "received_at": "2026-09-01", "valid_until": "2027-09-01", "reviewer": "s.iyer",
         "revision": 1},
        {"id": "DOC-3", "title": "payShield 9.2 release notes", "vendor": "Thales",
         "product": "payShield 9000", "version": "9.2", "received_at": "2026-10-01",
         "valid_until": "2027-10-01", "reviewer": "s.iyer", "revision": 1},
        {"id": "DOC-4", "title": "OpenSSL 3.0.13", "vendor": "OpenSSL Project",
         "product": "OpenSSL", "version": "3.0.13", "received_at": "2026-09-15",
         "valid_until": "2027-09-15", "reviewer": "r.nair", "revision": 2},
        {"id": "DOC-OLD", "title": "Acme datasheet", "vendor": "Acme Legacy",
         "product": "Acme Datacrypt", "version": "4.2", "received_at": "2024-06-01"},
    ],
    "vendors": [
        {"name": "Thales", "lifecycle": "ACTIVE", "risk_level": "HIGH",
         "documents": ["DOC-1"]},
        {"name": "OpenSSL Project", "lifecycle": "ACTIVE", "risk_level": "MEDIUM"},
        {"name": "Acme Legacy", "lifecycle": "RETIRED", "documents": ["DOC-OLD"]},
    ],
    "products": [
        {"name": "payShield 9000", "vendor": "Thales", "family": "payShield", "type": "HSM",
         "lifecycle": "SUPPORTED", "documents": ["DOC-1"]},
        {"name": "payShield SDK", "vendor": "Thales", "type": "SDK"},
        {"name": "OpenSSL", "vendor": "OpenSSL Project", "type": "LIBRARY",
         "lifecycle": "SUPPORTED", "documents": ["DOC-4"]},
        {"name": "Acme Datacrypt", "vendor": "Acme Legacy", "type": "HSM",
         "lifecycle": "EOL", "eol_date": "2026-06-30", "documents": ["DOC-OLD"]},
        {"name": "Orphan Product", "type": "HSM"},
    ],
    "releases": [
        {"product": "payShield 9000", "version": "8.4", "support_status": "MAINTENANCE",
         "eol_date": "2027-01-31", "documents": ["DOC-1"],
         "capabilities": [
             {"algorithm": "RSA", "key_size": 2048, "purpose": "card verification",
              "documents": ["DOC-1"]},
             {"algorithm": "AES", "key_size": 256, "mode": "GCM", "documents": ["DOC-2"]},
         ]},
        {"product": "payShield 9000", "version": "9.2", "support_status": "SUPPORTED",
         "documents": ["DOC-3"],
         "capabilities": [
             {"algorithm": "ML-KEM", "key_size": 768, "documents": ["DOC-3"]},
         ]},
        {"product": "payShield SDK", "version": "5.7",
         "packages": [{"coordinate": "pkg:generic/payshield-sdk", "version": "5.7"}]},
        {"product": "OpenSSL", "version": "3.0.13", "pqc_capability": "DECLARED",
         "documents": ["DOC-4"],
         "packages": [{"coordinate": "pkg:generic/openssl", "version": "3.0.13"}],
         "capabilities": [
             {"algorithm": "RSA", "key_size": 2048, "documents": ["DOC-4"]},
             {"algorithm": "ML-KEM", "key_size": 768, "documents": ["DOC-4"]},
         ]},
        # refused by name: a capability with no document cannot be cited, and this release
        # cites none, so its capability inherits nothing
        {"product": "Acme Datacrypt", "version": "4.2", "support_status": "EOS",
         "capabilities": [{"algorithm": "RSA", "key_size": 2048}]},
        {"product": "payShield 9000", "version": ""},
    ],
    "firmware": [
        {"product": "payShield 9000", "version": "8.4.2", "release": "8.4",
         "support_status": "MAINTENANCE", "eol_date": "2027-01-31",
         "security_status": "PATCHED", "pqc_capability": "DECLARED",
         "documents": ["DOC-2"]},
        {"product": "payShield 9000", "version": "9.2.1", "release": "9.2",
         "support_status": "SUPPORTED", "security_status": "CURRENT",
         "pqc_capability": "DECLARED", "documents": ["DOC-3"]},
        {"product": "payShield 9000", "version": "8.4.1", "release": "8.4",
         "support_status": "EOL", "eol_date": "2025-12-31"},
    ],
    "assets": [
        {"name": "HSM-001", "type": "HSM", "product": "payShield 9000", "version": "8.4",
         "firmware": "8.4.2", "serial": "PS9K-0001", "location": "DC-01",
         "owner": "Payments", "documents": ["DOC-2"]},
        {"name": "HSM-002", "type": "HSM", "product": "payShield 9000", "version": "9.2",
         "firmware": "9.2.1", "location": "DC-02", "owner": "Payments"},
        {"name": "HSM-003", "type": "HSM", "product": "Acme Datacrypt", "version": "4.2",
         "firmware": "4.2.0", "serial": "AC-0003", "location": "DC-01"},
        {"name": "HSM-004", "type": "HSM"},
    ],
    "packages": [
        {"coordinate": "pkg:generic/openssl", "version": "3.0.11", "product": "OpenSSL"},
        {"coordinate": "pkg:generic/payshield-sdk", "version": "5.4",
         "product": "payShield SDK"},
    ],
    "applications": [
        {"name": "Payments API", "system": "Payments System", "owner": "payments-team",
         "packages": ["pkg:generic/openssl", "pkg:generic/payshield-sdk"],
         "products": ["payShield SDK"], "assets": ["HSM-001"],
         "endpoints": ["payments.bank.example:443"]},
        {"name": "Reporting API", "system": "Reporting System",
         "packages": ["pkg:generic/openssl"]},
    ],
    "systems": [{"name": "Payments System", "criticality": "TIER-1"},
                {"name": "Reporting System", "criticality": "TIER-3"}],
    "usage": [
        {"application": "Payments API", "process": "payments-api 1821", "pid": 1821,
         "host": "srv-k8s-03", "package": "pkg:generic/openssl", "package_version": "3.0.11",
         "algorithm": "RSA", "key_size": 2048, "operation": "SIGN",
         "observed_at": "2026-11-03T06:30:00Z"},
    ],
    "network": [
        {"name": "LB-001", "type": "LOAD_BALANCER", "product": "payShield 9000",
         "version": "8.4", "firmware": "8.4.2", "serial": "LB-0001",
         "endpoint": "payments.bank.example:443", "application": "Payments API",
         "certificate": "CERT-001", "tls_mode": "TERMINATE"},
    ],
    "pki": [
        {"ca": "Issuing CA", "product": "payShield 9000", "version": "8.4",
         "serial": "CA-0001", "certificate": "CERT-001",
         "endpoint": "payments.bank.example:443", "not_after": "2027-04-01"},
    ],
    "components": (
        [{"coordinate": f"pkg:generic/component-{index:03d}", "vendor": "Thales"}
         for index in range(8)]
        + [{"coordinate": f"pkg:generic/mystery-{index:03d}", "vendor": "UNKNOWN"}
           for index in range(2)]
    ),
    "history": [
        {"subject": "HSM-001", "field": "vendor", "previous": "Acme Legacy",
         "current": "Thales", "changed_at": "2026-10-01",
         "evidence_before": "DOC-OLD", "evidence_after": "DOC-1"},
        {"subject": "HSM-001", "field": "colour", "previous": "grey", "current": "black"},
    ],
}


@pytest.fixture(scope="module")
def built():
    return v.build(PAYLOAD, as_of=AS_OF, estate_id="vbom:test")


@pytest.fixture(scope="module")
def bom(built):
    return built["bom"]


# --------------------------------------------------------------------------- #
# 1. The levels, and what a level means
# --------------------------------------------------------------------------- #

def test_a_firmware_with_no_release_gets_no_dangling_edge():
    """A key is a name, not a node: an edge to a release the estate never declared is refused.

    The device's own row is where the firmware came from, so the firmware exists and
    ``RUNS_FIRMWARE`` lands on it — it simply has no ``FIRMWARE_OF`` until a release arrives.
    """
    payload = {
        "as_of": AS_OF,
        "vendors": [{"name": "Thales"}],
        "products": [{"name": "payShield 9000", "vendor": "Thales"}],
        "firmware": [{"product": "payShield 9000", "version": "9.2.1"}],
        "assets": [{"name": "HSM-001", "type": "HSM", "product": "payShield 9000",
                    "firmware": "9.2.1", "serial": "SN-1"}],
    }
    built = v.build(payload, as_of=AS_OF)
    assert [row for row in built["bom"]["refusals"] if row["code"] == "UNKNOWN_REF"] == []
    assert not any(claim["relation"] == "FIRMWARE_OF" for claim in built["bom"]["claims"])
    assert any(claim["relation"] == "RUNS_FIRMWARE" for claim in built["bom"]["claims"])

def test_the_ten_levels_are_ordered_low_to_high():
    assert [name for name, _, _ in v.LEVELS] == [
        "vendor", "product", "release", "firmware", "package", "asset", "application",
        "crypto", "runtime", "system"]


def test_every_level_has_kinds_and_a_stated_meaning():
    assert all(kinds and meaning for _, kinds, meaning in v.LEVELS)


def test_every_asset_kind_belongs_to_exactly_one_level():
    kinds = [kind for _, level_kinds, _ in v.LEVELS for kind in level_kinds]
    assert len(kinds) == len(set(kinds))
    assert v.KIND_LEVEL["PRODUCT_VERSION"] == "release"
    assert v.KIND_LEVEL["VENDOR_PRODUCT"] == "product"


def test_the_estate_populates_every_level(built):
    assert all(count > 0 for count in built["levels"].values()), built["levels"]


# --------------------------------------------------------------------------- #
# 2. Applicability — the eight states and the precedence
# --------------------------------------------------------------------------- #
def test_all_eight_states_exist_with_meaning():
    assert set(v.APPLICABILITY) == {
        "MATCHED", "PARTIAL_MATCH", "VERSION_MISMATCH", "PRODUCT_MISMATCH",
        "DEPLOYMENT_UNVERIFIED", "EXPIRED", "SUPERSEDED", "UNKNOWN"}
    assert all(v.APPLICABILITY_MEANS[state] for state in v.APPLICABILITY)


def test_the_precedence_ends_with_matched():
    assert v.PRECEDENCE[-1] == v.MATCHED
    assert v.PRECEDENCE[0] == v.PRODUCT_MISMATCH


def test_a_matching_verified_deployment_is_matched():
    answer = v.applicability({"product": "payShield 9000", "version": "8.4"},
                             {"asset": "HSM-001", "product": "payShield 9000",
                              "version": "8.4", "verified": True}, as_of=AS_OF)
    assert answer["state"] == v.MATCHED
    assert all(value == "PASS" for key, value in answer["checks"].items()
               if key in ("product", "version", "deployment", "supersession"))


def test_a_different_release_is_a_version_mismatch():
    answer = v.applicability({"product": "payShield 9000", "version": "8.4"},
                             {"asset": "HSM-002", "product": "payShield 9000",
                              "version": "9.2", "verified": True}, as_of=AS_OF)
    assert answer["state"] == v.VERSION_MISMATCH
    assert "8.4 is not 9.2" in answer["reason"]


def test_a_different_product_is_a_product_mismatch():
    answer = v.applicability({"product": "payShield 7000", "version": "8.4"},
                             {"asset": "HSM-001", "product": "payShield 9000",
                              "version": "8.4", "verified": True}, as_of=AS_OF)
    assert answer["state"] == v.PRODUCT_MISMATCH


def test_an_unverified_asset_is_deployment_unverified():
    answer = v.applicability({"product": "payShield 9000", "version": "9.2"},
                             {"asset": "HSM-002", "product": "payShield 9000",
                              "version": "9.2", "verified": False}, as_of=AS_OF)
    assert answer["state"] == v.DEPLOYMENT_UNVERIFIED


def test_an_expired_document_is_expired_not_applied():
    answer = v.applicability({"product": "payShield 9000", "version": "8.4",
                              "valid_until": "2026-04-01"},
                             {"asset": "HSM-001", "product": "payShield 9000",
                              "version": "8.4", "verified": True}, as_of=AS_OF)
    assert answer["state"] == v.EXPIRED


def test_a_superseded_revision_is_superseded():
    answer = v.applicability({"product": "payShield 9000", "version": "8.4",
                              "superseded_by": "DOC-2"},
                             {"asset": "HSM-001", "product": "payShield 9000",
                              "version": "8.4", "verified": True}, as_of=AS_OF)
    assert answer["state"] == v.SUPERSEDED


def test_a_prefix_release_is_only_a_partial_match():
    answer = v.applicability({"product": "payShield 9000", "version": "8.4",
                              "firmware": "8.4"},
                             {"asset": "HSM-001", "product": "payShield 9000",
                              "version": "8.4", "firmware": "8.4.2", "verified": True},
                             as_of=AS_OF)
    assert answer["state"] == v.PARTIAL_MATCH


def test_a_claim_with_no_version_is_unknown():
    answer = v.applicability({"product": "payShield 9000"},
                             {"asset": "HSM-001", "product": "payShield 9000",
                              "verified": True}, as_of=AS_OF)
    assert answer["state"] == "UNKNOWN"


def test_version_comparison_knows_only_prefix_and_equality():
    assert v.compare_versions("8.4", "8.4")["result"] == v.SAME
    assert v.compare_versions("8.4", "8.4.2")["result"] == v.PREFIX
    assert v.compare_versions("8.4", "8.40")["result"] == v.DIFFERENT
    assert v.compare_versions("", "8.4")["result"] == v.NOT_COMPARABLE


def test_the_estate_reaches_five_states_at_once(built):
    report = v.declaration_applicability(built["bom"], as_of=AS_OF)
    assert {"MATCHED", "PARTIAL_MATCH", "VERSION_MISMATCH", "EXPIRED",
            "DEPLOYMENT_UNVERIFIED"} <= set(report["states"])


# --------------------------------------------------------------------------- #
# 3. Lifecycle and evidence
# --------------------------------------------------------------------------- #
def test_lifecycle_is_derived_from_dates_when_no_state_is_stated():
    assert v.lifecycle_of({"name": "x", "eol_date": "2026-06-30"},
                          as_of=AS_OF)["state"] == v.EOL
    assert v.lifecycle_of({"name": "x", "eos_date": "2026-06-30"},
                          as_of=AS_OF)["state"] == v.EOS
    assert v.lifecycle_of({"name": "x", "eol_date": "2027-01-01"},
                          as_of=AS_OF)["state"] == v.SUPPORTED
    assert v.lifecycle_of({"name": "x"}, as_of=AS_OF)["state"] == v.UNKNOWN_LIFECYCLE


def test_an_explicit_state_beats_the_arithmetic():
    state = v.lifecycle_of({"name": "x", "lifecycle": "MAINTENANCE",
                            "eol_date": "2020-01-01"}, as_of=AS_OF)
    assert state["state"] == "MAINTENANCE" and state["terminal"] is False


def test_a_terminal_state_is_terminal():
    assert v.LIFECYCLE_TERMINAL == {"EOL", "EOS", "RETIRED"}


def test_expired_evidence_is_expired():
    report = v.evidence_freshness({"id": "DOC-1", "received_at": "2024-02-20",
                                   "valid_until": "2026-04-01"}, as_of=AS_OF)
    assert report["state"] == v.EVIDENCE_EXPIRED


def test_an_old_document_is_stale():
    report = v.evidence_freshness({"id": "DOC-OLD", "received_at": "2024-06-01"},
                                  as_of=AS_OF)
    assert report["state"] == v.VENDOR_EVIDENCE_STALE
    assert report["age_days"] > v.STALE_AFTER_DAYS


def test_an_undated_document_is_unknown_not_fresh():
    assert v.evidence_freshness({"id": "DOC-X"}, as_of=AS_OF)["state"] == v.EVIDENCE_UNKNOWN


def test_the_document_cites_reviewer_revision_and_hash():
    report = v.evidence_freshness({"id": "DOC-1", "received_at": "2026-10-01",
                                   "reviewer": "s.iyer", "revision": 3,
                                   "source_hash": "sha256:1a1a"}, as_of=AS_OF)
    assert (report["reviewer"], report["revision"], report["source_hash"]) == \
        ("s.iyer", 3, "sha256:1a1a")


# --------------------------------------------------------------------------- #
# 4. Building the graph
# --------------------------------------------------------------------------- #
def test_a_claim_with_no_document_is_refused(built):
    assert any(row["code"] == "VENDOR_CLAIM_WITHOUT_DOCUMENT" for row in built["refusals"])


def test_a_product_with_no_vendor_is_refused(built):
    assert ("PRODUCT_WITHOUT_VENDOR", "Orphan Product") in \
        {(row["code"], row["subject"]) for row in built["refusals"]}


def test_a_release_with_no_version_is_refused(built):
    assert any(row["code"] == "RELEASE_WITHOUT_VERSION" for row in built["refusals"])


def test_an_asset_with_no_product_is_refused(built):
    assert ("ASSET_WITHOUT_PRODUCT", "HSM-004") in \
        {(row["code"], row["subject"]) for row in built["refusals"]}


def test_a_capability_is_attached_to_a_release(built):
    bom = built["bom"]
    rows = [claim for claim in bom["claims"] if claim["relation"] == "SUPPORTS"]
    assert rows
    for claim in rows:
        assert bom["by_key"][claim["from_key"]]["kind"] == "PRODUCT_VERSION"


def test_the_product_is_supplied_by_the_vendor(built):
    bom = built["bom"]
    product = bom["by_key"][v._one(bom, "payShield 9000")]
    vendors = [bom["by_key"][target]["name"] for target, _ in
               v._neighbours(bom, product["key"], ["SUPPLIED_BY"])]
    assert vendors == ["Thales"]


def test_firmware_belongs_to_a_release(built):
    bom = built["bom"]
    firmware = bom["by_key"][v._one(bom, "payShield 9000 firmware 8.4.2")]
    releases = [bom["by_key"][target]["name"] for target, _ in
                v._neighbours(bom, firmware["key"], ["FIRMWARE_OF"])]
    assert releases == ["payShield 9000@8.4"]


# --------------------------------------------------------------------------- #
# 5. The walks the review asked for
# --------------------------------------------------------------------------- #
def test_vendor_to_product_lists_releases(bom):
    report = v.vendor_products(bom, vendor="Thales")
    assert [row["name"] for row in report["products"]] == ["payShield 9000", "payShield SDK"]
    assert [row["version"] for row in report["products"][0]["releases"]] == ["8.4", "9.2"]


def test_product_releases_carry_lifecycle_and_capabilities(bom):
    report = v.product_releases(bom, product="payShield 9000")
    assert report["releases"][0]["lifecycle_state"]["state"] == "MAINTENANCE"
    assert len(report["releases"][0]["capabilities"]) == 2


def test_vendor_to_asset_reaches_the_devices(bom):
    report = v.vendor_assets(bom, vendor="Thales", as_of=AS_OF)
    names = {row["name"] for row in report["assets"]}
    assert {"HSM-001", "HSM-002", "LB-001"} <= names
    devices = {(row["location"], row["owner"]) for row in report["assets"]
               if row["name"].startswith("HSM")}
    assert devices == {("DC-01", "Payments"), ("DC-02", "Payments")}


def test_the_hardware_chain_runs_vendor_product_firmware_asset(bom):
    report = v.hardware_chain(bom, asset="HSM-001")
    assert (report["vendor"], report["model"]) == ("Thales", "payShield 9000")
    assert report["firmware"][0]["version"] == "8.4.2"


def test_the_software_chain_crosses_a_package(bom):
    report = v.software_chain(bom, vendor="OpenSSL Project")
    assert "pkg:generic/openssl" in {row["name"] for row in report["packages"]}
    assert "Payments API" in {row["name"] for row in report["applications"]}


def test_the_crypto_chain_carries_key_size_and_mode(bom):
    report = v.crypto_chain(bom, vendor="Thales")
    assert all(row["algorithm"] for row in report["capabilities"])
    assert any(row["key_size"] == 256 and row["mode"] == "GCM"
               for row in report["capabilities"])


def test_the_crypto_chain_is_vendor_declared(bom):
    report = v.crypto_chain(bom, vendor="Thales")
    assert {row["class"] for row in report["capabilities"]} == {tb.VENDOR_DECLARED}


def test_declared_and_observed_are_kept_apart(bom):
    report = v.declared_vs_observed(bom, vendor="Thales")
    assert "ML-KEM-768 capability" in report["not_observed"]
    runtime = [row for row in report["rows"] if row["capability"] == "RSA-2048 capability"]
    assert runtime and runtime[0]["state"] == tb.RUNTIME_OBSERVED


def test_vendor_to_application_returns_the_path(bom):
    report = v.vendor_applications(bom, vendor="Thales")
    assert "Payments API" in {row["name"] for row in report["applications"]}
    assert all(row["path"] for row in report["applications"])


def test_vendor_to_system_answers_with_systems(bom):
    report = v.vendor_systems(bom, vendor="Thales")
    assert {row["name"] for row in report["systems"]} == {"Payments System",
                                                          "Reporting System"}


def test_an_eol_product_nothing_uses_reaches_no_system(bom):
    report = v.vendor_systems(bom, vendor="Acme Legacy")
    assert report["systems"] == []


def test_the_algorithm_question_is_scoped_to_the_algorithm(bom):
    rsa = v.crypto_business(bom, vendor="OpenSSL Project", algorithm="RSA")
    des = v.crypto_business(bom, vendor="OpenSSL Project", algorithm="3DES")
    assert rsa["systems"] and not des["systems"]
    assert des["statement"].endswith("none")


def test_runtime_dependency_names_the_process_and_the_operation(bom):
    report = v.runtime_dependency(bom, vendor="OpenSSL Project")
    assert [row["name"] for row in report["processes"]] == ["payments-api 1821"]
    assert {row["class"] for row in report["observations"]} == {tb.OBSERVED}


def test_network_dependency_reaches_the_endpoint_and_the_application(bom):
    report = v.network_dependency(bom, vendor="Thales")
    assert report["devices"] and report["endpoints"] and report["applications"]


def test_network_identity_names_the_tls_mode(bom):
    report = v.network_identity(bom, asset="LB-001")
    assert report["endpoints"][0]["tls_mode"] == "TERMINATE"
    assert report["endpoints"][0]["routes_to"] == ["Payments API"]


def test_pki_dependency_runs_ca_certificate_endpoint(bom):
    report = v.pki_dependency(bom, vendor="Thales")
    assert report["authorities"] and report["certificates"] and report["endpoints"]


# --------------------------------------------------------------------------- #
# 6. Firmware, lifecycle impact, freshness
# --------------------------------------------------------------------------- #
def test_firmware_posture_carries_every_field(bom):
    report = v.firmware_posture(bom, as_of=AS_OF)
    keys = {"release_date", "support_status", "eol_date", "eos_date", "security_status",
            "pqc_capability", "lifecycle", "devices"}
    assert all(keys <= set(row) for row in report["firmware"])
    assert any(row["lifecycle"] == "EOL" for row in report["firmware"])


def test_lifecycle_impact_fans_out_from_the_product(bom):
    report = v.lifecycle_impact(bom, product="Acme Datacrypt", as_of=AS_OF)
    assert report["lifecycle"]["state"] == "EOL"
    assert "asset" in report["affected"]


def test_the_evidence_report_ages_every_document(bom):
    report = v.evidence_report(bom, as_of=AS_OF)
    assert report["states"][v.EVIDENCE_EXPIRED] >= 1
    assert report["states"][v.VENDOR_EVIDENCE_STALE] >= 1


def test_verification_answers_the_five_checks(bom):
    report = v.verification(bom, as_of=AS_OF)
    assert report["rows"]
    for row in report["rows"]:
        assert {"product_match", "version_match", "firmware_match", "deployment_verified",
                "capability_observed"} <= set(row)
    assert any(row["state"] == v.MATCHED for row in report["rows"])


# --------------------------------------------------------------------------- #
# 7. Agreement with the other BOMs
# --------------------------------------------------------------------------- #
def test_sbom_agreement_keeps_both_versions(bom):
    report = v.sbom_agreement(bom, vendor="OpenSSL Project")
    conflict = report["conflicts"][0]
    assert (conflict["declared"], conflict["observed"]) == ("3.0.13", "3.0.11")
    assert conflict["state"] == "VENDOR_DEPLOYMENT_VERSION_CONFLICT"


def test_cbom_agreement_names_declared_only_algorithms(bom):
    report = v.cbom_agreement(bom, vendor="OpenSSL Project")
    assert "ML-KEM" in report["declared_only"]
    assert "RSA" in report["both"]


def test_hardware_identity_is_the_digest_the_other_boms_use(bom):
    report = v.hardware_identity(bom, asset="HSM-001")
    assert report["identity"]["digest"] == bom["by_key"][v._one(bom, "HSM-001")]["digest"]
    assert report["serial"] == "PS9K-0001"


# --------------------------------------------------------------------------- #
# 8. Conflicts, history, coverage, risk, PQC
# --------------------------------------------------------------------------- #
def test_a_version_conflict_names_its_layers(bom):
    report = v.version_conflicts(bom)
    assert report["conflicts"]
    assert all(row["code"] == "VENDOR_DEPLOYMENT_VERSION_CONFLICT"
               for row in report["conflicts"])
    assert any(len(row["layers"]) >= 2 for row in report["conflicts"])


def test_history_records_a_vendor_change_with_evidence():
    report = v.history(PAYLOAD)
    change = next(row for row in report["changes"] if row["field"] == "vendor")
    assert change["code"] == "VENDOR_CHANGED"
    assert (change["evidence_before"], change["evidence_after"]) == ("DOC-OLD", "DOC-1")


def test_history_ignores_a_field_that_is_not_a_dependency():
    report = v.history(PAYLOAD)
    assert all(row["field"] in v.HISTORY_FIELDS for row in report["changes"])
    assert len(report["changes"]) == 1


def test_coverage_separates_unknown_from_internal():
    report = v.coverage(PAYLOAD)
    assert report["coverage_percent"] == 80.0
    assert (report["unknown"], report["internal"]) == (2, 0)
    assert report["accounted_percent"] == 80.0


def test_coverage_counts_internal_as_accounted_not_as_identified():
    payload = {"components": [{"coordinate": "a", "vendor": "INTERNAL"},
                              {"coordinate": "b", "vendor": "UNKNOWN"},
                              {"coordinate": "c", "vendor": "Thales"}]}
    report = v.coverage(payload)
    assert report["coverage_percent"] == 33.3
    assert report["accounted_percent"] == 66.7


def test_risk_propagation_travels_through_the_graph(bom):
    report = v.risk_propagation(bom, vendor="Thales", as_of=AS_OF)
    assert report["score"] > 0
    assert report["weights"]["system"] == 2


def test_a_terminal_lifecycle_multiplies_the_score(bom):
    report = v.risk_propagation(bom, vendor="Acme Legacy", as_of=AS_OF)
    assert report["terminal"]
    assert report["score"] == report["base"] * 2


def test_a_vendor_that_reaches_no_system_says_so(bom):
    report = v.risk_propagation(bom, vendor="Acme Legacy", as_of=AS_OF)
    assert report["systems"] == []


def test_pqc_is_three_answers_and_never_ready(bom):
    report = v.pqc_posture(bom, vendor="Thales")
    assert report["declared"] == v.PQC_DECLARED
    assert report["runtime"] == v.PQC_NOT_OBSERVED
    assert "READY" not in report["statement"].upper()


def test_the_twin_reports_levels_edges_and_gaps(bom):
    report = v.twin(bom)
    assert report["gaps"] == []
    assert {"SUPPLIED_BY", "RELEASES", "SUPPORTS", "DOCUMENTED_BY"} <= \
        set(report["vendor_edges"])


def test_the_document_names_the_schema_and_its_own_limits(built):
    assert built["schema"] == v.SCHEMA
    assert "asset(s)" in built["statement"]


def test_an_unknown_query_is_refused_rather_than_guessed(bom):
    with pytest.raises(tb.ClaimRefused) as refused:
        v.vendor_products(bom, vendor="Nobody")
    assert refused.value.code == "UNKNOWN_NODE"
