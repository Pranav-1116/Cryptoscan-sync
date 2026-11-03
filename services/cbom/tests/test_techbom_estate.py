"""Guide 166 tests — the stored inventory becomes an estate, never an observation."""

from __future__ import annotations

import pytest

from cbom import techbom as t
from cbom import techbom_estate as te
from cbom import techbom_queries as q


def inventory(**overrides):
    base = {
        "applications": [
            {"id": "SYS-1", "name": "Payments", "owner": "Payments Platform",
             "environment": "prod", "criticality": "CRITICAL"},
            {"id": "SYS-2", "name": "Cards", "owner": "Cards team",
             "criticality": "HIGH"},
        ],
        "system_assets": [{"id": "SA-1", "system_id": "SYS-1", "asset_id": "CA-1"},
                          {"id": "SA-2", "system_id": "SYS-1", "asset_id": "CA-2"}],
        "crypto": [
            {"id": "CA-1", "algorithm": "AES", "key_size": 256, "asset": "db-01",
             "library": "OpenSSL 3.0.13", "evidence_links": ["EV-1"]},
            {"id": "CA-2", "algorithm": "RSA", "key_size": 2048, "asset": "db-01",
             "library": "OpenSSL 3.0.13", "evidence_links": ["EV-2"]},
        ],
        "hardware": [
            {"asset_id": "HSM-01", "manufacturer": "Vendor X", "model": "HSM-9000",
             "device_type": "hsm", "firmware": "8.4", "hsm": {"model": "HSM-9000"},
             "crypto_capabilities": ["RSA-2048", "AES-256"],
             "evidence_history": ["EV-H1"], "asset": "SYS-1"},
            {"id": "SRV-12", "manufacturer": "Dell", "model": "R760",
             "device_type": "server", "tpm": True, "firmware": "2.1"},
        ],
        "vendors": [{"name": "Vendor X", "product": "HSM-9000", "lifecycle": "supported"}],
        "certificates": [{"fingerprint": "ab" * 32,
                          "subject": "CN=payments.bank.example"}],
        "system_dependencies": [
            {"parent_id": "SYS-1", "child_id": "SYS-2", "source": "discovered",
             "evidence_ref": "EV-DEP-1"},
        ],
        "software": [
            {"component_type": "library", "name": "OpenSSL",
             "coordinate": "library/OpenSSL", "origin": "CODE_AND_MANIFEST",
             "version": "3.0.13"},
            {"component_type": "package", "name": "left-pad",
             "coordinate": "pkg:npm/left-pad@1.0", "origin": "MANIFEST_DECLARED",
             "version": "1.0", "declared_in": "package.json"},
        ],
        "dependencies": [["pkg:npm/left-pad@1.0", "library/OpenSSL", "depends_on"]],
        "scan": {"software": {"scan_id": "SCAN-9", "state": "OBSERVED"}},
    }
    base.update(overrides)
    return base


@pytest.fixture()
def built():
    body = te.from_inventory(inventory(), environment="PRODUCTION")
    return body, t.build(body["estate"])


# --------------------------------------------------------------------------- #
# the estate it produces
# --------------------------------------------------------------------------- #

def test_the_adapter_accepts_the_inventory_and_build_accepts_its_estate(built):
    body, bom = built
    assert body["estate"]["schema"] == t.ESTATE_SCHEMA
    assert bom["schema"] == t.SCHEMA
    assert bom["refusals"] == []
    assert bom["projection"] is True
    assert body["skipped"] == []


def test_every_asset_and_claim_carries_an_evidence_reference(built):
    _, bom = built
    assert all(row["evidence_ids"] for row in bom["assets"])
    assert all(row["evidence_ids"] for row in bom["claims"])


def test_systems_become_business_systems_with_their_owner_and_criticality(built):
    _, bom = built
    payments = bom["by_key"]["BUSINESS_SYSTEM:payments:production"]
    assert payments["owner"] == "Payments Platform"
    assert payments["attributes"]["criticality"] == "CRITICAL"


def test_a_registration_links_a_system_to_the_asset_it_holds(built):
    _, bom = built
    owns = [row for row in bom["claims"] if row["relation"] == "OWNS"]
    assert len(owns) == 3  # two registered crypto assets and the HSM row's owner
    assert {row["confidence"] for row in owns} == {"IMPORTED"}
    assert all(row["basis"] == "operator-registration" for row in owns)


def test_a_crypto_asset_brings_its_library_and_the_host_it_was_found_on(built):
    _, bom = built
    library = bom["by_key"]["CRYPTO_LIBRARY:openssl 3.0.13:production"]
    assert library
    provides = [row for row in bom["claims"]
                if row["relation"] == "PROVIDES_ALGORITHM"]
    assert len(provides) == 2
    found = [row for row in bom["claims"] if row["relation"] == "FOUND_ON"]
    assert all(bom["by_key"][row["to_key"]]["kind"] == "HOST" for row in found)


def test_an_hsm_brings_its_firmware_capabilities_and_vendor(built):
    _, bom = built
    hsm = bom["by_key"]["HSM:hsm-01:production"]
    assert hsm["attributes"]["supports"] == ["RSA-2048", "AES-256"]
    assert any(row["relation"] == "RUNS_FIRMWARE" for row in bom["claims"])
    assert any(row["relation"] == "SUPPLIED_BY" and row["confidence"] == "VENDOR_DECLARED"
               for row in bom["claims"])


def test_a_tpm_server_becomes_a_tpm_and_its_firmware(built):
    _, bom = built
    kinds = {row["kind"] for row in bom["assets"]}
    assert "TPM" in kinds and "FIRMWARE" in kinds


def test_a_certificate_row_stops_at_the_certificate(built):
    _, bom = built
    kinds = {row["kind"] for row in bom["assets"]}
    assert "CERTIFICATE" in kinds
    assert "PUBLIC_KEY" not in kinds and "ALGORITHM" not in kinds
    assert any("key layer is not derived" in line for line in
               te.from_inventory(inventory())["not_proven"])


def test_software_rows_keep_their_origin_and_their_scan(built):
    _, bom = built
    package = bom["by_key"]["PACKAGE:pkg:npm/left-pad@1.0:production"]
    assert package["attributes"]["origin"] == "MANIFEST_DECLARED"
    assert "package.json" in package["attributes"]["declared_in"]
    edge = next(row for row in bom["claims"]
                if row["from_key"] == package["key"])
    assert edge["relation"] == "DEPENDS_ON"


# --------------------------------------------------------------------------- #
# classes: a stored row is never an observation
# --------------------------------------------------------------------------- #

def test_nothing_from_the_inventory_is_ever_observed(built):
    _, bom = built
    classes = {row["confidence"] for row in bom["claims"]}
    assert "OBSERVED" not in classes
    assert classes <= {"CONFIGURED", "IMPORTED", "VENDOR_DECLARED", "INFERRED"}
    assert "not an observation" in te.from_inventory(inventory())["statement"]


def test_a_discovered_dependency_is_configured_and_a_manual_one_is_imported():
    for source, expected in (("discovered", "CONFIGURED"), ("imported", "IMPORTED"),
                             ("manual", "IMPORTED")):
        body = te.from_inventory(inventory(system_dependencies=[
            {"parent_id": "SYS-1", "child_id": "SYS-2", "source": source,
             "evidence_ref": "EV-DEP-1"}]))
        bom = t.build(body["estate"])
        edge = next(row for row in bom["claims"] if row["relation"] == "DEPENDS_ON")
        assert edge["confidence"] == expected


def test_a_dependency_with_no_provenance_is_refused_by_name():
    body = te.from_inventory(inventory(system_dependencies=[
        {"parent_id": "SYS-1", "child_id": "SYS-2", "source": ""}]))
    assert body["skipped"][0]["kind"] == "DEPENDENCY"
    assert "manual, discovered or imported" in body["skipped"][0]["reason"]
    bom = t.build(body["estate"])
    systems = {row["key"] for row in bom["assets"] if row["kind"] == "BUSINESS_SYSTEM"}
    assert not any(row["relation"] == "DEPENDS_ON"
                   and row["from_key"] in systems and row["to_key"] in systems
                   for row in bom["claims"])


def test_a_dependency_naming_an_unknown_system_is_refused():
    body = te.from_inventory(inventory(system_dependencies=[
        {"parent_id": "SYS-1", "child_id": "SYS-404", "source": "discovered"}]))
    assert body["skipped"][0]["kind"] == "DEPENDENCY"
    assert "undeclared" in body["skipped"][0]["reason"]


def test_an_unclassifiable_source_basis_refuses_the_asset():
    body = te.from_inventory(inventory(crypto=[
        {"id": "CA-9", "algorithm": "3DES", "source_basis": "mystery"}]))
    assert body["skipped"][0]["kind"] == "CRYPTO_ASSET"
    assert "cannot be placed with a confidence" in body["skipped"][0]["reason"]


def test_a_software_row_with_an_unstated_origin_is_refused():
    body = te.from_inventory(inventory(software=[
        {"component_type": "package", "name": "x", "coordinate": "pkg/npm/x", "origin": ""}]))
    assert body["skipped"][0]["kind"] == "PACKAGE"
    assert "does not say whether the code imports it" in body["skipped"][0]["reason"]


def test_code_import_evidence_outranks_a_manifest_row():
    body = te.from_inventory(inventory(
        software=[{"component_type": "package", "name": "x", "coordinate": "pkg/npm/x",
                   "origin": "CODE_IMPORT"},
                  {"component_type": "library", "name": "OpenSSL",
                   "coordinate": "library/OpenSSL", "origin": "MANIFEST_DECLARED"}],
        dependencies=[["pkg/npm/x", "library/OpenSSL", "depends_on"]]))
    bom = t.build(body["estate"])
    edge = next(row for row in bom["claims"]
                if row["relation"] == "DEPENDS_ON"
                and row["from_key"] == "PACKAGE:pkg/npm/x:production")
    assert edge["basis"] in ("code-analysis", "scan-manifest")
    assert edge["confidence"] in ("CONFIGURED", "IMPORTED")


# --------------------------------------------------------------------------- #
# empty and partial inventories stay honest
# --------------------------------------------------------------------------- #

def test_an_empty_inventory_produces_an_empty_estate_not_an_error():
    body = te.from_inventory({})
    bom = t.build(body["estate"])
    assert body["assets"] == 0 and body["claims"] == 0
    assert bom["assets"] == []
    assert bom["completeness"]["overall"] == "UNMEASURED"


def test_a_none_inventory_is_treated_as_empty():
    body = te.from_inventory(None)
    assert body["assets"] == 0


def test_completeness_uses_the_denominator_when_one_is_supplied():
    body = te.from_inventory(inventory(), expected={"BUSINESS_SYSTEM": 4, "HSM": 1},
                             gaps=[{"kind": "BUSINESS_SYSTEM",
                                    "reason": "2 systems not authorized"}])
    block = t.build(body["estate"])["completeness"]
    assert block["overall"] == "PARTIAL"
    assert block["gaps"][0]["reason"] == "2 systems not authorized"


def test_the_adapter_says_what_it_cannot_prove():
    limits = te.from_inventory(inventory())["not_proven"]
    assert any("still true" in line for line in limits)
    assert any("coverage is a denominator" in line for line in limits)


# --------------------------------------------------------------------------- #
# the answers, on live-shaped data
# --------------------------------------------------------------------------- #

def test_a_rollup_works_on_a_live_inventory_and_says_what_is_declared(built):
    _, bom = built
    profile = q.rollup(bom, system="Payments")["systems"][0]
    assert profile["counts"]["CRYPTO_ASSET"] == 2
    assert profile["counts"]["HSM"] == 1
    assert profile["counts"]["FIRMWARE"] == 1
    assert profile["declared_only_assets"] >= 1  # the vendor declaration
    assert "declared only" in profile["statement"]


def test_impact_on_live_data_names_the_hsm_blockers(built):
    _, bom = built
    body = q.impact(bom, query="RSA-2048", required_algorithms=["ML-KEM-768"])
    codes = {row["code"] for row in body["pqc_blockers"]}
    assert "HSM_PQC_UNSUPPORTED" in codes  # the HSM lists RSA/AES, not ML-KEM
    assert body["not_proven"]


def test_the_live_estate_feeds_a_timeline():
    first = t.build(te.from_inventory(inventory())["estate"])
    changed = inventory()
    changed["software"] = [{**row, "version": "3.0.11"} if row["name"] == "OpenSSL"
                           else row for row in changed["software"]]
    second = t.build(te.from_inventory(changed)["estate"])
    body = q.timeline([first, second])
    assert body["measurable"] is True
    assert body["by_change"]["TECHNOLOGY_VERSION_CHANGED"] == 1
