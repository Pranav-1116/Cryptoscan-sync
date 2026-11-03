"""The vendor dependency graph over the estate the API holds.

``test_vbom_dependency.py`` proves the graph; these tests prove the mapper that feeds it from
stored rows, the answers the API reads off it, and the four rules the mapper refuses to break:
no invented rows, no runtime claim from a static finding, no capability without a document and
no joining across environments.

The inventory dictionaries here are the shape ``_gather_inventory`` assembles — that shape is
the contract, so the tests state it rather than importing the API.
"""

from __future__ import annotations

import copy

import pytest
from cbom import vbom_dependency as v
from cbom import vbom_estate as ve

AS_OF = "2026-11-03"

INVENTORY = {
    "vendors": [
        {"name": "Thales", "product": "payShield 9000", "model": "payShield 9000",
         "version": "9.2", "lifecycle": "SUPPORTED", "risk_level": "HIGH",
         "crypto_capability": "PQC_READY"},
        {"name": "F5", "product": "BIG-IP 9000", "model": "BIG-IP 9000", "version": "17.1",
         "lifecycle": "SUPPORTED", "risk_level": "MEDIUM"},
    ],
    "vendor_crypto": [
        {"id": "vc-1", "vendor": "Thales", "product": "payShield 9000", "version": "9.2",
         "algorithm": "AES", "key_size": 256, "mode": "GCM",
         "crypto_use_case": "card data at rest", "source_document": "payShield 9.2 policy",
         "discovered_at": "2026-09-01", "confidence": "HIGH"},
    ],
    "hardware": [
        {"id": "h-1", "asset_id": "HSM-001", "manufacturer": "Thales",
         "model": "payShield 9000", "device_type": "hsm", "firmware": "9.2.1",
         "serial_reference": "SN-001", "location": "dc-1", "hsm": True},
        {"id": "h-2", "asset_id": "LB-001", "manufacturer": "F5", "model": "BIG-IP 9000",
         "device_type": "load_balancer", "firmware": "17.1", "serial_reference": "SN-002"},
        {"id": "h-3", "asset_id": "SRV-01", "manufacturer": "Dell", "model": "R760",
         "device_type": "server", "firmware": "2.1.0"},
        {"id": "h-4", "asset_id": "MYSTERY-01", "device_type": "hsm"},
    ],
    "software": [
        {"coordinate": "pkg:pypi/cryptography@42.0", "name": "cryptography",
         "version": "42.0", "vendor": "", "crypto_bearing": True},
        {"coordinate": "pkg:npm/left-pad@1.3.0", "name": "left-pad", "version": "1.3.0"},
        {"name": "no-coordinate", "version": "1.0"},
    ],
    "applications": [
        {"id": "s-1", "name": "Payments System", "owner": "ops", "criticality": "TIER_1",
         "environment": "PRODUCTION"},
    ],
    "crypto": [
        {"algorithm": "RSA", "key_size": 2048, "purpose": "signing", "file_path": "a.py",
         "confidence": "HIGH"},
    ],
    "scan": {"target": "payments-api", "state": "COMPLETE"},
}


@pytest.fixture()
def inventory():
    return copy.deepcopy(INVENTORY)


@pytest.fixture()
def mapped(inventory):
    return ve.payload_from_inventory(inventory, as_of=AS_OF)


@pytest.fixture()
def assessed(inventory):
    return ve.assess(inventory, as_of=AS_OF)


# --------------------------------------------------------------------------- #
# The mapper: every row, or the reason it is not a row
# --------------------------------------------------------------------------- #

def test_the_payload_declares_the_input_schema(mapped):
    assert mapped["schema"] == ve.SCHEMA
    assert mapped["payload"]["schema"] == v.INPUT_SCHEMA
    assert mapped["environment"] == "PRODUCTION"


def test_a_vendor_row_becomes_a_vendor_a_product_and_a_release(mapped):
    payload = mapped["payload"]
    assert {"Thales", "F5"} <= {row["name"] for row in payload["vendors"]}
    assert {"payShield 9000", "BIG-IP 9000"} <= {row["name"] for row in payload["products"]}
    releases = {(row["product"], row["version"]) for row in payload["releases"]}
    assert ("payShield 9000", "9.2") in releases
    assert ("BIG-IP 9000", "17.1") in releases


def test_a_release_carries_the_lifecycle_and_pqc_field_the_vendor_row_had(mapped):
    release = next(row for row in mapped["payload"]["releases"]
                   if row["product"] == "payShield 9000")
    assert release["support_status"] == "SUPPORTED"
    assert release["pqc_capability"] == "PQC_READY"


def test_a_vendor_with_no_product_gets_a_vendor_and_no_invented_product(inventory):
    inventory["vendors"] = [{"name": "Advisory Co"}]
    inventory["hardware"] = []
    inventory["vendor_crypto"] = []
    payload = ve.payload_from_inventory(inventory)["payload"]
    assert [row["name"] for row in payload["vendors"]] == ["Advisory Co"]
    assert payload["products"] == []


def test_a_device_maps_to_the_kind_its_flags_and_type_imply(mapped):
    assets = {row["name"]: row for row in mapped["payload"]["assets"]}
    assert assets["HSM-001"]["type"] == "HSM"
    assert assets["LB-001"]["type"] == "LOAD_BALANCER"
    assert assets["SRV-01"]["type"] == "PHYSICAL_SERVER"


def test_a_device_keeps_its_firmware_serial_and_location(mapped):
    asset = next(row for row in mapped["payload"]["assets"] if row["name"] == "HSM-001")
    assert asset["firmware"] == "9.2.1"
    assert asset["serial"] == "SN-001"
    assert asset["location"] == "dc-1"


def test_a_device_with_no_model_is_unmapped_by_name(inventory, mapped):
    assert all(row["name"] != "MYSTERY-01" for row in mapped["payload"]["assets"])
    unmapped = [row for row in mapped["unmapped"] if row["subject"] == "MYSTERY-01"]
    assert unmapped and "no model" in unmapped[0]["reason"]


def test_a_device_with_no_asset_id_is_unmapped(inventory):
    inventory["hardware"] = [{"manufacturer": "Dell", "model": "R760", "firmware": "2.1"}]
    result = ve.payload_from_inventory(inventory)
    assert result["payload"]["assets"] == []
    assert any(row["section"] == "assets" for row in result["unmapped"])


def test_a_declared_capability_becomes_a_cited_release_capability(mapped):
    payload = mapped["payload"]
    assert len(payload["documents"]) == 1
    document = payload["documents"][0]
    assert document["title"] == "payShield 9.2 policy"
    release = next(row for row in payload["releases"] if row["product"] == "payShield 9000")
    assert release["capabilities"][0]["algorithm"] == "AES"
    assert release["capabilities"][0]["documents"] == [document["id"]]


def test_a_capability_with_no_document_is_unmapped_and_not_imported(inventory):
    inventory["vendor_crypto"][0]["source_document"] = ""
    result = ve.payload_from_inventory(inventory)
    release = next(row for row in result["payload"]["releases"]
                   if row["product"] == "payShield 9000")
    assert "capabilities" not in release or not release["capabilities"]
    assert any("VENDOR_CLAIM_WITHOUT_DOCUMENT" in row["reason"]
               for row in result["unmapped"])


def test_a_capability_without_a_release_is_unmapped(inventory):
    inventory["vendor_crypto"][0]["version"] = ""
    result = ve.payload_from_inventory(inventory)
    assert any("needs a vendor, a product, a release and an algorithm" in row["reason"]
               for row in result["unmapped"])


def test_two_declarations_of_one_release_share_it(mapped):
    release = next(row for row in mapped["payload"]["releases"]
                   if row["product"] == "payShield 9000")
    assert [row["product"] for row in mapped["payload"]["releases"]].count("payShield 9000") == 1
    assert release["capabilities"]


def test_a_software_row_becomes_a_package_and_a_coverage_component(mapped):
    payload = mapped["payload"]
    assert {row["coordinate"] for row in payload["packages"]} == {
        "pkg:pypi/cryptography@42.0", "pkg:npm/left-pad@1.3.0"}
    components = {row["coordinate"]: row for row in payload["components"]}
    assert components["pkg:npm/left-pad@1.3.0"]["vendor"] == "UNKNOWN"


def test_a_software_row_with_no_coordinate_is_unmapped(mapped):
    assert any(row["subject"] == "no-coordinate" for row in mapped["unmapped"])


def test_a_business_system_row_is_a_system_and_not_an_application(mapped):
    payload = mapped["payload"]
    assert [row["name"] for row in payload["systems"]] == ["Payments System"]
    assert payload["systems"][0]["criticality"] == "TIER_1"
    assert [row["name"] for row in payload["applications"]] == ["payments-api"]


def test_the_scanned_target_carries_the_packages_the_scan_reported(mapped):
    application = mapped["payload"]["applications"][0]
    assert sorted(application["packages"]) == ["pkg:npm/left-pad@1.3.0",
                                               "pkg:pypi/cryptography@42.0"]


def test_a_static_crypto_finding_is_never_mapped_into_runtime_usage(mapped):
    """The stored findings are static analysis: mapping them as usage would claim runtime."""
    assert mapped["payload"]["usage"] == []
    assert "static analysis" in mapped["not_mapped"]["usage"]


def test_every_section_the_mapper_does_not_read_is_named(mapped):
    assert set(mapped["not_mapped"]) <= set(ve.SECTIONS)
    assert "usage" in mapped["not_mapped"]
    assert mapped["statement"].endswith("unmapped by name")


def test_duplicate_vendor_rows_are_one_vendor(inventory):
    inventory["vendors"] = [
        {"name": "Thales", "product": "payShield 9000", "version": "9.2"},
        {"name": "Thales", "product": "payShield 9000", "version": "9.2"},
    ]
    inventory["hardware"] = []
    payload = ve.payload_from_inventory(inventory)["payload"]
    assert len(payload["vendors"]) == 1
    assert len(payload["products"]) == 1
    assert len(payload["releases"]) == 1


def test_an_empty_inventory_maps_to_an_empty_payload():
    result = ve.payload_from_inventory({})
    assert result["mapped"]["vendors"] == 0
    assert result["statement"].startswith("0 row(s) mapped")
    assert result["payload"]["vendors"] == []


# --------------------------------------------------------------------------- #
# The graph the mapper feeds
# --------------------------------------------------------------------------- #

def test_the_estate_builds_the_levels_its_rows_support(assessed):
    levels = assessed["levels"]
    assert levels["vendor"] == 3  # Thales, F5, Dell
    assert levels["product"] >= 3
    assert levels["asset"] == 3
    assert levels["system"] == 1
    assert levels["runtime"] == 0


def test_the_graph_carries_the_declared_capability_and_no_observation(assessed):
    document = assessed["document"]
    assert any(row["kind"] == "CRYPTO_CAPABILITY" for row in document["assets"])
    assert not any(row["kind"] == "CRYPTO_ASSET" for row in document["assets"])


def test_the_assessment_answers_the_questions_a_graph_can_answer(assessed):
    assert assessed["answers"]
    assert all(row["ok"] for row in assessed["answers"])
    assert {row["question"] for row in assessed["answers"]} == set(ve.DEFAULT_QUESTIONS)


def test_a_question_needing_a_subject_is_not_asked_by_default(assessed):
    asked = {row["question"] for row in assessed["answers"]}
    assert "vendor_products" not in asked
    assert "coverage" in asked


def test_the_assessment_statement_counts_what_was_mapped_and_answered(assessed):
    assert "question(s) answered" in assessed["statement"]
    assert "row(s) mapped" in assessed["statement"]


# --------------------------------------------------------------------------- #
# One answer
# --------------------------------------------------------------------------- #

def test_an_answer_is_the_readers_own(assessed):
    answer = ve.answer(assessed["document"], "vendor_products", vendor="Thales")
    direct = v.vendor_products(assessed["document"], vendor="Thales")
    assert answer["ok"] is True
    assert answer["result"] == direct
    assert answer["statement"] == direct["statement"]


def test_an_unknown_question_is_refused_with_a_code(assessed):
    answer = ve.answer(assessed["document"], "which_vendor_is_worst")
    assert answer["ok"] is False
    assert answer["code"] == "UNKNOWN_QUESTION"


def test_an_unknown_parameter_is_refused_rather_than_dropped(assessed):
    answer = ve.answer(assessed["document"], "vendor_products", vendor="Thales", team="ops")
    assert answer["code"] == "UNKNOWN_PARAMETER"


def test_a_missing_subject_is_refused_before_the_reader_runs(assessed):
    answer = ve.answer(assessed["document"], "vendor_products")
    assert answer["code"] == "MISSING_PARAMETER"
    assert "vendor" in answer["reason"]


def test_a_readers_refusal_survives_as_a_refusal(assessed):
    answer = ve.answer(assessed["document"], "vendor_products", vendor="Nobody")
    assert answer["ok"] is False
    assert answer["code"] == "UNKNOWN_NODE"


def test_the_catalogue_matches_the_module(assessed):
    catalogue = ve.catalogue()
    assert catalogue["count"] == len(ve.ANSWERS)
    assert {row["question"] for row in catalogue["questions"]} == set(ve.ANSWERS)
    for name, (reader, _params) in ve.ANSWERS.items():
        if reader is not None:
            assert getattr(reader, "__module__", "") == v.__name__, name


# --------------------------------------------------------------------------- #
# The summary and the export
# --------------------------------------------------------------------------- #

def test_the_summary_names_the_populated_levels_and_refusals(assessed):
    summary = ve.summary(assessed["document"], as_of=AS_OF)
    assert summary["levels"] == assessed["levels"]
    assert summary["populated_levels"]
    assert "refusal(s)" in summary["statement"]


def test_the_export_carries_only_the_vendor_side(assessed):
    exported = ve.to_cyclonedx(assessed["document"], as_of=AS_OF)
    kinds = {row["properties"][0]["value"] for row in exported["document"]["components"]
             if row["properties"] and row["properties"][0]["name"] == "cryptoscan:kind"}
    assert kinds <= set(ve.EXPORTED_KINDS)
    assert "cryptoscan:kind" in {p["name"] for c in exported["document"]["components"]
                                 for p in c["properties"]}


def test_every_dependency_reference_resolves(assessed):
    exported = ve.to_cyclonedx(assessed["document"], as_of=AS_OF)
    document = exported["document"]
    refs = {row["bom-ref"] for row in document["components"]}
    refs.add(document["metadata"]["component"]["bom-ref"])
    for entry in document["dependencies"]:
        assert entry["ref"] in refs
        assert set(entry["dependsOn"]) <= refs


def test_the_export_timestamp_is_the_documents_not_the_clock(assessed):
    document = ve.to_cyclonedx(assessed["document"], as_of=AS_OF)["document"]
    assert document["metadata"]["timestamp"] == f"{AS_OF}T00:00:00Z"


# --------------------------------------------------------------------------- #
# The API
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from api.config.settings import get_settings

    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/vbom.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def seeded(client):
    """One vendor, one device and one system in the real tables the route reads."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from api.config.settings import get_settings
    from db.models.hardware_live import HardwareAsset
    from db.models.system import System
    from db.models.vendor import Vendor

    url = get_settings().DATABASE_URL
    engine = create_engine(url)
    session = sessionmaker(bind=engine)()
    session.add_all([
        Vendor(name="Thales", vendor_type="HARDWARE", extra_json={"product": "payShield 9000",
                                                                  "version": "9.2"}),
        HardwareAsset(asset_id="HSM-001", manufacturer="Thales", model="payShield 9000",
                      device_type="hsm", firmware="9.2.1", serial_reference="SN-001",
                      hsm=True),
        System(name="Payments System", owner="ops", criticality="TIER_1"),
    ])
    session.commit()
    session.close()
    engine.dispose()
    return client


def _login(client):
    response = client.post("/api/v1/auth/login",
                           json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_the_route_requires_a_session(client):
    assert client.get("/api/v1/vbom/dependency").status_code == 401


def test_the_questions_route_serves_the_catalogue(client):
    response = client.get("/api/v1/vbom/dependency/questions", headers=_login(client))
    assert response.status_code == 200
    assert response.json()["count"] == len(ve.ANSWERS)


def test_the_estate_route_reports_what_it_mapped(seeded):
    headers = _login(seeded)
    response = seeded.get("/api/v1/vbom/dependency", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["mapped"]["vendors"] >= 1
    assert "not_mapped" in body
    assert body["summary"]["levels"]["asset"] >= 1


def test_a_vendor_that_is_not_in_the_estate_is_a_404(seeded):
    response = seeded.get("/api/v1/vbom/dependency/vendors/Nobody", headers=_login(seeded))
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "UNKNOWN_VENDOR"


def test_a_vendor_in_the_estate_answers_with_its_assets(seeded):
    response = seeded.get("/api/v1/vbom/dependency/vendors/Thales", headers=_login(seeded))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["answers"]["vendor_products"]["ok"] is True
    assert body["answers"]["vendor_assets"]["ok"] is True


def test_an_asset_that_is_not_in_the_estate_is_a_404(seeded):
    response = seeded.get("/api/v1/vbom/dependency/assets/NOPE", headers=_login(seeded))
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "UNKNOWN_ASSET"


def test_the_hardware_chain_answers_for_a_seeded_device(seeded):
    response = seeded.get("/api/v1/vbom/dependency/assets/HSM-001", headers=_login(seeded))
    assert response.status_code == 200, response.text
    chain = response.json()["answers"]["hardware_chain"]
    assert chain["ok"] is True
    assert chain["result"]["vendor"] == "Thales"


def test_the_export_route_returns_cyclonedx(seeded):
    response = seeded.get("/api/v1/vbom/dependency/export", headers=_login(seeded))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["document"]["bomFormat"] == "CycloneDX"
    assert body["document"]["specVersion"] == "1.6"
    assert body["components"] >= 1
    assert body["not_proven"]
