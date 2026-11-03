"""The VBOM surface: the catalogue, the envelope, the export and the live merge.

The dependency module answers; this module is how the answers are asked for. So the tests
here are about the *surface* behaving — a question not in the catalogue being unaskable, a
refusal staying a refusal, an export failing its own schema rather than shipping, and a live
collector's row joining the estate without overwriting what procurement said.

The graph itself is tested in ``test_vbom_dependency.py``; these tests use a smaller payload
and care about the plumbing.
"""

from __future__ import annotations

import copy

import pytest
from cbom import sbom_collectors as collectors
from cbom import techbom as tb
from cbom import vbom_dependency as v
from cbom import vbom_surface as vs

AS_OF = "2026-11-03"

PAYLOAD = {
    "as_of": AS_OF,
    "documents": [
        {"id": "DOC-1", "title": "payShield 9.2 notes", "vendor": "Thales",
         "product": "payShield 9000", "version": "9.2", "received_at": "2026-10-01",
         "valid_until": "2027-10-01", "reviewer": "s.iyer", "revision": 1},
        {"id": "DOC-2", "title": "OpenSSL 3.0.13", "vendor": "OpenSSL Project",
         "product": "OpenSSL", "version": "3.0.13", "received_at": "2026-09-15",
         "valid_until": "2027-09-15", "reviewer": "r.nair", "revision": 2},
    ],
    "vendors": [
        {"name": "Thales", "lifecycle": "ACTIVE", "risk_level": "HIGH"},
        {"name": "OpenSSL Project", "lifecycle": "ACTIVE", "risk_level": "MEDIUM"},
    ],
    "products": [
        {"name": "payShield 9000", "vendor": "Thales", "family": "payShield", "type": "HSM",
         "lifecycle": "SUPPORTED"},
        {"name": "OpenSSL", "vendor": "OpenSSL Project", "type": "LIBRARY",
         "lifecycle": "SUPPORTED", "documents": ["DOC-2"]},
    ],
    "releases": [
        {"product": "payShield 9000", "version": "9.2", "support_status": "SUPPORTED",
         "documents": ["DOC-1"],
         "capabilities": [{"algorithm": "AES", "key_size": 256, "mode": "GCM",
                           "documents": ["DOC-1"]}]},
        {"product": "OpenSSL", "version": "3.0.13", "pqc_capability": "DECLARED",
         "documents": ["DOC-2"],
         "packages": [{"coordinate": "pkg:generic/openssl", "version": "3.0.13"}],
         "capabilities": [{"algorithm": "ML-KEM", "key_size": 768,
                           "documents": ["DOC-2"]}]},
    ],
    "assets": [
        {"name": "HSM-001", "type": "HSM", "product": "payShield 9000", "vendor": "Thales",
         "firmware": "9.2.1", "location": "dc-1", "owner": "payments", "serial": "SN-1"},
        {"name": "LB-001", "type": "LOAD_BALANCER", "product": "OpenSSL",
         "vendor": "OpenSSL Project", "firmware": "3.0.13", "location": "dc-2"},
    ],
    "applications": [
        {"name": "Payments API", "system": "Payments System", "criticality": "TIER_1",
         "assets": ["LB-001"], "packages": ["pkg:generic/openssl"]},
    ],
    "usage": [
        {"application": "Payments API", "process": "java", "algorithm": "AES",
         "key_size": 256, "mode": "GCM", "operation": "encrypt", "host": "HSM-001",
         "observed_at": "2026-10-30T10:00:00Z"},
    ],
    "components": [
        {"coordinate": "pkg:generic/openssl", "vendor": "OpenSSL Project"},
        {"coordinate": "pkg:generic/newlib", "vendor": "UNKNOWN"},
        {"coordinate": "pkg:generic/payments-core", "vendor": "INTERNAL"},
    ],
    "sboms": [
        {"id": "SBOM-1", "product": "OpenSSL", "version": "3.0.13",
         "components": [{"coordinate": "pkg:generic/openssl", "version": "3.0.13"}]},
    ],
}

DIGEST = "sha256:" + "a" * 64

REGISTRY = {
    "transport": "registry",
    "image": {"repository": "payments-api", "tag": "4.2.1", "digest": DIGEST},
    "layers": [{"digest": "sha256:" + "b" * 64, "size": 42}],
}

SCAN = {
    "transport": "scan",
    "image": {"name": "payments-api", "tag": "4.2.1", "digest": DIGEST},
    "packages": [{"coordinate": "pkg:generic/newlib", "version": "1.2.3", "crypto": True}],
}


@pytest.fixture(scope="module")
def built():
    return v.build(PAYLOAD, as_of=AS_OF, estate_id="vbom:test")


@pytest.fixture(scope="module")
def bom(built):
    return built["bom"]


@pytest.fixture()
def payload():
    return copy.deepcopy(PAYLOAD)


# --------------------------------------------------------------------------- #
# The catalogue
# --------------------------------------------------------------------------- #

def test_the_catalogue_covers_every_public_reader():
    """No question exists that the surface cannot ask — that is the point of the catalogue."""
    names = {name for name in dir(v) if not name.startswith("_")}
    readers = {name for name in names if callable(getattr(v, name))
               and getattr(getattr(v, name), "__module__", "") == v.__name__}
    unaskable = readers - set(vs.QUESTIONS)
    assert unaskable == set(vs.NOT_QUESTIONS)
    assert all(hasattr(v, name) for name in vs.NOT_QUESTIONS)


def test_every_question_has_a_statement_and_a_section():
    for name, entry in vs.QUESTIONS.items():
        assert entry["statement"].strip(), name
        assert entry["section"].strip(), name


def test_required_parameters_are_read_from_the_reader_signature():
    catalogue = {row["question"]: row for row in vs.catalogue()["questions"]}
    assert catalogue["vendor_products"]["required"] == ["vendor"]
    assert catalogue["product_releases"]["required"] == ["product"]
    assert catalogue["twin"]["required"] == []
    assert catalogue["applicability"]["required"] == ["declaration", "deployment"]


def test_the_catalogue_is_ordered_and_counted(bom):
    body = vs.catalogue()
    assert body["schema"] == vs.SCHEMA
    assert body["count"] == len(vs.QUESTIONS) == 29
    assert [row["question"] for row in body["questions"]] == list(vs.QUESTIONS)
    assert "29 question(s)" in body["statement"]


def test_the_default_question_set_excludes_questions_needing_a_subject():
    assert "coverage" in vs.DEFAULT_QUESTIONS
    assert "software_chain" not in vs.DEFAULT_QUESTIONS
    assert "vendor_products" not in vs.DEFAULT_QUESTIONS


# --------------------------------------------------------------------------- #
# The envelope
# --------------------------------------------------------------------------- #

def test_a_question_is_answered_with_the_reader_result(bom):
    answer = vs.ask(bom, "vendor_products", vendor="Thales")
    direct = v.vendor_products(bom, vendor="Thales")
    assert answer["ok"] is True
    assert answer["schema"] == vs.ANSWER_SCHEMA
    assert answer["result"] == direct
    assert answer["statement"] == direct["statement"]


def test_an_unknown_question_is_refused_not_approximated(bom):
    answer = vs.ask(bom, "which_vendor_is_worst")
    assert answer["ok"] is False
    assert answer["code"] == "UNKNOWN_QUESTION"
    assert "29" in answer["reason"]


def test_an_unknown_parameter_is_refused(bom):
    answer = vs.ask(bom, "vendor_products", vendor="Thales", team="payments")
    assert answer["code"] == "UNKNOWN_PARAMETER"
    assert "team" in answer["reason"]


def test_a_missing_required_parameter_is_refused(bom):
    answer = vs.ask(bom, "product_releases")
    assert answer["code"] == "MISSING_PARAMETER"
    assert answer["result"] is None


def test_a_reader_refusal_stays_a_refusal(bom):
    """The graph saying "no such vendor" is an answer of the surface, not a 500."""
    answer = vs.ask(bom, "vendor_products", vendor="Nobody")
    assert answer["ok"] is False
    assert answer["code"] == "UNKNOWN_NODE"
    assert "Nobody" in answer["reason"]
    assert answer["params"] == {"vendor": "Nobody"}


def test_a_payload_question_needs_no_graph(payload):
    answer = vs.ask({}, "coverage", payload=payload)
    assert answer["ok"] is True
    assert answer["result"]["total"] > 0


def test_a_question_that_needs_a_subject_refuses_by_its_own_code(bom):
    answer = vs.ask(bom, "software_chain")
    assert answer["ok"] is False
    assert answer["code"] == "NO_QUERY"


# --------------------------------------------------------------------------- #
# An assessment
# --------------------------------------------------------------------------- #

def test_an_assessment_carries_the_graph_the_document_and_the_answers(payload):
    result = vs.assess(payload, as_of=AS_OF,
                       questions=["coverage", "twin", "version_conflicts"])
    assert result["schema"] == vs.SCHEMA
    assert result["document"]["schema"] == tb.SCHEMA
    assert result["graph"]["bom"] is None
    assert [answer["question"] for answer in result["answers"]] == [
        "coverage", "twin", "version_conflicts"]
    assert result["statement"].endswith("3 question(s) answered, 0 refused")


def test_an_assessment_with_no_questions_answers_none(payload):
    result = vs.assess(payload, as_of=AS_OF, questions=[])
    assert result["answers"] == []


def test_the_default_assessment_answers_the_questions_a_graph_can_answer(payload):
    result = vs.assess(payload, as_of=AS_OF)
    assert len(result["answers"]) == len(vs.DEFAULT_QUESTIONS)
    assert all(answer["ok"] for answer in result["answers"])


def test_a_given_parameter_reaches_the_reader(payload):
    result = vs.assess(payload, as_of=AS_OF, questions=["vendor_products"],
                       given={"vendor_products": {"vendor": "OpenSSL Project"}})
    assert result["answers"][0]["result"]["vendor"] == "OpenSSL Project"


def test_a_refused_question_is_named_in_the_statement(payload):
    result = vs.assess(payload, as_of=AS_OF, questions=["vendor_products"])
    assert result["refused"]
    assert "refused" in result["statement"]
    assert "vendor_products" in result["statement"]


# --------------------------------------------------------------------------- #
# The live merge
# --------------------------------------------------------------------------- #

def test_a_live_collector_joins_the_estate(payload):
    result = vs.assess(payload, live=[REGISTRY], as_of=AS_OF, questions=[])
    assert result["live"]["transports"] == ["registry"]
    assert result["live"]["rows"] > 0
    packages = {row["name"] for row in result["document"]["assets"]
                if row["kind"] == "PACKAGE"}
    assert "pkg:generic/openssl" in packages


def test_live_rows_never_overwrite_the_vendor_payload(payload):
    before = {row["key"] for row in v.build(payload, as_of=AS_OF)["bom"]["assets"]}
    after = vs.assess(payload, live=[REGISTRY], as_of=AS_OF, questions=[])
    vendors = {row["name"] for row in after["document"]["assets"] if row["kind"] == "VENDOR"}
    assert vendors == {"Thales", "OpenSSL Project"}
    assert before <= {row["key"] for row in after["document"]["assets"]}


def test_the_merge_deduplicates_by_coordinate(payload):
    """A package the payload already names is not added twice because a scan saw it."""
    merged = vs._fold_live(payload, collectors.collect(
        collectors.from_image_scan(SCAN, collected_at=AS_OF), as_of=AS_OF)["inventory"])
    coordinates = [row["coordinate"] for row in merged["packages"]]
    assert len(coordinates) == len(set(coordinates))
    assert "pkg:generic/openssl" not in coordinates  # the release already names it
    assert "pkg:generic/newlib" in coordinates


def test_the_merge_keeps_the_payloads_own_usage_rows(payload):
    merged = vs._fold_live(payload, {"software": [], "crypto": [], "applications": []})
    assert merged["usage"] == payload["usage"]


# --------------------------------------------------------------------------- #
# The CycloneDX export
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def export(built):
    return vs.to_cyclonedx(built["bom"], as_of=AS_OF,
                           applicability=v.declaration_applicability(built["bom"],
                                                                     as_of=AS_OF))


def test_the_export_is_valid_cyclonedx(export):
    assert export["validation"]["ok"], export["validation"]["errors"]
    assert export["document"]["specVersion"] == "1.6"
    assert export["document"]["metadata"]["timestamp"] == f"{AS_OF}T00:00:00Z"


def test_every_component_type_is_in_the_formats_vocabulary(export):
    allowed = {"application", "framework", "library", "container", "platform",
               "operating-system", "device", "device-driver", "firmware", "file",
               "machine-learning-model", "data", "cryptographic-asset"}

    def walk(components):
        for component in components:
            yield component
            yield from walk(component.get("components", []))

    kinds = {component["type"] for component in walk(export["document"]["components"])}
    assert kinds
    assert kinds <= allowed


def test_a_vendor_is_a_supplier_and_not_a_component(export):
    names = {component["name"] for component in export["document"]["components"]}
    assert "Thales" not in names
    suppliers = {component.get("supplier", {}).get("name")
                 for component in export["document"]["components"]}
    assert "Thales" in suppliers
    metadata = export["document"]["metadata"]["component"]["properties"]
    assert {"name": "cryptoscan:vendor", "value": "Thales"} in metadata


def test_a_release_is_nested_in_its_product(export):
    products = {component["name"]: component
                for component in export["document"]["components"]}
    releases = products["payShield 9000"].get("components", [])
    assert [component["name"] for component in releases] == ["payShield 9000@9.2"]
    assert releases[0]["version"] == "9.2"


def test_a_package_is_nested_in_its_release(export):
    def find(components, name):
        for component in components:
            if component["name"] == name:
                return component
            found = find(component.get("components", []), name)
            if found:
                return found
        return None

    release = find(export["document"]["components"], "OpenSSL@3.0.13")
    assert [child["name"] for child in release["components"]] == ["pkg:generic/openssl"]


def test_only_real_needs_become_dependencies(export):
    entries = export["document"]["dependencies"]
    assert entries
    kinds = {entry["ref"].split(":", 1)[0] for entry in entries}
    assert kinds <= {"device", "application", "hsm", "load_balancer", "vendor_product",
                     "product_version", "firmware", "package", "business_system"}
    refs = collect_refs(export["document"])
    for entry in entries:
        assert entry["ref"] in refs
        assert set(entry["dependsOn"]) <= refs


def collect_refs(document):
    refs = set()

    def walk(components):
        for component in components:
            refs.add(component["bom-ref"])
            walk(component.get("components", []))

    walk(document["components"])
    refs.add(document["metadata"]["component"]["bom-ref"])
    return refs


def test_the_basis_of_every_link_is_in_the_document(export):
    properties = [row for component in export["document"]["components"]
                  for row in component["properties"]]
    basis = [row for row in properties if row["name"] == "cryptoscan:supplier_basis"]
    assert basis and all(row["value"] for row in basis)
    relations = [row["value"] for row in properties if row["name"] == "cryptoscan:relation"]
    assert relations and all("via" in value for value in relations)


def test_the_applicability_state_travels_with_the_component(built):
    applicability = v.declaration_applicability(built["bom"], as_of=AS_OF)
    export = vs.to_cyclonedx(built["bom"], as_of=AS_OF, applicability=applicability)
    states = {row["value"] for component in export["document"]["components"]
              for row in component["properties"]
              if row["name"] == "cryptoscan:applicability"}
    assert states
    assert states <= set(v.APPLICABILITY)
    assert len(states) > 1


def test_the_export_is_deterministic(built):
    first = vs.to_cyclonedx(built["bom"], as_of=AS_OF)
    second = vs.to_cyclonedx(built["bom"], as_of=AS_OF)
    assert first["document"] == second["document"]
    assert first["statement"] == second["statement"]


def test_an_empty_estate_still_exports_a_valid_document():
    empty = v.build({"as_of": AS_OF}, as_of=AS_OF)
    export = vs.to_cyclonedx(empty["bom"], as_of=AS_OF)
    assert export["validation"]["ok"]
    assert export["components"] == 0
    assert export["document"]["dependencies"] == []


def test_the_export_says_what_it_left_out(export):
    assert "supplier(s)" in export["statement"]
    assert "INVALID" not in export["statement"]
    assert "a vendor is a supplier" in export["rule"]


# --------------------------------------------------------------------------- #
# The summary
# --------------------------------------------------------------------------- #

def test_the_summary_counts_levels_and_refusals(built):
    body = vs.summary(built["bom"])
    assert body["levels"] == v.levels(built["bom"])
    assert body["refusals"] >= 1
    assert "refusal(s)" in body["statement"]


def test_the_summary_counts_the_builders_refusals_too(built):
    """A row the builder could not place is not in the document, and must still be counted."""
    body = vs.summary(built["bom"], refusals=[{"code": "ASSET_WITHOUT_PRODUCT",
                                               "subject": "UNMAPPED-HSM"}])
    assert "ASSET_WITHOUT_PRODUCT" in body["refusal_codes"]
    assert "UNMAPPED-HSM" in body["unresolved"]


def test_the_summary_de_duplicates_a_refusal_reported_twice():
    empty = v.build({"as_of": AS_OF}, as_of=AS_OF)
    refusal = {"code": "NO_NAME", "subject": "HOST"}
    body = vs.summary(empty["bom"], refusals=[refusal, refusal])
    assert body["refusals"] == 1


def test_the_summary_reports_applicability_states(bom):
    body = vs.summary(bom)
    assert body["applicability"] == v.declaration_applicability(bom,
                                                                as_of=AS_OF)["states"]


def test_a_summary_of_an_empty_estate_says_so():
    body = vs.summary(v.build({"as_of": AS_OF}, as_of=AS_OF)["bom"])
    assert not any(body["levels"].values())
    assert "no declaration reaches a deployment" in body["statement"]


# --------------------------------------------------------------------------- #
# The API surface
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


def _login(client):
    response = client.post("/api/v1/auth/login",
                           json={"username": "admin", "password": "cryptoscan"})
    return {"Authorization": f"Bearer {response.json()['token']}"}


def test_the_surface_requires_a_session(client):
    assert client.get("/api/v1/cbom/vbom/questions").status_code == 401
    assert client.post("/api/v1/cbom/vbom/assess",
                       json={"payload": PAYLOAD}).status_code == 401


def test_the_catalogue_is_served(client):
    response = client.get("/api/v1/cbom/vbom/questions", headers=_login(client))
    assert response.status_code == 200
    assert response.json()["count"] == 29


def test_an_assessment_is_served_over_http(client):
    response = client.post("/api/v1/cbom/vbom/assess",
                           headers=_login(client),
                           json={"payload": PAYLOAD, "questions": ["coverage", "twin"],
                                 "as_of": AS_OF})
    assert response.status_code == 200
    body = response.json()
    assert [answer["question"] for answer in body["answers"]] == ["coverage", "twin"]
    assert body["graph"]["levels"]


def test_one_question_is_served_over_http(client):
    response = client.post("/api/v1/cbom/vbom/answer/vendor_products",
                           headers=_login(client),
                           json={"payload": PAYLOAD, "params": {"vendor": "Thales"},
                                 "as_of": AS_OF})
    assert response.status_code == 200
    assert response.json()["result"]["vendor"] == "Thales"


def test_an_unknown_question_is_a_404(client):
    response = client.post("/api/v1/cbom/vbom/answer/worst_vendor",
                           headers=_login(client),
                           json={"payload": PAYLOAD, "as_of": AS_OF})
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "UNKNOWN_QUESTION"


def test_a_missing_parameter_is_a_422(client):
    response = client.post("/api/v1/cbom/vbom/answer/vendor_products",
                           headers=_login(client),
                           json={"payload": PAYLOAD, "as_of": AS_OF})
    assert response.status_code == 422
    assert response.json()["detail"]["required"] == ["vendor"]


def test_a_request_without_a_payload_is_a_422(client):
    response = client.post("/api/v1/cbom/vbom/assess", headers=_login(client), json={})
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "PAYLOAD_REQUIRED"


def test_a_payload_from_another_schema_is_a_422(client):
    response = client.post("/api/v1/cbom/vbom/assess", headers=_login(client),
                           json={"payload": {"schema": "cryptoscan.cbom-input/1"}})
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "UNKNOWN_PAYLOAD_SCHEMA"


def test_the_export_endpoint_returns_a_validated_document(client):
    response = client.post("/api/v1/cbom/vbom/export/cyclonedx",
                           headers=_login(client),
                           json={"payload": PAYLOAD, "as_of": AS_OF})
    assert response.status_code == 200
    assert response.json()["validation"]["ok"] is True


def test_the_summary_endpoint_serves_the_three_numbers(client):
    response = client.post("/api/v1/cbom/vbom/summary", headers=_login(client),
                           json={"payload": PAYLOAD, "as_of": AS_OF})
    assert response.status_code == 200
    assert "levels" in response.json()


def test_a_refused_answer_over_http_is_still_200(client):
    response = client.post("/api/v1/cbom/vbom/answer/vendor_products",
                           headers=_login(client),
                           json={"payload": PAYLOAD, "params": {"vendor": "Nobody"},
                                 "as_of": AS_OF})
    assert response.status_code == 200
    assert response.json()["code"] == "UNKNOWN_NODE"


def test_the_refusal_vocabulary_is_the_modules(built):
    """The surface does not invent refusals: every code it can return comes from the module."""
    refused = vs.ask(built["bom"], "software_chain")
    assert refused["code"] == "NO_QUERY"
    assert refused["code"] not in vs.SURFACE_CODES
    assert vs.SURFACE_CODES == {"UNKNOWN_QUESTION", "UNKNOWN_PARAMETER", "MISSING_PARAMETER"}
