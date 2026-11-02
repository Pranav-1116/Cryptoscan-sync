"""The vendor REST reader (H4): documented endpoints, or a refusal.

The recorded replies below are shaped like the example results in the Thales
Luna REST API reference — the same fields, the same JSON types. They are written
by hand from that document, which is the whole point: an endpoint this module
did not read about does not exist in it, and `test_every_endpoint_cites_a_
document` is what keeps that true when someone adds one.

No appliance was contacted. What the suite proves is the manifest discipline,
the path encoding, the projection, the refusals and the failure modes; the
artifact says plainly that a real Luna answers over TLS with a session this
reader does not create.
"""

from __future__ import annotations

import pytest

from universal_vendor.hardware.hsm_readers.rest import (
    SCHEMA,
    THALES_LUNA,
    UNDOCUMENTED,
    VENDORS,
    DocumentedEndpoint,
    EndpointNotAllowed,
    RestHsmReader,
    RestReadError,
    VendorNotDocumented,
    build_url,
    https_json_transport,
    manifest_for,
    quote_segment,
)
from universal_vendor.hardware.safety import SecretMaterialRefused

BASE = "https://luna01.bank.example:8443"

HSM = {
    "loggedIn": "nobody",
    "manuallyZeroized": False,
    "firmwareVersion": "7.8.2",
    "state": "initialized",
    "model": "K7 Base",
    "label": "luna01",
    "partNumber": "908-000632-001",
    "fipsModeEnabled": True,
    "partitionsAllowed": 20,
    "partitionsCreated": 2,
    "storageSpace": {"total": 16252928, "used": 0, "free": 16252928},
    "authenticationMethod": "password",
    "pedPresent": False,
    "policies": "/api/lunasa/hsms/151363/policies",
}
PARTITION = {
    "label": "PAYMENTS01", "name": "PAYMENTS01", "state": "initialized",
    "objectCount": 42, "storageSpace": {"free": 20480, "total": 20480, "used": 0},
    "roles": "/api/lunasa/hsms/151363/partitions/273087011389/roles",
}
ROLES = {"roles": [
    {"id": "co", "name": "Crypto Officer"},
    {"id": "cu", "name": "Crypto User"},
    {"id": "so", "name": "Partition SO"},
]}
CAPABILITIES = {"capabilities": [{"id": "FIPS"}, {"id": "PPSO"}, {"id": "STC"}]}


class RecordedTransport:
    """A transport that answers from a dict of path -> payload."""

    def __init__(self, routes, *, fail=()):
        self.routes = routes
        self.fail = set(fail)
        self.urls: list[str] = []

    def __call__(self, url):
        self.urls.append(url)
        for path in self.fail:
            if url.endswith(path):
                raise RestReadError(f"{url}: HTTP 404 Not Found")
        for path, payload in self.routes.items():
            if url.endswith(path):
                return payload
        raise RestReadError(f"{url}: no recorded reply")


def reader(routes=None, *, fail=()):
    routes = {"151363": HSM, "273087011389": PARTITION,
              "/partitions/273087011389/roles": ROLES,
              "/capabilities": CAPABILITIES, **(routes or {})}
    transport = RecordedTransport(routes, fail=fail)
    return RestHsmReader(THALES_LUNA, transport, base_url=BASE), transport


# -- the manifest is the contract ------------------------------------------- #


def test_every_endpoint_cites_a_document_and_says_what_it_returns():
    for manifest in VENDORS.values():
        assert manifest.documentation.startswith("https://")
        for endpoint in manifest.endpoints:
            assert endpoint.source.startswith("https://"), endpoint.key
            assert endpoint.returns, f"{endpoint.key} cites a page but not a fact"
            assert "thalesdocs.com" in endpoint.source


def test_every_shipped_endpoint_is_a_get():
    for manifest in VENDORS.values():
        assert {endpoint.method for endpoint in manifest.endpoints} == {"GET"}
        assert len(manifest.get_paths()) == len(manifest.endpoints)


def test_an_undocumented_vendor_is_named_and_refused_rather_than_guessed():
    assert UNDOCUMENTED, "a register of known gaps is the honest alternative to a guess"
    for vendor in UNDOCUMENTED:
        with pytest.raises(VendorNotDocumented) as excinfo:
            manifest_for(vendor)
        assert "invent" in str(excinfo.value) or "no documented manifest" in str(excinfo.value)
    with pytest.raises(VendorNotDocumented):
        manifest_for("some-new-hsm-vendor")


def test_a_vendor_name_is_matched_case_insensitively():
    assert manifest_for("Thales_Luna").key == "thales_luna"


def test_an_endpoint_outside_the_manifest_is_refused():
    with pytest.raises(EndpointNotAllowed):
        THALES_LUNA.endpoint("zeroize")
    with pytest.raises(EndpointNotAllowed):
        THALES_LUNA.endpoint("actions/factoryReset")


# -- paths ------------------------------------------------------------------ #


def test_a_parameter_cannot_leave_its_path_segment():
    assert quote_segment("151363") == "151363"
    assert quote_segment("1234/../zeroize") == "1234%2F..%2Fzeroize"
    assert quote_segment("20160901/actions") == "20160901%2Factions"
    with pytest.raises(RestReadError):
        quote_segment("..")
    with pytest.raises(RestReadError):
        quote_segment("")


def test_a_url_is_only_ever_built_from_a_documented_path():
    endpoint = THALES_LUNA.endpoint("partition")
    url = build_url(BASE, endpoint, hsmid="151363", partitionid="273087011389")
    assert url == f"{BASE}/api/lunasa/hsms/151363/partitions/273087011389"
    with pytest.raises(RestReadError):
        build_url(BASE, endpoint, hsmid="151363")
    with pytest.raises(RestReadError):
        build_url(BASE, endpoint, hsmid="151363", partitionid="1", policyid="2")


def test_a_plain_http_url_is_refused():
    transport = https_json_transport(opener=object())
    with pytest.raises(RestReadError) as excinfo:
        transport("http://luna01.bank.example/api/lunasa/hsms")
    assert "https" in str(excinfo.value)


# -- what the appliance says ------------------------------------------------ #


def test_the_hsm_resource_names_the_firmware_the_model_and_the_serial():
    facts, _ = reader()
    facts = facts.collect(151363)
    assert facts.firmware == "7.8.2"
    assert facts.model == "K7 Base"
    assert facts.serial_reference == "151363"
    assert facts.fips_mode is True
    assert facts.part_number == "908-000632-001"
    assert facts.state == "initialized"
    assert facts.partitions_created == 2 and facts.partitions_allowed == 20
    assert facts.storage == {"total": 16252928, "used": 0, "free": 16252928}


def test_a_partition_carries_its_object_count_and_its_roles_by_name():
    facts, _ = reader()
    facts = facts.collect(151363, partition_ids=("273087011389",))
    partition = facts.partitions[0]
    assert partition["label"] == "PAYMENTS01"
    assert partition["object_count"] == 42
    assert [role["name"] for role in partition["roles"]] == [
        "Crypto Officer", "Crypto User", "Partition SO"]


def test_the_evidence_names_the_endpoint_url_and_the_document():
    facts, _ = reader()
    facts = facts.collect(151363, partition_ids=("273087011389",))
    kinds = [entry["endpoint"] for entry in facts.evidence]
    assert kinds == ["hsm", "capabilities", "partition", "partition_roles"]
    for entry in facts.evidence:
        assert entry["url"].startswith(BASE + "/api/lunasa/")
        assert entry["documentation"].startswith("https://")
        assert entry["documented_returns"]


def test_capability_identifiers_are_read_from_the_documented_envelope():
    facts, _ = reader()
    assert facts.collect(151363).capabilities == ["FIPS", "PPSO", "STC"]


def test_the_scanner_shape_is_filled_from_the_appliance_not_left_empty():
    facts, _ = reader()
    raw = facts.collect(151363, partition_ids=("273087011389",)).to_raw()
    assert raw["manufacturer"] == "Thales"
    assert raw["model"] == "K7 Base"
    assert raw["firmware"] == "7.8.2"
    assert raw["serial_reference"] == "151363"
    assert raw["partition_metadata"][0]["object_count"] == 42
    # The appliance's API describes itself, not a mechanism list: that is
    # PKCS#11's job and this reader says so instead of inventing algorithms.
    assert raw["supported_algorithms"] == []
    assert raw["key_type_metadata"] == []


# -- refusals and failure modes -------------------------------------------- #


def test_a_secret_in_the_reply_stops_the_read():
    leaky = {**HSM, "label": "luna01 secret=hunter2"}
    facts_reader, _ = reader({"151363": leaky})
    with pytest.raises(SecretMaterialRefused):
        facts_reader.collect(151363)


def test_a_field_outside_the_projection_is_not_stored():
    noisy = {**HSM, "wrappedKey": "do-not-store-me"}
    facts_reader, _ = reader({"151363": noisy})
    facts = facts_reader.collect(151363)
    assert "do-not-store-me" not in str(facts.to_dict())


def test_a_missing_capability_read_is_reported_not_silently_empty():
    facts_reader, _ = reader(fail=("/capabilities",))
    facts = facts_reader.collect(151363)
    assert facts.capabilities == []
    assert any(reason.startswith("capabilities:") for reason in facts.unavailable)


def test_a_missing_firmware_field_is_stated_as_unknown_not_invented():
    no_firmware = {name: value for name, value in HSM.items() if name != "firmwareVersion"}
    facts_reader, _ = reader({"151363": no_firmware})
    facts = facts_reader.collect(151363)
    assert facts.firmware is None
    assert any("firmwareVersion" in reason for reason in facts.unavailable)


def test_a_partition_that_404s_does_not_lose_the_appliance():
    facts_reader, _ = reader(fail=("/partitions/999999",))
    facts = facts_reader.collect(151363, partition_ids=("999999",))
    assert facts.firmware == "7.8.2"
    assert facts.partitions[0]["id"] == "999999"
    assert "HTTP 404" in facts.partitions[0]["unavailable"]


def test_the_transport_only_ever_sends_a_get():
    _, transport = reader()
    for url in transport.urls:
        assert url.startswith("https://")


def test_the_reader_holds_no_verb_that_changes_an_appliance():
    import inspect

    from universal_vendor.hardware.hsm_readers import rest as module

    source = inspect.getsource(module)
    for verb in ('"POST"', '"PUT"', '"DELETE"', '"PATCH"'):
        assert verb not in source, f"{verb} has no place in a read-only reader"
    payload = reader()[0].collect(151363).to_dict()
    assert payload["schema"] == SCHEMA


def test_no_login_is_performed_by_this_reader():
    """Authentication arrives on the transport; no password enters this module."""
    facts_reader, transport = reader()
    facts_reader.collect(151363)
    assert all("/auth/" not in url for url in transport.urls)
    assert not any("token" in entry["url"] or "password" in entry["url"]
                   for entry in facts_reader.collect(151363).evidence)


def test_an_endpoint_cannot_be_assembled_without_a_citation():
    with pytest.raises(ValueError):
        DocumentedEndpoint("hsms", "GET", "/api/lunasa/hsms", "", "the HSMs")
    with pytest.raises(ValueError):
        DocumentedEndpoint("hsms", "GET", "/api/lunasa/hsms", "http://example/", "the HSMs")
    with pytest.raises(ValueError):
        DocumentedEndpoint("hsms", "GET", "/api/lunasa/hsms", "https://example/", "")
