"""Promotion: a capability stays a candidate until evidence promotes it."""

from __future__ import annotations

from cbom import promotion as promo

OPENSSL = {"name": "openssl", "version": "3.0.13", "evidence_id": "SBOM-1",
           "algorithms": ["AES-128-GCM", "AES-256-GCM", "RSA-2048", "ECDSA-P256"]}


def _event(klass, algorithm="AES-256-GCM", evidence_id="E-1"):
    return {"class": klass, "evidence_id": evidence_id, "algorithm": algorithm,
            "layer": {"STATIC_OBSERVED": "static", "RUNTIME_OBSERVED": "runtime",
                      "NETWORK_OBSERVED": "network", "CONFIGURED": "config",
                      "IMPORTED": "sbom"}[klass]}


# --------------------------------------------------------------------------- #
# the promotion ladder


def test_a_capability_alone_is_level_capability():
    assert promo.promotion_level(["IMPORTED"]) == "CAPABILITY"
    assert promo.promotion_level(["VENDOR_DECLARED"]) == "CAPABILITY"


def test_static_and_configured_sit_above_capability():
    assert promo.promotion_level(["STATIC_OBSERVED"]) == "STATIC"
    assert promo.promotion_level(["CONFIGURED"]) == "CONFIGURED"
    assert promo.LEVEL_RANK["STATIC"] > promo.LEVEL_RANK["CAPABILITY"]


def test_runtime_and_network_together_are_verified():
    assert promo.promotion_level(["RUNTIME_OBSERVED"]) == "RUNTIME"
    assert promo.promotion_level(["NETWORK_OBSERVED"]) == "NETWORK"
    assert promo.promotion_level(["RUNTIME_OBSERVED", "NETWORK_OBSERVED"]) == "VERIFIED"


def test_the_strongest_class_decides_the_level():
    assert promo.promotion_level(["IMPORTED", "STATIC_OBSERVED", "RUNTIME_OBSERVED"]) == \
        "RUNTIME"


def test_no_evidence_is_no_level():
    assert promo.promotion_level([]) == "NONE"


# --------------------------------------------------------------------------- #
# promote


def test_a_library_with_no_observations_promotes_nothing():
    body = promo.promote([OPENSSL], [])
    assert body["assets"] == []
    assert len(body["candidates"]) == 4
    assert "a capability is not an invocation" in body["statement"]


def test_one_observed_algorithm_is_promoted_and_the_rest_stay_candidates():
    body = promo.promote([OPENSSL], [_event("RUNTIME_OBSERVED", "AES-256-GCM", "RUNTIME-1")])
    assert [asset["algorithm"] for asset in body["assets"]] == ["AES-256-GCM"]
    assert {row["algorithm"] for row in body["candidates"]} == {
        "AES-128-GCM", "RSA-2048", "ECDSA-P256"}
    assert body["levels"] == {"RUNTIME": 1}
    assert "left out of the document" in body["statement"]


def test_a_promoted_asset_carries_its_evidence_and_level():
    body = promo.promote([OPENSSL], [
        _event("RUNTIME_OBSERVED", "AES-256-GCM", "RUNTIME-1"),
        _event("NETWORK_OBSERVED", "AES-256-GCM", "NET-1"),
    ])
    asset = body["assets"][0]
    assert asset["promotion_level"] == "VERIFIED"
    assert set(asset["profile"]["evidence_ids"]) == {"RUNTIME-1", "NET-1"}
    properties = {row["name"]: row["value"] for row in asset["component_document"]["properties"]}
    assert properties["cryptoscan:usage"] == "OBSERVED"
    assert properties["cryptoscan:promotion_level"] == "VERIFIED"
    assert "cryptoscan:evidence_id" in properties


def test_a_component_without_an_evidence_id_is_refused():
    body = promo.promote([{**OPENSSL, "evidence_id": None},
                          {"name": "openssl", "version": "3.0.13",
                           "evidence_id": "SBOM-2", "algorithms": ["AES-128-GCM"]}],
                         [_event("STATIC_OBSERVED", "AES-128-GCM", "S-1")])
    assert [row["component"] for row in body["refused"]] == ["openssl"]
    assert "cannot be attributed" in body["refused"][0]["reason"]
    assert [asset["algorithm"] for asset in body["assets"]] == ["AES-128-GCM"]


def test_a_component_with_no_algorithms_is_refused():
    body = promo.promote([{"name": "openssl", "evidence_id": "SBOM-1"}], [])
    assert body["refused"] and "algorithms it supports" in body["refused"][0]["reason"]


def test_an_imported_event_cannot_promote_an_asset():
    body = promo.promote([OPENSSL], [_event("IMPORTED", "AES-256-GCM", "SBOM-1")])
    assert body["assets"] == []
    assert {row["algorithm"] for row in body["candidates"]} == {
        "AES-128-GCM", "AES-256-GCM", "RSA-2048", "ECDSA-P256"}


def test_evidence_for_another_algorithm_does_not_promote_this_one():
    body = promo.promote([OPENSSL], [_event("RUNTIME_OBSERVED", "RSA-2048", "R-1")])
    assert [asset["algorithm"] for asset in body["assets"]] == ["RSA-2048"]


def test_a_refused_evidence_event_does_not_silently_promote():
    bad = {"class": "RUNTIME_OBSERVED", "algorithm": "AES-256-GCM"}  # no evidence id
    body = promo.promote([OPENSSL], [bad])
    assert body["assets"] == []


# --------------------------------------------------------------------------- #
# the document


def _document(**kwargs):
    body = promo.promote([OPENSSL], [
        _event("RUNTIME_OBSERVED", "AES-256-GCM", "RUNTIME-1"),
        _event("STATIC_OBSERVED", "ECDSA-P256", "S-1"),
    ], **kwargs)
    return promo.to_cbom(body, name="payments-api"), body


def test_the_document_holds_only_promoted_assets():
    document, body = _document()
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.5"
    assert {component["name"] for component in document["components"]} == {
        "AES-256-GCM", "ECDSA-P256"}
    assert len(body["candidates"]) == 2


def test_candidates_are_counted_in_metadata_not_written_as_components():
    document, _ = _document()
    properties = {row["name"]: row["value"] for row in document["metadata"]["properties"]}
    assert properties["cryptoscan:promoted_assets"] == "2"
    assert properties["cryptoscan:candidates_excluded"] == "2"


def test_a_component_is_a_cyclonedx_cryptographic_asset():
    document, _ = _document()
    component = next(row for row in document["components"] if row["name"] == "AES-256-GCM")
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    assert component["bom-ref"].startswith("crypto/algorithm/")


def test_platform_claims_live_in_properties_not_in_the_standard_fields():
    document, _ = _document()
    component = document["components"][0]
    assert set(component["cryptoProperties"]) <= {"assetType", "oid", "primitive",
                                                  "algorithmProperties"}
    assert all(row["name"].startswith("cryptoscan:") for row in component["properties"])


def test_the_primitive_and_oid_become_standard_fields():
    body = promo.promote([OPENSSL], [_event("RUNTIME_OBSERVED", "AES-256-GCM", "R-1")],
                         primitives={"AES-256-GCM": "aead"},
                         oids={"AES-256-GCM": "2.16.840.1.101.3.4.1.46"})
    component = body["assets"][0]["component_document"]
    assert component["cryptoProperties"]["primitive"] == "aead"
    assert component["cryptoProperties"]["oid"] == "2.16.840.1.101.3.4.1.46"
    assert component["cryptoProperties"]["algorithmProperties"]["cryptoFunction"] == [
        "encrypt", "decrypt"]


def test_parameters_travel_into_algorithm_properties():
    body = promo.promote([OPENSSL],
                         [{"class": "RUNTIME_OBSERVED", "evidence_id": "R-1",
                           "algorithm": "AES-256-GCM",
                           "parameters": {"key_size": 256, "mode": "GCM"}}])
    properties = body["assets"][0]["component_document"]["cryptoProperties"][
        "algorithmProperties"]
    assert properties["parameterSetIdentifier"] == "256" and properties["mode"] == "GCM"


def test_the_inventory_says_what_the_document_may_be_read_as():
    _, body = _document()
    inventory = promo.asset_inventory(body)
    assert inventory["algorithms"] == {"AES-256-GCM": ["RUNTIME"],
                                       "ECDSA-P256": ["STATIC"]}
    assert inventory["candidates"] == 2
    assert "not in it" in inventory["statement"]


def test_an_empty_promotion_produces_an_empty_document_not_an_error():
    body = promo.promote([], [])
    document = promo.to_cbom(body)
    assert document["components"] == []
    assert promo.asset_inventory(body)["algorithms"] == {}
