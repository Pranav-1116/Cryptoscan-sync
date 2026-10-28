"""HSM *usage* over KMIP (spec 67 §17; spec 93 §13).

Three claims this file holds the module to:

* **read-only** — ``Locate`` and ``GetAttributes`` only; the ``Get`` operation,
  which returns key material, is never issued from here;
* **capability is not use** — a Pre-Active AES-256 key is ``SUPPORTED``; only the
  appliance's own usage counter above zero earns ``OBSERVED``;
* **a refusal is not an empty HSM** — a socket or TLS failure marks the keys
  ``NOT_OBSERVED`` and the plane ``PARTIAL``.
"""

from __future__ import annotations

import pytest

from api import estate_discovery, hsm_usage

ENDPOINT = {"host": "hsm.bank.test", "port": 5696, "tls_verification": "REQUIRED", "source": "INJECTED"}
CONFIG = {**ENDPOINT, "tls_verification": "REQUIRED", "source": "INJECTED", "ca_file": None,
          "client_cert": None, "client_key": None, "insecure": False}


def _response(payload: list[bytes] | None, status: int = 0) -> bytes:
    header = hsm_usage.ttlv_structure(
        hsm_usage.TAG_RESPONSE_HEADER,
        hsm_usage.ttlv_structure(hsm_usage.TAG_PROTOCOL_VERSION,
                                 hsm_usage.ttlv_int(hsm_usage.TAG_PROTOCOL_VERSION_MAJOR, 2),
                                 hsm_usage.ttlv_int(hsm_usage.TAG_PROTOCOL_VERSION_MINOR, 0)),
        hsm_usage.ttlv_int(hsm_usage.TAG_BATCH_COUNT, 1),
        hsm_usage.ttlv_enum(hsm_usage.TAG_RESULT_STATUS, status),
    )
    batch_items = [hsm_usage.ttlv_enum(hsm_usage.TAG_RESULT_STATUS, status)]
    if payload is not None:
        batch_items.append(hsm_usage.ttlv_structure(hsm_usage.TAG_RESPONSE_PAYLOAD, *payload))
    return hsm_usage.ttlv_structure(
        hsm_usage.TAG_RESPONSE_MESSAGE, header, hsm_usage.ttlv_structure(hsm_usage.TAG_BATCH_ITEM, *batch_items)
    )


def _locate(*identifiers: str) -> bytes:
    located = hsm_usage.ttlv_structure(
        hsm_usage.TAG_LOCATED_ITEMS,
        *[hsm_usage.ttlv_text(hsm_usage.TAG_UNIQUE_IDENTIFIER, item) for item in identifiers],
    )
    return _response([located])


def _attribute(name: str, *values: bytes) -> bytes:
    return hsm_usage.ttlv_structure(
        hsm_usage.TAG_ATTRIBUTE, hsm_usage.ttlv_text(hsm_usage.TAG_ATTRIBUTE_NAME, name), *values
    )


def _attributes(identifier: str, *, state: int = hsm_usage.STATE_ACTIVE, mask: int = 0x0000000C,
                algorithm: int = 0x00000003, count: int | None = None, total: int | None = None) -> bytes:
    items: list[bytes] = [hsm_usage.ttlv_text(hsm_usage.TAG_UNIQUE_IDENTIFIER, identifier)]
    items.append(_attribute("Object Type", hsm_usage.ttlv_enum(hsm_usage.TAG_OBJECT_TYPE,
                                                              hsm_usage.OBJECT_TYPE_SYMMETRIC_KEY)))
    items.append(_attribute("Cryptographic Algorithm",
                            hsm_usage.ttlv_enum(hsm_usage.TAG_CRYPTOGRAPHIC_ALGORITHM, algorithm)))
    items.append(_attribute("Cryptographic Usage Mask",
                            hsm_usage.ttlv_int(hsm_usage.TAG_CRYPTOGRAPHIC_USAGE_MASK, mask)))
    items.append(_attribute("State", hsm_usage.ttlv_enum(hsm_usage.TAG_STATE, state)))
    if count is not None or total is not None:
        limits = [hsm_usage.ttlv_long(hsm_usage.TAG_USAGE_LIMITS_TOTAL, total or 0),
                  hsm_usage.ttlv_long(hsm_usage.TAG_USAGE_LIMITS_COUNT, count or 0),
                  hsm_usage.ttlv_enum(hsm_usage.TAG_USAGE_LIMITS_UNIT, 0x00000002)]
        items.append(_attribute("Usage Limits", hsm_usage.ttlv_structure(hsm_usage.TAG_USAGE_LIMITS, *limits)))
    items.append(_attribute("Initial Date", hsm_usage.ttlv_datetime(
        hsm_usage.TAG_INITIAL_DATE, __import__("datetime").datetime(2025, 1, 6, 8, 0, tzinfo=__import__("datetime").timezone.utc))))
    return _response(items)


class _Appliance:
    """A double that answers Locate then one GetAttributes per identifier."""

    def __init__(self, identifiers: list[str], attributes: dict[str, bytes] | None = None,
                 fail_on: str | None = None):
        self.identifiers = identifiers
        self.attributes = attributes or {}
        self.fail_on = fail_on
        self.sent: list[bytes] = []

    def __call__(self, request: bytes) -> bytes:
        self.sent.append(request)
        operations = [
            item["value"]
            for message in hsm_usage.decode(request)
            for batch in hsm_usage._all(message["items"], hsm_usage.TAG_BATCH_ITEM)
            for item in hsm_usage._all(batch["items"], hsm_usage.TAG_OPERATION)
        ]
        assert operations, "every request carries exactly one operation"
        if self.fail_on and self.identifiers and operations[0] == hsm_usage.OPERATION_GET_ATTRIBUTES:
            raise ConnectionResetError("peer reset the connection")
        if operations[0] == hsm_usage.OPERATION_LOCATE:
            return _locate(*self.identifiers)
        assert operations[0] == hsm_usage.OPERATION_GET_ATTRIBUTES
        identifier = self.identifiers[self.sent.count(request) - 2] if len(self.identifiers) > 1 else self.identifiers[0]
        if identifier not in self.attributes:
            identifier = self.identifiers[0]
        return self.attributes[identifier]


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def test_without_kmip_host_the_plane_is_not_attempted():
    with pytest.raises(hsm_usage.PlaneNotConfigured):
        hsm_usage.hsm_config({})

    def boom(_db, **_kwargs):
        raise hsm_usage.PlaneNotConfigured("no hsm")

    report = estate_discovery.run(None, persist=False, collectors={"HSM": boom})
    hsm = next(item for item in report["collectors"] if item["plane"] == "HSM")
    assert hsm["status"] == "NOT_ATTEMPTED"
    assert "NOT_OBSERVED" in hsm["impact"]


def test_tls_is_required_unless_the_operator_opts_out():
    config = hsm_usage.hsm_config({"KMIP_HOST": "hsm.bank.test"})
    assert config["port"] == 5696
    assert config["tls_verification"] == "REQUIRED"

    lab = hsm_usage.hsm_config({"KMIP_HOST": "hsm.bank.test", "KMIP_INSECURE": "true"})
    assert lab["tls_verification"] == "DISABLED"

    result = hsm_usage.collect_hsm_usage(None, transport=lambda _r: _locate(), config=lab)
    assert result["tls_verification"] == "DISABLED"


# --------------------------------------------------------------------------- #
# the protocol: read-only, tagged correctly
# --------------------------------------------------------------------------- #
def test_the_request_is_a_kmip_locate_for_symmetric_keys_only():
    appliance = _Appliance(["key-1"], {"key-1": _attributes("key-1")})
    hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)

    first = appliance.sent[0]
    root = hsm_usage.decode(first)
    message = hsm_usage._find(root, hsm_usage.TAG_REQUEST_MESSAGE)
    assert message is not None, "the outer tag must be RequestMessage"
    header = hsm_usage._find(message["items"], hsm_usage.TAG_REQUEST_HEADER)
    assert header is not None
    assert hsm_usage._find(header["items"], hsm_usage.TAG_BATCH_COUNT)["value"] == 1
    version = hsm_usage._find(header["items"], hsm_usage.TAG_PROTOCOL_VERSION)
    assert hsm_usage._find(version["items"], hsm_usage.TAG_PROTOCOL_VERSION_MAJOR)["value"] == 2

    batch = hsm_usage._find(message["items"], hsm_usage.TAG_BATCH_ITEM)
    assert hsm_usage._find(batch["items"], hsm_usage.TAG_OPERATION)["value"] == hsm_usage.OPERATION_LOCATE
    payload = hsm_usage._find(batch["items"], hsm_usage.TAG_REQUEST_PAYLOAD)
    attribute = hsm_usage._find(payload["items"], hsm_usage.TAG_ATTRIBUTE)
    assert hsm_usage._find(attribute["items"], hsm_usage.TAG_OBJECT_TYPE)["value"] == (
        hsm_usage.OBJECT_TYPE_SYMMETRIC_KEY
    )


def test_the_get_operation_which_returns_key_material_is_never_issued():
    appliance = _Appliance(["key-1", "key-2"],
                           {"key-1": _attributes("key-1"), "key-2": _attributes("key-2")})
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)

    operations = set()
    for request in appliance.sent:
        for message in hsm_usage.decode(request):
            for batch in hsm_usage._all(message["items"], hsm_usage.TAG_BATCH_ITEM):
                operations.update(item["value"] for item in hsm_usage._all(batch["items"],
                                                                          hsm_usage.TAG_OPERATION))
    assert operations == {hsm_usage.OPERATION_LOCATE, hsm_usage.OPERATION_GET_ATTRIBUTES}
    assert 0x0000000A not in operations, "KMIP Get returns the key value and must never be called"

    # no field anywhere carries key material, and no byte-string value is emitted
    fields: set[str] = set()

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                fields.add(str(key).lower())
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk({"assets": result["assets"], "evidence": result["evidence"]})
    for forbidden in ("material", "key_bytes", "secret", "plaintext", "private_key"):
        assert not [field for field in fields if forbidden in field], forbidden
    assert not [asset for asset in result["assets"] if asset["type"] == "SECRET"]


def test_every_emitted_object_carries_state_usage_and_algorithm_without_key_material():
    appliance = _Appliance(["key-1"], {"key-1": _attributes("key-1", count=4, total=100)})
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)
    key = next(asset for asset in result["assets"] if asset["type"] == "HSM")
    assert key["attributes"]["algorithm"] == "AES"
    assert key["attributes"]["state"] == "ACTIVE"
    assert key["attributes"]["capabilities"] == ["ENCRYPT", "DECRYPT"]
    assert "material" not in key["attributes"]

    facts = result["evidence"][0]["facts"]
    assert facts["usage_state"] == "OBSERVED"
    assert facts["usage_limits"] == {"total": 100, "count": 4, "unit": "OBJECT"}
    assert facts["unique_identifier"] == "key-1"
    assert result["evidence"][0]["evidence_type"] == "CONFIGURED"


def test_an_unmapped_usage_mask_bit_is_reported_never_dropped():
    unknown_bit = 0x00040000  # not in the reader's table
    appliance = _Appliance(["key-1"], {"key-1": _attributes("key-1", mask=0x00000004 | unknown_bit)})
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)
    facts = result["evidence"][0]["facts"]
    assert facts["capabilities"] == ["ENCRYPT"]
    assert facts["usage_mask_unmapped"] == ["0x40000"]
    assert facts["usage_mask"] == 0x00040004


# --------------------------------------------------------------------------- #
# capability ≠ use
# --------------------------------------------------------------------------- #
def test_the_usage_counter_not_the_algorithm_decides_observed():
    cases = [
        (hsm_usage.STATE_ACTIVE, 41, 100, "OBSERVED"),
        (hsm_usage.STATE_ACTIVE, 0, 100, "CONFIGURED"),
        (hsm_usage.STATE_ACTIVE, None, None, "CONFIGURED"),
        (hsm_usage.STATE_PRE_ACTIVE, None, None, "SUPPORTED"),
        (hsm_usage.STATE_DEACTIVATED, 900, 1000, "NOT_OBSERVED"),
        (hsm_usage.STATE_DESTROYED, None, None, "NOT_OBSERVED"),
    ]
    for state, count, total, expected in cases:
        observed, reason = hsm_usage.usage_state(
            {"state": hsm_usage.STATE_NAMES[state],
             "usage_limits": {"count": count, "total": total, "unit": "OBJECT"}}
        )
        assert observed == expected, (state, count, expected)
        assert reason


def test_an_aes_key_that_was_never_used_is_not_reported_as_used():
    appliance = _Appliance(
        ["key-1"],
        {"key-1": _attributes("key-1", state=hsm_usage.STATE_PRE_ACTIVE, mask=0x00000004, algorithm=0x00000003)},
    )
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)
    facts = result["evidence"][0]["facts"]
    assert facts["usage_state"] == "SUPPORTED"
    assert "could do crypto" in facts["usage_reason"]
    assert result["relationships"] == [], "existence must not be projected as an observed use edge"


# --------------------------------------------------------------------------- #
# refusals and limits
# --------------------------------------------------------------------------- #
def test_a_refused_connection_is_partial_not_an_empty_hsm():
    def refused(_request):
        raise ConnectionRefusedError("connection refused")

    result = hsm_usage.collect_hsm_usage(None, transport=refused, config=CONFIG)
    assert result["blocked"] and "connection refused" in result["blocked"][0]
    assert "NOT_OBSERVED, not absent" in " ".join(result["limitations"])
    assert [asset for asset in result["assets"] if asset["type"] == "HSM"] == []

    outcome = estate_discovery._collect("HSM", lambda _db, **_: result, None)
    assert outcome["status"] == "PARTIAL"
    assert "NOT_OBSERVED" in outcome["impact"]


def test_a_key_whose_attributes_fail_is_unknown_not_absent():
    appliance = _Appliance(["key-1", "key-2"], {"key-1": _attributes("key-1")}, fail_on="attributes")
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)
    assert result["blocked"], "the failing key must be recorded"
    assert "NOT_OBSERVED" in " ".join(result["limitations"])


def test_an_empty_partition_is_still_an_hsm():
    result = hsm_usage.collect_hsm_usage(None, transport=lambda _r: _locate(), config=CONFIG)
    assert result["keys_read"] == 0
    assert result["appliance_asset_id"]
    assert "empty partition, not an empty HSM estate" in " ".join(result["limitations"])


def test_the_key_cap_is_declared_partial():
    identifiers = [f"key-{index}" for index in range(3)]
    appliance = _Appliance(identifiers, {item: _attributes(item) for item in identifiers})
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG, max_keys=3)
    assert "cap was reached" in " ".join(result["limitations"])
    assert "PARTIAL" in " ".join(result["limitations"])


# --------------------------------------------------------------------------- #
# the graph
# --------------------------------------------------------------------------- #
def test_hsm_and_kms_are_planes_and_their_keys_enter_the_estate_graph():
    assert "HSM" in estate_discovery.PLANES and "KMS" in estate_discovery.PLANES
    assert "KMIP" in estate_discovery.PLANE_DETAIL["HSM"]["source"]
    assert "CloudTrail" in estate_discovery.PLANE_DETAIL["KMS"]["source"]
    assert "never" in estate_discovery.PLANE_DETAIL["HSM"]["limitation"]

    appliance = _Appliance(["key-1"], {"key-1": _attributes("key-1", count=2, total=10)})
    result = hsm_usage.collect_hsm_usage(None, transport=appliance, config=CONFIG)
    report = estate_discovery.run(
        None, persist=False, collectors={"HSM": lambda _db, **_: result},
    )
    hsm = next(item for item in report["collectors"] if item["plane"] == "HSM")
    assert hsm["status"] == "COMPLETE"
    assert hsm["collected"] >= 1
