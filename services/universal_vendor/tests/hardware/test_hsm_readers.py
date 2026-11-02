"""H4 readers: PKCS#11 partitions/mechanisms and the KMIP Query surface.

Everything here runs against recorded tool output and a hand-built TTLV
response, on the production code path. Nothing contacts an appliance, and the
one test that touches ``subprocess`` uses a stub — the point is that the
boundaries (allowlist, PIN, read-only) are executable statements.
"""

from __future__ import annotations

import pytest

from universal_vendor.hardware.hsm_hw import HsmHardwareScanner
from universal_vendor.hardware.hsm_readers import (
    CommandNotAllowed,
    FunctionNotAllowed,
    HsmReadResult,
    KmipQueryReader,
    PinOnCommandLineRefused,
    Pkcs11Reader,
    algorithm_name,
    build_argv,
    mechanism_families,
    parse_mechanisms,
    parse_query_response,
    parse_token_info,
    pqc_families,
    query_request,
    validate_module_path,
)
from universal_vendor.hardware.hsm_readers import kmip_query as kmip

TOKEN_INFO = """Available slots:
Slot 0 (0x0): Thales Luna PCIe 800
  token label        : partition-payments
  token manufacturer : Thales
  token model        : Luna K7
  token flags        : login required, rng, write protected,
  token serial       : 1234567890
  hardware version   : 7.0
  firmware version   : 7.8.1
  UTC time           : Tue Nov  4 09:12:00 2025

Slot 1 (0x1): Thales Luna PCIe 800
  token label        : partition-signing
  token manufacturer : Thales
  token model        : Luna K7
  token flags        : login required, rng,
  token serial       : 1234567891
  hardware version   : 7.0
  firmware version   : 7.8.1

Slot 2 (0x2): Luna Backup
  (empty)
"""

MECHANISMS = """Using slot 0 with a present token (0x0)
Supported mechanisms:
  CKM_AES_KEY_GEN, keySize={16,32}, hw, encrypt, decrypt, wrap, unwrap
  CKM_ML_KEM, keySize={768,1024}, hw
  CKM_ML_DSA, keySize={44,65,87}, hw, sign, verify
  CKM_SLH_DSA, hw, sign, verify
  CKM_RSA_PKCS, keySize={1024,4096}, hw, sign, verify
  CKM_ECDSA, ecParams={...}, hw, sign
  CKM_SHA256_HMAC, hw, sign, verify
  CKM_AES_KEY_GEN, keySize={16,32}, hw
"""

@pytest.fixture()
def module(tmp_path):
    """A PKCS#11 library path that exists, since the reader checks it does."""
    path = tmp_path / "libCryptoki2_64.so"
    path.write_text("not really a library", encoding="utf-8")
    return str(path)


class Tool:
    """A recorded ``pkcs11-tool``: answers by flag, remembers argv and env."""

    def __init__(self, *, info: str = TOKEN_INFO, mechanisms: str = MECHANISMS,
                 fail: str | None = None) -> None:
        self.info = info
        self.mechanisms = mechanisms
        self.fail = fail
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def __call__(self, argv, timeout, env):
        from universal_vendor.hardware.hsm_readers.pkcs11 import CommandResult

        self.calls.append((tuple(argv), dict(env)))
        if self.fail:
            return CommandResult(tuple(argv), 1, "", self.fail)
        stdout = self.info if "-T" in argv else self.mechanisms
        return CommandResult(tuple(argv), 0, stdout, "")


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

def test_token_info_yields_one_record_per_initialised_partition():
    tokens = parse_token_info(TOKEN_INFO)
    assert len(tokens) == 2, "an empty slot is not a partition"
    assert tokens[0]["label"] == "partition-payments"
    assert tokens[0]["serial_reference"] == "1234567890"
    assert tokens[0]["firmware"] == "7.8.1"
    assert tokens[0]["model"] == "Luna K7"


def test_token_flags_become_posture_not_prose():
    tokens = parse_token_info(TOKEN_INFO)
    assert tokens[0]["login_required"] is True
    assert tokens[0]["write_protected"] is True
    assert tokens[1]["write_protected"] is False


def test_mechanisms_are_deduplicated_in_order():
    mechanisms = parse_mechanisms(MECHANISMS)
    assert mechanisms[0] == "CKM_AES_KEY_GEN"
    assert mechanisms.count("CKM_AES_KEY_GEN") == 1
    assert "CKM_ML_KEM" in mechanisms


def test_mechanisms_become_algorithm_families_and_pqc_is_separate():
    families = mechanism_families(parse_mechanisms(MECHANISMS))
    assert {"AES", "RSA", "ECDSA", "SHA-256"} <= set(families)
    assert set(pqc_families(families)) == {"ML-KEM", "ML-DSA", "SLH-DSA"}
    assert "AES" not in pqc_families(families)


# --------------------------------------------------------------------------- #
# boundaries
# --------------------------------------------------------------------------- #

def test_only_pkcs11_tool_may_run():
    assert build_argv("pkcs11-tool", "--module", "/tmp/lib.so", "-T")[0] == "pkcs11-tool"
    for bad in ("bash", "sh", "openssl", "/bin/sh"):
        with pytest.raises(CommandNotAllowed):
            build_argv(bad, "-c", "id")


def test_a_pin_on_argv_is_refused():
    """`pkcs11-tool --pin 1234` puts the partition PIN in every `ps` on the host."""
    for form in ("--pin", "--pin=1234"):
        with pytest.raises(PinOnCommandLineRefused):
            build_argv("pkcs11-tool", "--module", "/tmp/lib.so", form)


def test_shell_metacharacters_are_refused():
    with pytest.raises(CommandNotAllowed):
        build_argv("pkcs11-tool", "--module", "/tmp/x; rm -rf /")


def test_the_module_must_be_an_absolute_regular_file(tmp_path):
    real = tmp_path / "libCryptoki.so"
    real.write_text("x", encoding="utf-8")
    assert validate_module_path(str(real)) == str(real)
    for bad in ("libCryptoki.so", "/usr/lib/../etc/passwd", str(tmp_path / "missing.so")):
        with pytest.raises(CommandNotAllowed):
            validate_module_path(bad)


def test_the_pin_travels_in_the_environment_not_argv(module):
    tool = Tool()
    reader = Pkcs11Reader(runner=tool, environ={"PKCS11_PIN": "1234"})
    reader.collect(module)
    for argv, env in tool.calls:
        assert not any("1234" in part for part in argv), "the PIN must not be an argument"
        assert env.get("PKCS11_PIN") == "1234"
        assert "shell" not in " ".join(argv)


def test_without_a_pin_the_metadata_is_still_read_and_the_gap_stated(module):
    tool = Tool(mechanisms="")
    facts = Pkcs11Reader(runner=tool, environ={}).collect(module)
    assert facts.serial_reference == "1234567890"
    assert any("PKCS11_PIN is not set" in reason for reason in facts.unavailable)
    assert any("empty capability list" in reason for reason in facts.unavailable)


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #

def test_a_partition_reads_as_an_hsm(module):
    facts = Pkcs11Reader(runner=Tool(), environ={"PKCS11_PIN": "1234"}).collect(module)
    assert facts.manufacturer == "Thales"
    assert facts.model == "Luna K7"
    assert facts.firmware == "7.8.1"
    assert len(facts.partitions) == 2
    assert facts.login_required is True
    assert set(facts.pqc_algorithms) == {"ML-KEM", "ML-DSA", "SLH-DSA"}
    assert "2 partition(s) on one appliance" in facts.capabilities


def test_absent_module_answers_are_reasons_not_crashes(module):
    facts = Pkcs11Reader(runner=Tool(fail="C_Initialize failed: 0x6"),
                         environ={}).collect(module)
    assert facts.partitions == []
    assert any("C_Initialize failed" in reason for reason in facts.unavailable)


def test_a_module_with_no_token_is_a_fact(module):
    facts = Pkcs11Reader(runner=Tool(info="Available slots:\nSlot 0 (0x0): Luna Backup\n"
                                          "  (empty)\n"), environ={}).collect(module)
    assert facts.partitions == []
    assert any("listed no initialized token" in reason for reason in facts.unavailable)


def test_reader_output_flows_into_the_one_hsm_observation(module):
    """Readers feed the scanner; they do not invent a second observation shape."""
    facts = Pkcs11Reader(runner=Tool(), environ={"PKCS11_PIN": "1234"}).collect(module)
    observation = HsmHardwareScanner().scan(facts.to_raw())

    assert observation["manufacturer"] == "Thales"
    assert observation["serial_reference"] == "1234567890"
    assert observation["partition_metadata"]["count"] == 2
    assert "ML-DSA" in observation["pqc_algorithms"]
    assert observation["pqc_capability"] == "SUPPORTED"
    # Posture is not a canonical HSM field: it lands in vendor_specific, where
    # the scanner keeps metadata it does not model first-class.
    assert observation["vendor_specific"]["security_posture"]["write_protected"] is True
    assert observation["vendor_specific"]["pkcs11_mechanisms"][0] == "CKM_AES_KEY_GEN"


def test_a_read_result_without_pqc_says_so():
    facts = HsmReadResult(source="pkcs11", mechanisms=["CKM_RSA_PKCS"])
    assert facts.to_raw()["pqc_capability"] == "NOT_SUPPORTED"


# --------------------------------------------------------------------------- #
# KMIP Query
# --------------------------------------------------------------------------- #

def _response(operations=(0x08, 0x0B, 0x18), objects=(0x02, 0x03, 0x04),
              vendor="Thales Luna K7", serial="LX-778812", profile="KMIP 2.0 Profile"):
    payload = kmip.ttlv_structure(
        kmip.TAG_RESPONSE_PAYLOAD,
        kmip.ttlv_structure(kmip.TAG_OPERATIONS,
                            *[kmip.ttlv_enum(kmip.TAG_OPERATION, op) for op in operations]),
        kmip.ttlv_structure(kmip.TAG_OBJECTS,
                            *[kmip.ttlv_enum(kmip.TAG_OPERATION, obj) for obj in objects]),
        kmip.ttlv_structure(kmip.TAG_SERVER_INFORMATION,
                            kmip.ttlv_text(kmip.TAG_VENDOR_IDENTIFICATION, vendor),
                            kmip.ttlv_text(kmip.TAG_SERVER_SERIAL_NUMBER, serial)),
        kmip.ttlv_structure(kmip.TAG_PROFILE_INFORMATION,
                            kmip.ttlv_text(kmip.TAG_NAME, profile)),
    )
    batch = kmip.ttlv_structure(kmip.TAG_BATCH_ITEM,
                                kmip.ttlv_enum(kmip.TAG_RESULT_STATUS, 0), payload)
    return kmip.ttlv_structure(kmip.TAG_RESPONSE_MESSAGE, batch)


def test_the_request_is_a_query_and_nothing_else():
    request = query_request()
    decoded = kmip.decode(request)
    assert [hex(node["tag"]) for node in decoded] == [hex(kmip.TAG_REQUEST_MESSAGE)]
    assert b"\x00\x00\x00\x18" in request, "operation 0x18 is Query"
    for forbidden in (b"get", b"locate", b"create", b"destroy"):
        assert forbidden not in request.lower()


def test_a_non_read_function_is_refused():
    # 0x08 Application Namespaces, 0x0C Client Registration Methods, 0x0D Defaults.
    for function in (0x00000004, 0x0000000C, 0x0000000D):
        with pytest.raises(FunctionNotAllowed):
            query_request([function])


def test_the_response_names_the_vendor_and_the_capabilities():
    parsed = parse_query_response(_response())
    assert parsed["vendor_identification"] == "Thales Luna K7"
    assert parsed["server_serial_number"] == "LX-778812"
    assert "locate" in parsed["operations"]
    assert "private_key" in parsed["objects"]
    assert parsed["profiles"] == ["KMIP 2.0 Profile"]


def test_a_failed_query_reports_the_appliance_reason():
    batch = kmip.ttlv_structure(
        kmip.TAG_BATCH_ITEM, kmip.ttlv_enum(kmip.TAG_RESULT_STATUS, 1),
        kmip.ttlv_enum(kmip.TAG_RESULT_REASON, 2),
        kmip.ttlv_text(kmip.TAG_RESULT_MESSAGE, "Query is not permitted for this user"))
    with pytest.raises(kmip.KmipQueryError) as caught:
        parse_query_response(kmip.ttlv_structure(kmip.TAG_RESPONSE_MESSAGE, batch))
    assert "Query is not permitted" in str(caught.value)


def test_unknown_operation_codes_are_not_guessed():
    parsed = parse_query_response(_response(operations=(0x08, 0x77)))
    assert parsed["operations"] == ["locate", "unknown_119"]


def test_unknown_algorithm_codes_are_not_guessed():
    assert algorithm_name(0x03) == "AES"
    assert algorithm_name(0x41) == "unknown_0x00000041"


def test_the_reader_states_a_missing_transport():
    capabilities = KmipQueryReader().collect()
    assert capabilities.supports_query is False
    assert "no KMIP transport configured" in capabilities.unavailable[0]


def test_the_reader_survives_a_transport_failure():
    def broken(request):
        raise OSError("connection refused")

    capabilities = KmipQueryReader(transport=broken).collect()
    assert "connection refused" in capabilities.unavailable[0]


def test_capabilities_project_into_the_hsm_raw_shape():
    capabilities = KmipQueryReader(transport=lambda request: _response()).collect()
    raw = capabilities.to_raw()
    assert raw["manufacturer"] == "Thales Luna K7"
    assert raw["crypto_capabilities"] == ["KMIP 2.0 Profile"]
    assert raw["firmware"] is None, "Query does not report firmware; do not invent it"


def test_query_capabilities_and_pkcs11_agree_on_the_appliance(module):
    """Both readers name the same box, which is the point of having both."""
    pkcs11_facts = Pkcs11Reader(runner=Tool(), environ={"PKCS11_PIN": "1"}
                                ).collect(module)
    kmip_facts = KmipQueryReader(transport=lambda request: _response()).collect()
    assert pkcs11_facts.manufacturer == "Thales"
    assert kmip_facts.vendor_identification.startswith("Thales")
