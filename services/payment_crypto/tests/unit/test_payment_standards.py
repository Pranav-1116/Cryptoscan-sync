"""ISO 9564 PIN blocks, ISO 8583 field crypto, and the EMV cryptogram lifecycle.

Pure and deterministic: no HSM, no network, no key material. The safety
property these modules claim — that they analyse declarations and refuse
anything that looks like real PIN or key material — is asserted directly.
"""

from __future__ import annotations

import pytest

from payment_crypto.emv import (
    analyse_cryptogram_config,
    cryptogram_type,
    looks_like_key_material,
    summarise_portfolio,
)
from payment_crypto.iso8583 import analyse_message_fields, summarise_links
from payment_crypto.pinblocks import (
    analyse_pin_block_format,
    looks_like_pin_material,
    summarise_estate,
)


# ------------------------------------------------- ISO 9564 PIN block formats


def _codes(verdict) -> set[str]:
    return {i["code"] for i in verdict.issues}


@pytest.mark.parametrize("declared", ["0", "ISO-0", "iso0", "ANSI X9.8", "format0", "FMT_0"])
def test_format_zero_is_recognised_however_it_is_spelled(declared):
    v = analyse_pin_block_format(declared)
    assert v.valid and v.iso_format == "0"
    assert v.pan_bound is True
    assert v.block_cipher == "TDES"


def test_format_one_is_flagged_as_not_pan_bound():
    v = analyse_pin_block_format("ISO-1")
    assert v.pan_bound is False
    assert "PIN_BLOCK_NOT_PAN_BOUND" in _codes(v)


def test_format_two_online_is_critical_but_offline_is_fine():
    online = analyse_pin_block_format("ISO-2", online=True)
    assert "OFFLINE_FORMAT_USED_ONLINE" in _codes(online)
    assert online.pci_pin_compliant is False

    offline = analyse_pin_block_format("ISO-2", online=False)
    assert "OFFLINE_FORMAT_USED_ONLINE" not in _codes(offline)


def test_format_four_is_the_aes_target_and_raises_no_tdes_finding():
    v = analyse_pin_block_format("ISO-4", key_algorithm="AES")
    assert v.iso_format == "4"
    assert v.block_cipher == "AES" and v.block_bits == 128
    assert v.requires_tdes_migration is False
    assert v.pci_pin_compliant is True
    assert _codes(v) == set()


def test_aes_key_with_a_64_bit_format_is_a_mismatch():
    v = analyse_pin_block_format("ISO-0", key_algorithm="AES")
    assert "PIN_FORMAT_KEY_MISMATCH" in _codes(v)


def test_tdes_key_with_format_four_is_a_mismatch():
    v = analyse_pin_block_format("ISO-4", key_algorithm="3DES")
    assert "PIN_FORMAT_KEY_MISMATCH" in _codes(v)


def test_proprietary_formats_are_named_not_guessed():
    v = analyse_pin_block_format("IBM3624")
    assert v.proprietary == "IBM 3624"
    assert "PROPRIETARY_PIN_BLOCK" in _codes(v)
    assert v.pci_pin_compliant is False


def test_unknown_format_is_an_error_not_a_pass():
    v = analyse_pin_block_format("format-99")
    assert v.valid is False and v.errors
    assert v.pci_pin_compliant is None


def test_pin_block_data_is_refused_rather_than_analysed():
    """A 16-hex-digit value is an enciphered PIN block, not a format name."""
    assert looks_like_pin_material("A1B2C3D4E5F60718")
    v = analyse_pin_block_format("A1B2C3D4E5F60718")
    assert v.valid is False
    assert any("refused" in e for e in v.errors)


def test_format_name_is_not_mistaken_for_pin_material():
    assert not looks_like_pin_material("ISO-0")
    assert not looks_like_pin_material("4")


def test_estate_rollup_counts_the_migration_backlog():
    summary = summarise_estate([
        {"system": "atm-switch", "format": "ISO-0"},
        {"system": "pos-switch", "format": "ISO-3"},
        {"system": "new-rail", "format": "ISO-4", "key_algorithm": "AES"},
        {"system": "legacy-atm", "format": "IBM3624"},
    ])
    assert summary["total"] == 4
    assert summary["aes_ready"] == 1
    assert summary["tdes_bound"] == 3
    assert summary["non_compliant"] == 1          # the proprietary one
    assert summary["by_format"]["ISO-0"] == 1


# --------------------------------------------------------------- ISO 8583


def test_pin_bearing_link_without_a_mac_is_a_high_finding():
    v = analyse_message_fields([2, 52])
    assert v.carries_pin is True and v.is_maced is False
    assert "PIN_WITHOUT_MAC" in {i["code"] for i in v.issues}


def test_secondary_bitmap_mac_counts_as_maced():
    """Field 128 is the MAC when the secondary bitmap is used."""
    v = analyse_message_fields([2, 52, 128])
    assert v.is_maced is True
    assert "PIN_WITHOUT_MAC" not in {i["code"] for i in v.issues}


def test_emv_and_key_management_fields_are_inventoried():
    v = analyse_message_fields([52, 53, 55, 64])
    kinds = {c["kind"] for c in v.crypto_fields}
    assert kinds == {"PIN", "KEY_MGMT", "EMV", "MAC"}
    assert v.carries_emv is True


def test_retail_mac_is_flagged_as_a_des_construction():
    v = analyse_message_fields([52, 53, 64], mac_algorithm="ISO 9797-1 Algorithm 3 (Retail MAC)")
    assert "TDES_MAC" in {i["code"] for i in v.issues}


def test_aes_cmac_link_raises_no_mac_algorithm_finding():
    v = analyse_message_fields([52, 53, 64], mac_algorithm="AES-CMAC",
                               pin_block_format="ISO-4")
    codes = {i["code"] for i in v.issues}
    assert "TDES_MAC" not in codes and "MAC_ALGORITHM_UNDECLARED" not in codes


def test_pin_block_format_findings_are_attributed_to_field_52():
    v = analyse_message_fields([52, 53, 64], pin_block_format="ISO-1")
    pin_issues = [i for i in v.issues if i.get("source") == "field 52 PIN block format"]
    assert any(i["code"] == "PIN_BLOCK_NOT_PAN_BOUND" for i in pin_issues)


def test_dict_input_ignores_values_and_reads_only_field_numbers():
    """Callers must not be able to push cardholder data through this."""
    v = analyse_message_fields({"2": "4111111111111111", "52": "A1B2C3D4E5F60718"})
    assert v.fields_present == [2, 52]
    assert "4111111111111111" not in str(v)


def test_out_of_range_and_non_numeric_elements_are_errors():
    v = analyse_message_fields([0, 129, "abc", 52])
    assert v.fields_present == [52]
    assert len(v.errors) == 3


def test_link_rollup():
    summary = summarise_links([
        {"link": "visa-base1", "fields": [2, 52, 64], "mac_algorithm": "AES-CMAC",
         "pin_block_format": "ISO-4"},
        {"link": "legacy-atm", "fields": [2, 52]},
    ])
    assert summary["pin_links"] == 2
    assert summary["unmaced_links"] == 1


# ------------------------------------------------------------------- EMV


def test_cvn_10_session_key_is_not_diversified():
    """The finding that matters: no ATC input means one key for every transaction."""
    v = analyse_cryptogram_config("10")
    assert v.valid and v.scheme == "Visa"
    assert v.atc_diversified is False
    assert "SESSION_KEY_NOT_DIVERSIFIED" in _codes(v)


def test_cvn_18_is_aes_and_diversified():
    v = analyse_cryptogram_config("18", key_algorithm="AES", key_bits=128)
    assert v.cipher == "AES" and v.atc_diversified is True
    assert "SESSION_KEY_NOT_DIVERSIFIED" not in _codes(v)
    assert "TDES_CRYPTOGRAM" not in _codes(v)


def test_mchip_letter_cvns_are_recognised():
    assert analyse_cryptogram_config("A").scheme == "Mastercard"
    assert analyse_cryptogram_config("C").cipher == "AES"


@pytest.mark.parametrize("spelling", ["10", "CVN 10", "cvn10", " 10 "])
def test_cvn_spellings_normalise(spelling):
    assert analyse_cryptogram_config(spelling).atc_diversified is False


def test_declared_key_algorithm_is_cross_checked_against_the_cvn():
    v = analyse_cryptogram_config("18", key_algorithm="TDES")
    assert "CVN_KEY_ALGORITHM_MISMATCH" in _codes(v)


def test_two_key_tdes_imk_is_flagged():
    v = analyse_cryptogram_config("14", key_algorithm="TDES", key_bits=112)
    assert "TWO_KEY_TDES" in _codes(v)


def test_short_imk_is_flagged():
    v = analyse_cryptogram_config("18", key_algorithm="AES", key_bits=64)
    assert "IMK_TOO_SHORT" in _codes(v)


def test_aes_128_is_still_quantum_vulnerable_but_aes_256_is_not():
    assert analyse_cryptogram_config("18", key_bits=128).quantum_vulnerable is True
    assert analyse_cryptogram_config("18", key_bits=256).quantum_vulnerable is False


def test_unknown_cvn_is_an_error_not_a_guess():
    v = analyse_cryptogram_config("99")
    assert v.valid is False and v.errors and not v.issues


def test_key_material_is_refused_rather_than_parsed():
    key = "0123456789ABCDEF0123456789ABCDEF"
    assert looks_like_key_material(key)
    v = analyse_cryptogram_config(key)
    assert v.valid is False
    assert any("refused" in e for e in v.errors)


def test_cryptogram_type_surfaces_unknown_labels():
    assert cryptogram_type("ARQC")["known"] is True
    unknown = cryptogram_type("ZZZZ")
    assert unknown["known"] is False and "UNKNOWN" in unknown["description"]


def test_portfolio_rollup():
    summary = summarise_portfolio([
        {"application": "VISA-DEBIT", "cvn": "10", "key_algorithm": "TDES", "key_bits": 112},
        {"application": "VISA-CREDIT", "cvn": "18", "key_algorithm": "AES", "key_bits": 256},
        {"application": "MC-DEBIT", "cvn": "A", "key_algorithm": "TDES", "key_bits": 168},
    ])
    assert summary["total"] == 3
    assert summary["aes_applications"] == 1
    assert summary["tdes_applications"] == 2
    assert summary["undiversified_session_keys"] == 1
    assert summary["quantum_vulnerable"] == 2
