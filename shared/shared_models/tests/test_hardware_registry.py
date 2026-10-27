"""Tests for the canonical hardware security registry."""

from __future__ import annotations

import pytest

from shared_models.hardware_registry import (
    ALLOWED,
    DEPRECATED,
    DISALLOWED,
    RESTRICTED,
    REQUIRED,
    UNKNOWN,
    HARDWARE_KEYSTORE,
    ROOT_OF_TRUST,
    catalog,
    classify_hardware,
    risk_severity,
    tpm_verdict,
)


def test_catalog_is_nonempty_and_well_formed():
    entries = catalog()
    assert len(entries) >= 50
    for e in entries:
        assert e["device"]
        assert e["category"]
        assert e["status"] in (REQUIRED, ALLOWED, RESTRICTED, DEPRECATED, DISALLOWED, UNKNOWN)
        assert isinstance(e["attestation"], bool)


# -- TPM --------------------------------------------------------------------- #
@pytest.mark.parametrize("version", ["2.0", "2", "2.0 (Infineon)", "TPM 2.0"])
def test_tpm_20_is_required_root_of_trust(version):
    info = classify_hardware(version, kind="tpm")
    assert info.category == ROOT_OF_TRUST
    assert info.status == REQUIRED


def test_tpm_version_helper():
    assert tpm_verdict("2.0").status == REQUIRED
    assert tpm_verdict("1.2").status == DEPRECATED
    assert tpm_verdict(None, present=False).status == DISALLOWED
    assert tpm_verdict(None, present=True).status == UNKNOWN


def test_tpm_12_is_deprecated():
    info = classify_hardware("1.2", kind="tpm")
    assert info.status == DEPRECATED


# -- HSMs -------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "name,mfr",
    [("Luna SA 7", "Thales"), ("nShield Connect", "Entrust"),
     ("Utimaco SecurityServer", "Utimaco"), ("CloudHSM", "AWS")],
)
def test_hsm_appliances_allowed(name, mfr):
    info = classify_hardware(name, kind="hsm", manufacturer=mfr)
    assert info.category == HARDWARE_KEYSTORE
    assert info.status == ALLOWED


def test_softhsm_is_not_hardware():
    info = classify_hardware("SoftHSM2", kind="hsm")
    assert info.status == RESTRICTED
    assert "software" in (info.notes + info.canonical).lower() or not info.attestation


# -- secure elements / enclaves --------------------------------------------- #
def test_security_keys():
    assert classify_hardware("YubiKey 5C NFC", kind="secure_element").status == ALLOWED
    assert classify_hardware("Titan Security Key", kind="secure_element").canonical == "Google Titan Key"


def test_mobile_enclaves():
    assert classify_hardware("Secure Enclave", kind="enclave").canonical == "Apple Secure Enclave"
    assert classify_hardware("StrongBox", kind="enclave").canonical == "Android StrongBox"
    assert classify_hardware("TrustZone", kind="tee").canonical == "ARM TrustZone"


# -- TEE / confidential computing ------------------------------------------- #
@pytest.mark.parametrize("name,expected_status", [
    ("TDX", ALLOWED), ("SEV-SNP", ALLOWED), ("Intel SGX", RESTRICTED),
])
def test_confidential_computing(name, expected_status):
    assert classify_hardware(name, kind="tee").status == expected_status


# -- storage encryption ------------------------------------------------------ #
def test_sed_verdicts():
    assert classify_hardware("Opal 2.0 SED", kind="sed").status == ALLOWED
    pyrite = classify_hardware("Pyrite", kind="sed")
    assert pyrite.status == DISALLOWED  # access control WITHOUT encryption


# -- management controllers -------------------------------------------------- #
def test_bmc_verdicts():
    assert classify_hardware("Redfish", kind="bmc").status == ALLOWED
    assert classify_hardware("IPMI 2.0", kind="bmc").status == DEPRECATED


# -- severity ---------------------------------------------------------------- #
def test_severity_floor():
    assert risk_severity(classify_hardware("unknown-chip-zz", kind="")) == "MEDIUM"
    assert risk_severity(tpm_verdict(None, present=False)) == "HIGH"      # no root of trust
    assert risk_severity(tpm_verdict("2.0")) == "INFO"
    assert risk_severity(classify_hardware("1.2", kind="tpm")) == "MEDIUM"  # deprecated TPM
    assert risk_severity(classify_hardware("Pyrite", kind="sed")) == "HIGH"  # fake encryption = disallowed


def test_recognition_flags():
    assert classify_hardware("YubiKey 5", kind="secure_element").recognized is True
    assert classify_hardware("flibbertigibbet-chip", kind="").recognized is False
