"""Evidence-backed hardware relationships, and hardware drift.

The two claims that matter, tested separately:

* an edge exists only when something evidences it, and the confidence reported is
  the *weakest* citation rather than the strongest — a config-proven dependency
  must not be able to ride on a stale CMDB row;
* drift names what actually moved: a firmware bump is not a replacement, a
  capability that was *removed* is not the same event as one that was added, and
  the post-quantum change is reported on its own line because that is the line a
  PQC programme reads.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "services" / "universal_vendor"))

from universal_vendor.hardware.drift import (  # noqa: E402
    PQC_ALGORITHMS, diff, summarise,
)
from universal_vendor.hardware.relationships import (  # noqa: E402
    Evidence, UnevidencedRelationship, blast_radius, derive_edges, require_evidence,
)


# ------------------------------------------------------------------ relationships


def test_config_evidence_produces_a_high_confidence_edge():
    edges = derive_edges("payment-api", config_reference="etc/pkcs11.conf",
                         config_text="pkcs11:\n  slot: 1\n  token: HSM-01\n")
    assert len(edges) == 1
    edge = edges[0]
    assert (edge.subject, edge.hardware, edge.kind) == ("payment-api", "HSM-01", "USES_HSM")
    assert edge.confidence == "HIGH"
    assert [e.kind for e in edge.evidence] == ["CONFIG"]
    assert edge.evidence[0].evidence_id.startswith("EV-")


def test_a_slot_number_is_not_an_appliance():
    """`slot=1` used to mint an edge to a hardware asset called "1"."""
    assert derive_edges("app", config_text="pkcs11: slot=1") == []


def test_two_sources_for_one_pair_are_one_edge_with_two_citations():
    edges = derive_edges("payment-api", config_reference="etc/pkcs11.conf",
                         config_text="pkcs11: token=HSM-01\n",
                         declared=["HSM-01"])
    assert len(edges) == 1
    assert {e.kind for e in edges[0].evidence} == {"CONFIG", "DECLARED"}
    # the weakest citation decides: an edge is only as strong as its weakest record
    assert edges[0].confidence == "MEDIUM"


def test_an_edge_without_evidence_is_refused():
    with pytest.raises(UnevidencedRelationship, match="no evidence"):
        require_evidence("payment-api", "HSM-01", "USES_HSM", [])
    with pytest.raises(UnevidencedRelationship):
        require_evidence("payment-api", "HSM-01", "USES_HSM", [Evidence("DECLARED", "")])


def test_evidence_must_point_at_a_location_not_a_secret():
    for reference in ("config#password=hunter2", "vault:pin", "file#private_key"):
        with pytest.raises(UnevidencedRelationship, match="point at the file"):
            Evidence("CONFIG", reference)
    with pytest.raises(UnevidencedRelationship):
        Evidence("GUESS", "etc/pkcs11.conf")


def test_nothing_observed_is_an_empty_list_not_a_failure():
    """No dependency was found; that is a finding, and it is not an exception."""
    assert derive_edges("payment-api", config_text="nothing about crypto here") == []


def test_blast_radius_counts_only_evidenced_edges_and_reports_the_weakest():
    edges = derive_edges("payment-api", config_reference="etc/pkcs11.conf",
                         config_text="pkcs11: token=HSM-01\n")
    edges += derive_edges("card-auth", declared=["HSM-01"])
    edges += derive_edges("unrelated", declared=["HSM-02"])
    radius = blast_radius("HSM-01", edges,
                          system_of={"payment-api": "payments", "card-auth": "payments"},
                          business_system_of={"payments": "card-authorisation"})
    assert radius["applications"] == ["card-auth", "payment-api"]
    assert radius["systems"] == ["payments"]
    assert radius["business_flows"] == ["card-authorisation"]
    assert radius["applications_affected"] == 2
    assert radius["lowest_confidence"] == "MEDIUM"   # card-auth is DECLARED only
    assert radius["edges"] and all(edge["evidence"] for edge in radius["edges"])


def test_blast_radius_marks_the_unmapped_rather_than_dropping_them():
    edges = derive_edges("orphan-app", declared=["HSM-01"])
    radius = blast_radius("HSM-01", edges, system_of={}, business_system_of={})
    assert radius["unmapped_applications"] == ["orphan-app"]
    assert radius["systems_affected"] == 0


# ------------------------------------------------------------------------ drift


def _hsm(**over):
    state = {"asset_id": "hsm-01", "device_type": "hsm", "manufacturer": "Vendor-X",
             "model": "HSM-X500", "serial_reference": "SYN-0001",
             "firmware": {"HSM": "8.2.1"},
             "supported_algorithms": ["RSA-2048", "RSA-3072", "ECDSA-P256", "AES-256"],
             "evidence_history": ["EV-1"]}
    state.update(over)
    return state


def test_a_firmware_bump_is_not_a_replacement():
    changes = diff(_hsm(), _hsm(firmware={"HSM": "8.4.0"}, evidence_history=["EV-2"]))
    kinds = [change.event_type for change in changes]
    assert kinds == ["FIRMWARE_CHANGED"], kinds
    detail = changes[0].detail["components"]
    assert detail["HSM"] == {"before": "8.2.1", "after": "8.4.0"}
    assert changes[0].change_class == "FIRMWARE_CHANGE"
    assert sorted(changes[0].evidence) == ["EV-1", "EV-2"]


def test_a_model_change_is_a_replacement():
    changes = diff(_hsm(), _hsm(model="HSM-X700"))
    assert [change.event_type for change in changes] == ["HARDWARE_CHANGED"]
    assert changes[0].change_class == "REPLACEMENT"
    assert changes[0].detail["fields"]["model"] == {"before": "HSM-X500", "after": "HSM-X700"}


def test_a_new_post_quantum_algorithm_is_its_own_event():
    after = _hsm(supported_algorithms=[*_hsm()["supported_algorithms"], "ML-DSA-65"])
    changes = diff(_hsm(), after)
    kinds = [change.event_type for change in changes]
    assert kinds == ["CRYPTO_CAPABILITY_CHANGED", "PQC_CAPABILITY_ADDED",
                     "HSM_CAPABILITY_CHANGED"]
    pqc = next(change for change in changes if change.event_type == "PQC_CAPABILITY_ADDED")
    assert pqc.detail["algorithms"] == ["ML-DSA-65"]
    assert pqc.pqc_affected is True
    assert pqc.severity == "MEDIUM"


def test_losing_a_post_quantum_algorithm_outranks_gaining_one():
    before = _hsm(supported_algorithms=["RSA-2048", "ML-KEM-768"])
    changes = diff(before, _hsm(supported_algorithms=["RSA-2048"]))
    removed = next(change for change in changes if change.event_type == "PQC_CAPABILITY_REMOVED")
    assert removed.detail["algorithms"] == ["ML-KEM-768"]
    assert removed.severity == "HIGH"


def test_spelling_differences_are_not_a_change():
    assert diff(_hsm(), _hsm(supported_algorithms=["rsa 2048", "RSA-3072",
                                                   "ecdsa-p256", "aes_256"])) == []


def test_tpm_firmware_moves_under_its_own_event():
    before = _hsm(device_type="server", tpm={"present": True, "firmware": "8.63"})
    after = _hsm(device_type="server", tpm={"present": True, "firmware": "8.70"})
    kinds = [change.event_type for change in diff(before, after)]
    assert "FIRMWARE_CHANGED" in kinds and "TPM_FIRMWARE_CHANGED" in kinds


def test_no_change_produces_no_events():
    assert diff(_hsm(), _hsm()) == []
    assert summarise([])["total"] == 0


def test_diffing_two_different_assets_is_refused():
    with pytest.raises(ValueError, match="two assets are not one asset"):
        diff(_hsm(), _hsm(asset_id="hsm-02"))


def test_summary_separates_the_pqc_signal():
    before = _hsm()
    after = _hsm(firmware={"HSM": "8.4.0"},
                 supported_algorithms=[*_hsm()["supported_algorithms"], "ML-KEM-768"])
    summary = summarise(diff(before, after))
    assert summary["total"] == 4
    assert summary["pqc_changes"] == 3
    assert summary["by_event"]["PQC_CAPABILITY_ADDED"] == 1
    assert summary["highest_severity"] == "HIGH"


def test_the_pqc_family_list_covers_the_standards():
    for name in ("ML-KEM", "ML-KEM-768", "ML-DSA", "ML-DSA-65", "SLH-DSA-128S".replace("128S", "SHA2-128S")):
        assert name in PQC_ALGORITHMS


# ------------------------------------------------- the guard must survive python -O


def test_the_secret_guard_is_not_an_assertion():
    """`python -O` strips asserts — a security boundary cannot be one.

    Run the scanners in a subprocess with -O, where an `assert`-based guard would
    silently disappear and the HSM scan would return key material in a BOM.
    """
    code = (
        "import sys;"
        f"sys.path.insert(0, {str(ROOT / 'services' / 'universal_vendor')!r});"
        "from universal_vendor.hardware.hsm_hw import HsmHardwareScanner;"
        "from universal_vendor.hardware.safety import SecretMaterialRefused;"
        "refused = 0\n"
        "try:\n"
        "    HsmHardwareScanner().scan({'model': 'X', 'private_key': 'k'})\n"
        "except SecretMaterialRefused:\n"
        "    refused = 1\n"
        "print(refused)\n"
    )
    completed = subprocess.run([sys.executable, "-O", "-c", code], capture_output=True,
                               text=True, timeout=120,
                               env={**os.environ, "PYTHONPATH": str(ROOT / "services" / "universal_vendor")})
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] == "1", (
        "the guard did not refuse under -O: it is an assertion, not a boundary")
