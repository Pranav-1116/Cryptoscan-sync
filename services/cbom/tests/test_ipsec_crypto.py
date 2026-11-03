"""Guide 162 tests — IPsec as two security associations, with PFS as its own answer."""

from __future__ import annotations

import pytest

from cbom import ipsec_crypto as ic

DC = {
    "peer": "dc1.fw.bank.example", "local": "10.1.0.1", "ike_version": "IKEv2",
    "authentication": "CERTIFICATE", "evidence_id": "VPN-1",
    "observed_at": "2026-11-01T00:00:00Z", "source": "firewall-api",
    "ike": {"proposal": ["AES256", "SHA256", "DH14"]},
    "child": {"proposal": ["AES256", "SHA256"], "pfs": "DH14", "lifetime": 3600},
}
BRANCH = {
    "peer": "branch42.fw.bank.example", "ike_version": "1", "authentication": "PSK",
    "mode": "AGGRESSIVE", "evidence_id": "VPN-2",
    "ike": {"proposal": ["3DES", "SHA1", "DH2"]},
    "child": {"proposal": ["3DES", "MD5"]},
}


def _ratings(body):
    return {problem["rating"] for problem in body["problems"]}


def test_a_tunnel_is_two_security_associations():
    body = ic.tunnel(DC)
    assert {row["phase"] for row in body["ike_proposal"]} == {"IKE"}
    assert {row["phase"] for row in body["child_proposal"]} == {"CHILD"}
    assert body["problems"] == []
    assert body["worst"] is None


def test_the_phase_one_group_is_not_forward_secrecy_for_data():
    body = ic.tunnel({**DC, "child": {"proposal": ["AES256"]}})
    assert body["forward_secrecy_for_data"] is False
    assert "NO_FORWARD_SECRECY" in _ratings(body)


def test_a_modern_proposal_without_pfs_is_still_flagged():
    body = ic.tunnel({"peer": "partner.example", "ike_version": "IKEv2",
                      "authentication": "PSK", "evidence_id": "VPN-3",
                      "ike": {"proposal": ["AES128", "SHA1", "DH19"]},
                      "child": {"proposal": ["AES128GCM16"]}})
    assert body["worst"] == "NO_FORWARD_SECRECY"
    assert body["child_proposal"][0]["rating"] == "ACCEPTABLE"


def test_a_weak_pfs_group_is_a_finding_on_its_own():
    body = ic.tunnel({**DC, "child": {"proposal": ["AES256"], "pfs": "DH2"}})
    assert "WEAK" in _ratings(body)
    assert body["pfs"]["group_bits"] == 1024


def test_a_valid_pfs_group_is_not_a_problem():
    body = ic.tunnel({**DC, "child": {"proposal": ["AES256"], "pfs": "DH19"}})
    assert body["problems"] == []


def test_ikev1_aggressive_mode_with_psk_is_an_offline_attack():
    body = ic.tunnel(BRANCH)
    assert "OFFLINE_PSK_ATTACK" in _ratings(body)
    assert body["worst"] == "OFFLINE_PSK_ATTACK"


def test_the_same_psk_under_ikev2_is_not_that_finding():
    body = ic.tunnel({**BRANCH, "ike_version": "IKEv2"})
    assert "OFFLINE_PSK_ATTACK" not in _ratings(body)


def test_aggressive_mode_is_not_an_ikev2_mode():
    body = ic.tunnel({**DC, "mode": "AGGRESSIVE"})
    assert body["mode"] == "IKEV2_SA_INIT"


def test_null_encryption_is_reported_and_not_scored_safe():
    body = ic.tunnel({**DC, "child": {"proposal": ["ENCR_NULL", "SHA256"],
                                     "pfs": "DH14"}})
    assert "NO_CONFIDENTIALITY" in _ratings(body)
    assert ic.transform("ENCR_NULL", phase="CHILD")["null_encryption"] is True


def test_a_tunnel_with_only_phase_one_says_so():
    assert "NO_CHILD_SA" in _ratings(ic.tunnel({**DC, "child": {}}))


def test_an_unknown_ike_version_is_refused():
    with pytest.raises(ValueError, match="unknown"):
        ic.tunnel({**DC, "ike_version": "3"})


def test_an_sa_without_evidence_is_refused():
    row = {key: value for key, value in DC.items() if key != "evidence_id"}
    with pytest.raises(ValueError, match="no evidence id"):
        ic.tunnel(row)


def test_a_tunnel_without_a_peer_is_refused():
    with pytest.raises(ValueError, match="needs a peer"):
        ic.tunnel({**DC, "peer": None})


def test_a_phase_outside_the_two_is_refused():
    with pytest.raises(ValueError, match="is not one of"):
        ic.transform("AES256", phase="PHASE3")


def test_an_unknown_transform_is_unknown_and_not_weak():
    assert ic.transform("some-future-transform", phase="CHILD")["rating"] == "UNKNOWN"


@pytest.mark.parametrize("name,bits", [("DH14", 2048), ("DH1", 768), ("DH5", 1536)])
def test_a_group_carries_its_size(name, bits):
    assert ic.transform(name, phase="IKE")["group_bits"] == bits


def test_the_estate_lists_peers_without_pfs_and_refusals():
    body = ic.estate([DC, BRANCH, {"ike_version": "2"}, "nonsense"])
    assert body["without_pfs"] == ["branch42.fw.bank.example"]
    assert body["ikev1"] == ["branch42.fw.bank.example"]
    assert len(body["refused"]) == 2
    assert "1 without a PFS group" in body["statement"]


def test_facts_carry_phase_role_and_evidence():
    body = ic.to_algorithms(ic.estate([DC, BRANCH]))
    assert {fact["role"] for fact in body["facts"]} == {
        "KEY_EXCHANGE", "PRF_AND_INTEGRITY", "BULK"}
    assert all(fact["protocol"] == "IPSEC" and fact["phase"] in {"IKE", "CHILD"}
               and fact["evidence_ids"] for fact in body["facts"])


def test_a_symmetric_cipher_is_never_quantum_vulnerable():
    body = ic.to_algorithms(ic.estate([DC, BRANCH]))
    assert not any(fact["quantum_vulnerable"] for fact in body["facts"]
                   if fact["algorithm"].startswith(("aes", "3des")))
    assert "dh2" in body["quantum_vulnerable"]


def test_a_foreign_document_is_refused_by_to_algorithms():
    with pytest.raises(ValueError, match="not a"):
        ic.to_algorithms({"tunnels": []})


def test_the_summary_repeats_the_worst_finding_per_peer():
    summary = ic.summary(ic.estate([DC, BRANCH]))
    assert summary["worst"] == {"branch42.fw.bank.example": "OFFLINE_PSK_ATTACK"}
    assert summary["tunnels"] == 2
