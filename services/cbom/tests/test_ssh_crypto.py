"""Review item 13: SSH negotiates four things, two of them per direction."""

from __future__ import annotations

import pytest

from cbom import ssh_crypto as sc

MODERN = {
    "host": "jump.bank.example", "port": 22, "banner": "SSH-2.0-OpenSSH_9.6",
    "evidence_id": "SSH-1", "observed_at": "2026-11-01T00:00:00Z",
    "source": "ssh-probe", "host_key_fingerprint": "SHA256:abc",
    "negotiated": {"kex": "curve25519-sha256", "host_key": "ssh-ed25519",
                   "cipher_client_to_server": "chacha20-poly1305@openssh.com",
                   "cipher_server_to_client": "chacha20-poly1305@openssh.com"},
}
LEGACY = {
    "host": "legacy.bank.example", "evidence_id": "SSH-2",
    "negotiated": {"kex": "diffie-hellman-group1-sha1", "host_key": "ssh-rsa",
                   "cipher": "3des-cbc", "mac": "hmac-md5"},
}


def test_a_session_is_four_negotiations_not_one():
    body = sc.session(MODERN)
    assert body["kex"]["algorithm"] == "curve25519-sha256"
    assert body["host_key"]["algorithm"] == "ssh-ed25519"
    assert body["directions"]["CLIENT_TO_SERVER"]["cipher"]["algorithm"] == \
        "chacha20-poly1305@openssh.com"
    assert set(body["directions"]) == {"CLIENT_TO_SERVER", "SERVER_TO_CLIENT"}
    assert body["state"] == "NEGOTIATED"
    assert body["private_material"] == "NOT_STORED"


def test_the_two_directions_are_reported_separately():
    split = {**MODERN, "negotiated": {**MODERN["negotiated"],
                                      "cipher_server_to_client": "aes128-cbc"}}
    body = sc.session(split)
    assert body["asymmetric"] is True
    assert body["directions"]["SERVER_TO_CLIENT"]["cipher"]["algorithm"] == "aes128-cbc"
    assert "the weaker one decides" in body["statement"]
    assert body["problems"][0] == {"dimension": "CIPHER",
                                   "direction": "SERVER_TO_CLIENT",
                                   "algorithm": "aes128-cbc", "rating": "DEPRECATED",
                                   "detail": "CBC mode with no authenticated encryption"}


def test_an_aead_cipher_needs_no_separate_mac():
    body = sc.session({**MODERN, "negotiated": {**MODERN["negotiated"],
                                                "mac_client_to_server": "hmac-md5"}})
    assert body["directions"]["CLIENT_TO_SERVER"]["mac"] is None
    assert body["problems"] == []
    cbc = sc.session({**MODERN, "negotiated": {**MODERN["negotiated"],
                                               "cipher_client_to_server": "aes256-cbc",
                                               "mac_client_to_server": "hmac-md5"}})
    assert cbc["directions"]["CLIENT_TO_SERVER"]["mac"]["algorithm"] == "hmac-md5"


def test_ssh_rsa_is_sha1_and_is_not_the_same_as_rsa_sha2():
    legacy = sc.algorithm("ssh-rsa", "HOST_KEY")
    assert legacy["rating"] == "DEPRECATED" and "SHA-1" in legacy["reason"]
    modern = sc.algorithm("rsa-sha2-256", "HOST_KEY")
    assert modern["rating"] == "ACCEPTABLE"
    assert modern["quantum_vulnerable"] == "RSA host key"


def test_deprecated_algorithms_are_rated_by_why_they_are_deprecated():
    assert sc.algorithm("arcfour256", "CIPHER")["rating"] == "BROKEN"
    assert sc.algorithm("hmac-md5", "MAC")["rating"] == "BROKEN"
    assert sc.algorithm("3des-cbc", "CIPHER")["rating"] == "BROKEN"
    assert sc.algorithm("diffie-hellman-group1-sha1", "KEX")["rating"] == "BROKEN"
    assert sc.algorithm("hmac-sha2-256", "MAC")["rating"] == "ACCEPTABLE"


def test_an_unknown_algorithm_is_not_called_broken():
    body = sc.algorithm("some-future-kex@example.com", "KEX")
    assert body["rating"] == "ACCEPTABLE" and body["reason"] is None


def test_a_dimension_outside_the_four_is_refused():
    with pytest.raises(ValueError, match="is not one of"):
        sc.algorithm("x", "COMPRESSION")
    with pytest.raises(ValueError, match="needs a name"):
        sc.algorithm("", "KEX")


def test_a_session_needs_a_host_and_evidence():
    with pytest.raises(ValueError, match="needs a host"):
        sc.session({"evidence_id": "E-1"})
    with pytest.raises(ValueError, match="no evidence id"):
        sc.session({"host": "h"})
    with pytest.raises(ValueError, match="must be an object"):
        sc.session("not a session")


def test_an_estate_counts_the_deprecated_algorithms_and_who_uses_them():
    body = sc.estate([MODERN, LEGACY])
    assert body["hosts"] == ["jump.bank.example", "legacy.bank.example"]
    assert set(body["deprecated"]) == {"diffie-hellman-group1-sha1", "ssh-rsa",
                                       "3des-cbc", "hmac-md5"}
    assert body["deprecated"]["ssh-rsa"] == ["legacy.bank.example"]
    assert "4 deprecated algorithm(s) in use" in body["statement"]


def test_a_refused_session_is_listed_rather_than_dropped():
    body = sc.estate([MODERN, {"host": "x"}, "nonsense"])
    assert len(body["refused"]) == 2
    assert "2 session(s) refused" in body["statement"]


def test_facts_carry_the_roles_the_rest_of_the_platform_uses():
    body = sc.to_algorithms(sc.estate([MODERN]))
    roles = {(fact["host"], fact["role"]): fact["algorithm"] for fact in body["facts"]}
    assert roles[("jump.bank.example", "KEY_EXCHANGE")] == "curve25519-sha256"
    assert roles[("jump.bank.example", "SIGNATURE")] == "ssh-ed25519"
    assert "AES-256-GCM" not in " ".join(roles.values())
    assert "chacha20-poly1305@openssh.com" in {fact["algorithm"] for fact in body["facts"]}
    assert all(fact["protocol"] == "SSH" and fact["class"] == "NETWORK_OBSERVED"
               for fact in body["facts"])


def test_quantum_vulnerable_algorithms_are_named_without_a_migration_verdict():
    body = sc.to_algorithms(sc.estate([LEGACY]))
    assert body["quantum_vulnerable"] == ["ssh-rsa"]
    modern = sc.to_algorithms(sc.estate([MODERN]))
    assert modern["quantum_vulnerable"] == ["curve25519-sha256", "ssh-ed25519"]


def test_the_symmetric_ciphers_are_not_called_quantum_vulnerable():
    body = sc.algorithm("aes256-gcm@openssh.com", "CIPHER")
    assert body["quantum_vulnerable"] is None
    assert body["aead"] is True


def test_the_summary_states_what_one_session_cannot_prove():
    body = sc.summary(sc.estate([MODERN, LEGACY]))
    assert body["sessions"] == 2 and body["hosts"] == 2
    assert any("only one the server accepts" in line for line in body["not_proven"])
    assert any("known_hosts" in line for line in body["not_proven"])


def test_a_document_that_is_not_an_ssh_estate_is_refused_downstream():
    with pytest.raises(ValueError, match="not a"):
        sc.to_algorithms({"sessions": []})


def test_the_banner_is_recorded_and_never_judged():
    body = sc.session({**MODERN, "banner": "SSH-2.0-OpenSSH_7.4"})
    assert body["banner"] == "SSH-2.0-OpenSSH_7.4"
    assert all("banner" not in problem for problem in body["problems"])
