"""Review item 8: a cipher suite is four decisions, not one string."""

from __future__ import annotations

import pytest

from cbom import cipher_suite as cs

TLS12 = "ECDHE-RSA-AES128-GCM-SHA256"
TLS13 = "TLS_AES_256_GCM_SHA384"


def test_a_tls12_suite_names_all_four_dimensions():
    body = cs.decompose(TLS12, tls_version="1.2")
    dims = body["dimensions"]
    assert dims["KEY_EXCHANGE"]["algorithm"] == "ECDHE"
    assert dims["KEY_EXCHANGE"]["evidence"] == "NAMED_IN_SUITE"
    assert dims["AUTHENTICATION"]["algorithm"] == "RSA"
    assert dims["ENCRYPTION"]["algorithm"] == "AES-128-GCM"
    assert dims["ENCRYPTION"]["parameters"] == {"key_size": 128, "mode": "GCM"}
    assert dims["HASH"]["algorithm"] == "SHA-256"
    assert body["not_named"] == []


def test_a_tls13_suite_names_two_dimensions_and_needs_the_handshake_for_the_rest():
    bare = cs.decompose(TLS13, tls_version="1.3")
    assert bare["not_named"] == ["KEY_EXCHANGE", "AUTHENTICATION"]
    assert bare["dimensions"]["KEY_EXCHANGE"]["algorithm"] is None
    assert "not RSA" in bare["dimensions"]["KEY_EXCHANGE"]["note"]
    full = cs.decompose(TLS13, tls_version="1.3", group="X25519",
                        signature_algorithm="ECDSA_SECP256R1_SHA256")
    assert full["dimensions"]["KEY_EXCHANGE"]["algorithm"] == "X25519"
    assert full["dimensions"]["KEY_EXCHANGE"]["evidence"] == "NEGOTIATED"
    assert full["dimensions"]["AUTHENTICATION"]["algorithm"] == "ECDSA-P256"
    assert full["not_named"] == []


def test_the_authentication_can_come_from_the_certificate_key():
    body = cs.decompose(TLS13, tls_version="1.3", group="X25519",
                        certificate_key={"algorithm": "RSA", "key_size": 2048})
    auth = body["dimensions"]["AUTHENTICATION"]
    assert auth["algorithm"] == "RSA" and auth["evidence"] == "NEGOTIATED"
    assert auth["method"] == "CERTIFICATE_KEY"
    assert auth["parameters"] == {"key_size": 2048}


def test_a_missing_dimension_produces_no_algorithm_fact():
    body = cs.decompose(TLS13, tls_version="1.3")
    algorithms = cs.to_algorithms(body)
    assert [fact["role"] for fact in algorithms["facts"]] == ["BULK", "HASH"]
    assert algorithms["absent"] == ["KEY_EXCHANGE", "AUTHENTICATION"]
    assert "left absent rather than assumed" in algorithms["statement"]


def test_the_negotiated_group_is_mapped_to_a_method():
    x25519 = cs.decompose(TLS13, tls_version="1.3", group="X25519")
    assert x25519["dimensions"]["KEY_EXCHANGE"]["method"] == "ECDHE"
    assert x25519["strength"]["forward_secrecy"] is True
    dhe = cs.decompose(TLS13, tls_version="1.3", group="ffdhe2048")
    assert dhe["dimensions"]["KEY_EXCHANGE"]["method"] == "DHE"
    assert dhe["dimensions"]["KEY_EXCHANGE"]["parameters"] == {"key_size": 2048}
    p384 = cs.decompose(TLS13, tls_version="1.3", group="secp384r1")
    assert p384["dimensions"]["KEY_EXCHANGE"]["algorithm"] == "ECDH-P384"


def test_an_unknown_group_is_unknown_rather_than_the_nearest_curve():
    body = cs.decompose(TLS13, tls_version="1.3", group="brainpoolP512r1")
    assert body["dimensions"]["KEY_EXCHANGE"]["evidence"] == "NOT_NAMED"
    assert "KEY_EXCHANGE" in body["not_named"]


def test_rsa_key_transport_is_named_and_has_no_forward_secrecy():
    body = cs.decompose("TLS_RSA_WITH_AES_128_GCM_SHA256", tls_version="1.2")
    key_exchange = body["dimensions"]["KEY_EXCHANGE"]
    assert key_exchange["method"] == "RSA_KEY_TRANSPORT"
    assert body["strength"]["forward_secrecy"] is False
    assert "certificate key protects the session" in body["strength"]["note"]


def test_a_cbc_suite_is_weak_and_a_rc4_suite_is_broken():
    cbc = cs.decompose("AES128-SHA", tls_version="1.2")
    assert cbc["dimensions"]["ENCRYPTION"]["algorithm"] == "AES-128-CBC"
    assert cbc["dimensions"]["ENCRYPTION"]["method"] == "ENCRYPT_THEN_MAC"
    assert cbc["dimensions"]["HASH"]["algorithm"] == "SHA-1"
    assert cbc["strength"]["rating"] == "WEAK"
    rc4 = cs.decompose("RC4-SHA", tls_version="1.2")
    assert rc4["strength"]["rating"] == "BROKEN"
    assert rc4["strength"]["broken_tokens"] == ["RC4"]
    des = cs.decompose("ECDHE-RSA-DES-CBC3-SHA", tls_version="1.2")
    assert des["dimensions"]["ENCRYPTION"]["algorithm"] == "3DES-CBC"
    assert des["strength"]["rating"] == "BROKEN"


def test_a_mode_the_table_does_not_model_stays_unknown():
    body = cs.decompose("TLS_AES_128_CCM_SHA256", tls_version="1.2")
    assert body["dimensions"]["ENCRYPTION"]["evidence"] == "NOT_NAMED"
    assert "ENCRYPTION" in body["not_named"]
    assert body["strength"]["rating"] == "UNKNOWN"


def test_an_unrecognised_suite_is_reported_rather_than_guessed():
    body = cs.decompose("FOO-BAR", tls_version="1.2")
    assert body["recognised"] is False
    assert body["strength"]["rating"] == "UNKNOWN"
    assert "not in the token table" in body["strength"]["note"]


def test_a_tls13_suite_is_recognised_from_its_name_when_no_version_is_supplied():
    body = cs.decompose(TLS13)
    assert body["modern"] is True
    assert body["not_named"] == ["KEY_EXCHANGE", "AUTHENTICATION"]


def test_the_trailing_hash_of_a_tls12_aead_suite_is_the_prf_only():
    body = cs.decompose(TLS12, tls_version="1.2")
    assert "PRF hash only" in body["dimensions"]["HASH"]["note"]
    cbc = cs.decompose("AES128-SHA", tls_version="1.2")
    assert "PRF hash only" not in cbc["dimensions"]["HASH"]["note"]


def test_a_suite_with_no_name_is_refused():
    with pytest.raises(ValueError, match="needs a cipher suite"):
        cs.decompose("   ")


def test_case_and_spacing_do_not_change_the_answer():
    body = cs.decompose("  tls_aes_256_gcm_sha384 ", tls_version="1.3")
    assert body["suite"] == "TLS_AES_256_GCM_SHA384"
    assert body["dimensions"]["ENCRYPTION"]["algorithm"] == "AES-256-GCM"


def test_the_statement_names_every_dimension_and_its_evidence():
    statement = cs.decompose(TLS13, tls_version="1.3", group="X25519")["statement"]
    assert "key_exchange=X25519 (negotiated)" in statement
    assert "authentication=unknown" in statement
    assert "encryption=AES-256-GCM (named_in_suite)" in statement
    assert "hash=SHA-384 (named_in_suite)" in statement


def test_a_handshake_batch_decomposes_each_row_and_counts_the_ratings():
    body = cs.handshake([
        {"endpoint": "payments:443", "cipher_suite": TLS13, "tls_version": "1.3",
         "group": "X25519", "signature_algorithm": "ECDSA_SECP256R1_SHA256",
         "evidence_id": "NET-1"},
        {"endpoint": "legacy:443", "cipher_suite": "RC4-SHA", "tls_version": "1.2",
         "evidence_id": "NET-2"},
    ])
    assert len(body["handshakes"]) == 2
    assert body["endpoints"] == ["legacy:443", "payments:443"]
    assert body["ratings"] == {"BROKEN": 1, "STRONG": 1}
    by_endpoint = {row["endpoint"]: row for row in body["handshakes"]}
    assert by_endpoint["payments:443"]["evidence_ids"] == ["NET-1"]
    assert by_endpoint["legacy:443"]["evidence_ids"] == ["NET-2"]
    assert "decomposed into four dimensions" in body["statement"]


def test_a_handshake_row_with_no_suite_is_refused_not_decomposed():
    body = cs.handshake([{"endpoint": "x:443"}, {"endpoint": "y:443",
                                                 "cipher_suite": "FOO"}])
    assert body["refused"][0]["reason"] == "a decomposition needs a cipher suite"
    assert len(body["handshakes"]) == 1
    assert "1 refused" in body["statement"]


def test_algorithm_facts_use_the_roles_the_cbom_already_understands():
    body = cs.to_algorithms(cs.decompose(TLS13, tls_version="1.3", group="X25519",
                                         certificate_key={"algorithm": "RSA",
                                                          "key_size": 2048}))
    roles = {fact["role"]: fact["algorithm"] for fact in body["facts"]}
    assert roles == {"KEY_EXCHANGE": "X25519", "SIGNATURE": "RSA",
                     "BULK": "AES-256-GCM", "HASH": "SHA-384"}
    assert body["from_handshake"] == 2 and body["from_suite"] == 2
    assert all(fact["class"] == "NETWORK_OBSERVED" for fact in body["facts"])


def test_a_document_that_is_not_a_decomposition_is_refused_downstream():
    with pytest.raises(ValueError, match="not a"):
        cs.to_algorithms({"dimensions": {}})
    with pytest.raises(ValueError, match="not a"):
        cs.frontier({"suite": TLS13})


def test_the_migration_frontier_names_the_dimensions_to_replace():
    body = cs.frontier(cs.decompose(TLS13, tls_version="1.3", group="X25519",
                                    signature_algorithm="ECDSA_SECP256R1_SHA256"))
    rows = {row["dimension"]: row for row in body["dimensions"]}
    assert rows["KEY_EXCHANGE"]["quantum_relevant"] is True
    assert rows["AUTHENTICATION"]["quantum_relevant"] is True
    assert rows["ENCRYPTION"]["quantum_relevant"] is False
    assert "post-quantum" in rows["KEY_EXCHANGE"]["next_action"]
    assert "no asymmetric replacement" in rows["ENCRYPTION"]["next_action"]
    bare = cs.frontier(cs.decompose(TLS13, tls_version="1.3"))
    unknown = {row["dimension"]: row for row in bare["dimensions"]}
    assert "collect the handshake context" in unknown["AUTHENTICATION"]["next_action"]


def test_the_model_states_what_one_handshake_cannot_prove():
    body = cs.decompose(TLS12, tls_version="1.2")
    assert any("only one the endpoint accepts" in line for line in cs.NOT_PROVEN)
    assert any("forward secrecy is a property" in line for line in cs.NOT_PROVEN)
    assert "attack" not in body["statement"].lower()
    assert len(cs.NOT_PROVEN) >= 4
