"""TLS on crypto-bearing ports — a real extension that must not overclaim.

The rule these tests defend: a handshake on 5671 proves TLS on 5671. It does not
prove AMQP channel encryption, and no result from this module may suggest it did.
"""

from __future__ import annotations

import pytest

from network_scanner.probing import port_protocols as P


def test_known_ports_are_classified_with_their_source():
    amqps = P.classify_port(5671)
    assert amqps["protocol"] == "amqp"
    assert amqps["classification"] == P.CLASSIFICATION_IANA
    assert "IANA" in amqps["source"]
    assert amqps["plaintext_variant"] is False

    kafka = P.classify_port(9093)
    # a vendor convention, labelled as such rather than as a registry fact
    assert kafka["classification"] == P.CLASSIFICATION_CONVENTION
    assert P.classify_port(65000) is None


def test_plaintext_convention_ports_are_named_as_such():
    assert P.classify_port(5672)["plaintext_variant"] is True
    assert P.classify_port(1883)["plaintext_variant"] is True
    assert P.classify_port(5671)["plaintext_variant"] is False


def test_plan_probes_keeps_unclassified_endpoints_instead_of_dropping_them():
    plan = P.plan_probes(
        [
            {"host": "broker-1", "port": 5671},
            {"host": "kafka-1", "port": 9093},
            {"host": "mystery", "port": 12345},
            {"host": "", "port": 636},
            {"host": "db-1", "port": "nope"},
        ]
    )
    assert plan["counts"] == {"probes": 2, "unclassified": 1}
    assert plan["unclassified"] == [{"host": "mystery", "port": 12345}]
    assert {probe["port"] for probe in plan["probes"]} == {5671, 9093}
    assert all(probe["probe"] == "TLS_HANDSHAKE" for probe in plan["probes"])
    assert "not a claim that the probe spoke that protocol" in plan["note"]


def test_a_successful_handshake_is_tls_evidence_only():
    result = P.interpret(5671, {"version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"})
    assert result["state"] == "TLS_OBSERVED"
    assert result["tls"]["version"] == "TLSv1.3"
    # the message layer is explicitly out of scope
    assert result["app_protocol_spoken"] is False
    assert "channel encryption" in result["cannot_claim"]
    assert "AMQP" in result["message_layer"]


def test_no_tls_is_an_observation_not_a_probe_failure():
    plain = P.interpret(5672, {"error": "handshake refused"})
    assert plain["state"] == "NO_TLS"
    assert "observation about the deployment" in plain["reason"]

    missing = P.interpret(636, None)
    assert missing["state"] == "NOT_ATTEMPTED"


def test_unclassified_port_is_not_guessed():
    result = P.interpret(2222, {"version": "TLSv1.2"})
    assert result["state"] == "UNCLASSIFIED"
    assert result["reason"]
    assert result["app_protocol_spoken"] is False


def test_coverage_table_states_its_claim_and_its_split():
    doc = P.coverage()
    assert doc["counts"]["ports"] == len(P.KNOWN_TLS_PORTS)
    assert doc["counts"]["iana"] + doc["counts"]["convention"] == doc["counts"]["ports"]
    assert "No message-layer protocol is spoken" in doc["claim"]


def test_every_entry_carries_a_message_layer_and_a_source():
    for entry in P.KNOWN_TLS_PORTS:
        assert entry["source"], entry["port"]
        assert entry["message_layer"], entry["port"]
        assert entry["classification"] in {P.CLASSIFICATION_IANA, P.CLASSIFICATION_CONVENTION}
    ports = [entry["port"] for entry in P.KNOWN_TLS_PORTS]
    assert len(ports) == len(set(ports))


@pytest.mark.parametrize("port", sorted(P.PORT_INDEX))
def test_interpret_is_total_over_the_table(port):
    result = P.interpret(port, {"version": "TLSv1.2"})
    assert result["state"] == "TLS_OBSERVED"
    assert result["app_protocol_spoken"] is False
