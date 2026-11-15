"""Stack status honesty tests (deploy/stack/): UNCONFIGURED claims
nothing, UNREACHABLE is named — never a quiet success — and a REACHABLE
socket is reported as reachability, never as health or qualification.
"""

from __future__ import annotations


from shared_config.stack_settings import (
    BACKENDS, REACHABLE, UNCONFIGURED, UNREACHABLE, probe, settings,
)


def test_every_platform_table_backend_has_a_named_setting():
    names = {(s.name, s.role) for s in settings({})}
    for name, role, var in BACKENDS:
        assert (name, role) in names
        assert var


def test_unconfigured_backends_claim_nothing():
    status = probe(environ={})
    assert status.checked, "every backend is checked"
    for row in status.checked:
        assert row["status"] == UNCONFIGURED
        assert "nothing is claimed" in row["detail"]
    assert "not connected backends" in status.note


def test_a_failed_probe_is_named_unreachable_never_a_quiet_success():
    def refuse(host, port, timeout):
        raise ConnectionRefusedError(111, "refused")

    status = probe(environ={"DATABASE_URL": "postgresql://db-host:5432/cryptoscan"},
                   connect=refuse)
    row = status.checked[0]
    assert row["status"] == UNREACHABLE
    assert "never drawn as a quiet success" in row["detail"]


def test_a_successful_probe_is_reachability_not_a_qualification():
    calls = []

    def ok(host, port, timeout):
        calls.append((host, port))

    status = probe(environ={
        "NEO4J_URI": "bolt://graph-host:7687",
        "KAFKA_BOOTSTRAP_SERVERS": "kafka-a:9092,kafka-b:9092",
    }, connect=ok)
    neo4j, kafka = status.checked[1], status.checked[4]
    assert neo4j["status"] == REACHABLE
    assert "not a health or qualification claim" in neo4j["detail"]
    assert calls == [("graph-host", 7687), ("kafka-a", 9092)], \
        "a multi-broker string probes its first broker"
    assert kafka["status"] == REACHABLE


def test_an_unparseable_endpoint_is_unreachable_with_a_reason():
    status = probe(environ={"VAULT_ADDR": "not a url"},
                   connect=lambda h, p, t: None)
    row = next(r for r in status.checked if r["name"] == "Vault")
    assert row["status"] == UNREACHABLE
    assert "no probeable host" in row["detail"]
