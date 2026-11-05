"""The HOST plane: a configuration file reaches the estate as a declaration.

Before this plane existed the host collector's ``TLS_CONFIGURATION`` fact lived and died
inside the host BOM. That made the "which client would a raised floor strand?" question
unanswerable in the negative, which downstream reads as "nothing would break" — the one
reading a check must never manufacture. These tests follow one real stored host snapshot
from intake to the twin's declared bucket.
"""

from api import estate_discovery
from db.tenancy import tenant_scope
from shared_models import estate_twin as twin
from shared_models.estate_graph import build_graph
from test_assurance_workflows import assured as assured  # noqa: F401 — the shared fixture
from test_software_supply_chain_api import banks as banks  # noqa: F401 — assured depends on it
from test_host_evidence import setup, submit


def _stored_host_snapshot(assured):
    clients, db, identifier, _body, snapshot = setup(assured)
    result = submit(clients, identifier, snapshot)
    assert result.status_code == 201, result.text
    return db


def _graph(plane):
    return build_graph(
        {
            "estate": "test",
            "scope": "host-plane",
            "assets": plane["assets"],
            "evidence": plane["evidence"],
            "relationships": [],
        }
    )


def test_a_stored_tls_configuration_reaches_the_estate_as_a_declaration(assured):
    db = _stored_host_snapshot(assured)

    with tenant_scope("a"):
        plane = estate_discovery.collect_host(db)

    assert plane["plane"] == "HOST"
    assert plane["collected"] == 1
    assert plane["note"] is None
    facts = plane["evidence"][0]["facts"]
    # what the config allows, as collected
    assert facts["protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert facts["cipher_suites"] == ["AES256-GCM-SHA384"]
    # and the basis travels with it: a declaration is not a negotiation
    assert facts["local_basis"] == "DECLARED"
    assert "not what it did negotiate" in facts["layer_note"]
    assert plane["assets"][0]["name"] == "payments-1"


def test_the_twin_reads_that_declaration_on_its_own_axis(assured):
    db = _stored_host_snapshot(assured)
    with tenant_scope("a"):
        plane = estate_discovery.collect_host(db)

    # the config permits TLSv1.2 and TLSv1.3; under a TLSv1.3 floor the TLSv1.2
    # permission is still there, so the declaration is below the floor
    result = twin.protocol_floor(_graph(plane), {"floor": "TLSv1.3"})

    declared = result["declared"]
    assert declared["counts"]["assets_with_declaration"] == 1
    row = declared["declares_below_floor"][0]
    assert row["asset_name"] == "payments-1"
    assert row["declared"] == ["TLSV1.2", "TLSV1.3"]
    assert row["basis"] == "DECLARED"
    # at TLSv1.2 nothing in the declaration is below the floor
    assert twin.protocol_floor(_graph(plane), {"floor": "TLSv1.2"})["declared"]["counts"]["declares_below_floor"] == 0
    # nothing negotiated anything: this is a declaration, and the check says so
    assert result["counts"]["protocol_records"] == 0
    assert result["status"] == "INSUFFICIENT_EVIDENCE"


def test_a_config_with_a_directive_this_build_cannot_read_is_partial_not_permissive(assured):
    clients, db, identifier, _body, snapshot = setup(assured)
    config = next(item for item in snapshot["manifest"]["inputs"] if item["kind"] == "NGINX_TLS_CONFIG")
    # an include is a directive the parser cannot follow: the config declares *something*
    receipt = next(item for item in snapshot["receipts"] if item["input_id"] == config["input_id"])
    receipt["facts"][0]["unparsed_directives"] = True
    assert submit(clients, identifier, snapshot).status_code == 201

    with tenant_scope("a"):
        plane = estate_discovery.collect_host(db)

    assert plane["evidence"][0]["facts"]["unparsed_directives"] is True


def test_no_stored_host_snapshot_is_reported_as_not_observed_not_as_a_permissive_estate(assured):
    _clients, db, _tmp = assured

    with tenant_scope("a"):
        plane = estate_discovery.collect_host(db)

    assert plane["collected"] == 0
    assert "NOT_OBSERVED" in plane["note"]
    assert "not 'no TLS configuration'" in plane["note"]
