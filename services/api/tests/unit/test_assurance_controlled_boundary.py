from test_software_supply_chain_api import banks as banks
from test_execution_controls import controlled as controlled, configure
from test_assurance_workflows import manifest
from db.models.assurance import AssuranceRevision

P = "/api/v1/assurance"


def test_assurance_metadata_requires_region_policy_and_never_enables_legacy_acquisition(controlled, monkeypatch):
    state = controlled
    a = state["clients"]["bank_a"]
    assert a.post(P + "/registers", json=manifest()).status_code == 409
    assert state["db"].query(AssuranceRevision).count() == 0
    configure(state)
    created = a.post(P + "/registers", json=manifest())
    assert created.status_code == 201, created.text
    rid = created.json()["subject_id"]
    assert a.get(P + f"/registers/{rid}/coverage").status_code == 200
    assert a.post("/api/v1/network/ssh-scan", json={"hosts": ["10.1.2.3"]}).status_code == 409
    monkeypatch.setenv("CRYPTOSCAN_EVIDENCE_REGION", "other-region")
    assert a.get(P + f"/registers/{rid}/coverage").status_code == 409
    assert a.post(P + "/registers", json=manifest()).status_code == 409
    assert state["db"].query(AssuranceRevision).count() == 1


def test_operator_inbox_is_metadata_only_and_region_admitted(controlled, monkeypatch):
    state = controlled
    a = state["clients"]["bank_a"]
    assert a.get(P + "/operator-decisions").status_code == 409
    configure(state)
    result = a.get(P + "/operator-decisions")
    assert result.status_code == 200, result.text
    assert result.json()["estate_id"] == "a"
    assert a.post("/api/v1/network/tls-scan", json={"hosts": ["bank.example:443"]}).status_code == 409
    monkeypatch.setenv("CRYPTOSCAN_EVIDENCE_REGION", "wrong-region")
    assert a.get(P + "/operator-decisions").status_code == 409
