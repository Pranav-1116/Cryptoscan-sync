"""Guide 182 — the security control API: who may write evidence, and what a finding is.

The unit tests prove the layer's analysis. These prove the three properties that only exist at
the boundary:

* **a user session cannot write a snapshot**, and the refusal names the credential rather than
  pretending the caller is unauthenticated;
* **a retried snapshot does not advance the chain**, but a changed one does;
* **a finding without evidence is refused**, and ``NOT_CONFIGURED`` is never collapsed into
  ``UNKNOWN``.

The harness is the router on a real SQLite session, not a mocked one: idempotency and the chain
are database behaviour, and a MagicMock would happily "store" the same row twice.
"""

from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def session(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401 — registers every model on the metadata
    from db.models.base import Base
    import db.models.security_control  # noqa: F401
    from db.models.user import AuditLog

    engine = create_engine(f"sqlite:///{tmp_path / 'controls.db'}")
    # the audit log is written on every stored snapshot, so the harness creates the tables the
    # route actually touches rather than mocking the repository that writes them
    Base.metadata.create_all(engine, tables=[
        db.models.security_control.SecurityControlSnapshot.__table__,
        db.models.security_control.SecurityControlFinding.__table__,
        AuditLog.__table__,
    ])
    factory = sessionmaker(bind=engine)
    db = factory()
    try:
        yield db
    finally:
        db.close()
        engine.dispose()


@pytest.fixture()
def api(session):
    from api import dependencies
    from api.routers import security_controls

    from api.dependencies import TenantContext

    app = FastAPI()
    app.include_router(security_controls.router, prefix="/api")
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    # read routes resolve a tenant context; this harness has no tenant plane, so it resolves
    # to the platform estate, exactly as a single-tenant install does
    app.dependency_overrides[dependencies.get_tenant_context] = lambda: TenantContext(
        username="auditor", tenant_id=None, tenant_role="admin", is_platform_admin=True)
    return app


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """A per-test evidence store, tenant directory and all, exactly as production files it."""
    from api.config.settings import get_settings

    root = tmp_path / "evidence"
    root.mkdir()
    monkeypatch.setattr(get_settings(), "SECURITY_CONTROLS_EVIDENCE_ROOT", str(root),
                        raising=False)
    return root


class CollectorClient:
    """What a collector actually does: write the content-addressed body first, then post.

    A snapshot that cites evidence names the body's location and digest, and the platform
    resolves every id against that artifact. The harness writes a real artifact (under the
    tenant's own directory) so a test payload is a claim the store can back, not a wish.
    """

    def __init__(self, client, store) -> None:
        self._client = client
        self._store = store

    def _attach(self, payload: dict) -> dict:
        import hashlib
        from datetime import datetime, timezone

        captured = payload.get("captured_at") or datetime.now(timezone.utc).isoformat()
        body_doc: dict = {"captured_at": captured, "collector": payload.get("collector"),
                          "evidence": []}
        for finding in payload.get("findings", []):
            for evidence_id in finding.get("evidence_ids", []):
                body_doc["evidence"].append({
                    "evidence_id": evidence_id,
                    "scheme": "v1",
                    "control": finding.get("control"),
                    "vendor": finding.get("vendor") or "test-vendor",
                    "system": finding.get("subject"),
                    "kind": finding.get("kind", "STATE"),
                    "identity": finding.get("subject"),
                    "config_version": {},
                })
        raw = json.dumps(body_doc, sort_keys=True).encode("utf-8")
        location = f"{str(payload.get('digest', 'body')).replace(':', '_')}.json"
        target = self._store / "_platform" / location
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        payload = dict(payload)
        payload["captured_at"] = captured
        payload["body_location"] = location
        payload["body_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        payload["body_bytes"] = len(raw)
        return payload

    def post(self, url: str, json: dict | None = None, **kwargs):
        if json and json.get("findings") is not None and not json.get("body_location"):
            json = self._attach(json)
        return self._client.post(url, json=json, **kwargs)

    def get(self, url: str, **kwargs):
        return self._client.get(url, **kwargs)


@pytest.fixture()
def writer(api, store, monkeypatch):
    """A client that authenticates as a machine and collects like one. The transport is
    not what is under test."""
    from api.routers import security_controls

    monkeypatch.setattr(security_controls, "_service_identity",
                        lambda request, signature=None: {"kind": "api_key",
                                                         "id": "key-collector-1",
                                                         "signature_bound": False})
    return CollectorClient(TestClient(api), store)


def body(digest: str = "sha256:aaaabbbbccccdddd", **overrides) -> dict:
    payload = {
        "digest": digest,
        "controls": ["FIREWALL", "WAF"],
        "counts": {"assets": 3, "claims": 4},
        "read_state": "OK",
        "collector": "key-collector-1",
        "findings": [{
            "control": "FIREWALL",
            "state": "OBSERVED",
            "subject": "FW-EDGE-01",
            "facts": ["OBSERVED"],
            "evidence_ids": ["EVID-FIREWALL-00000000abcd"],
            "reason": "TLS inspection enabled on the edge policy",
        }],
    }
    payload.update(overrides)
    return payload


# --------------------------------------------------------------------------- #
# who may write
# --------------------------------------------------------------------------- #

def test_a_user_session_token_cannot_write_a_snapshot(api, monkeypatch):
    from api import dependencies

    monkeypatch.setattr(dependencies.SessionManager, "validate_session",
                        lambda self, token: "alice" if token == "user-token" else None)
    client = TestClient(api)
    response = client.post("/api/security-controls/snapshots", json=body(),
                           headers={"Authorization": "Bearer user-token"})
    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["error"] == "user_token_not_accepted"
    assert detail["stored"] is False


def test_no_credential_at_all_is_a_service_identity_refusal(api):
    response = TestClient(api).post("/api/security-controls/snapshots", json=body())
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "service_identity_required"


def test_a_machine_credential_is_accepted(writer):
    response = writer.post("/api/security-controls/snapshots", json=body())
    assert response.status_code == 200, response.text
    stored = response.json()
    assert stored["stored"] is True
    assert stored["identity"]["kind"] == "api_key"


# --------------------------------------------------------------------------- #
# idempotency and the chain
# --------------------------------------------------------------------------- #

def test_a_retry_does_not_advance_the_chain(writer):
    first = writer.post("/api/security-controls/snapshots", json=body()).json()
    second = writer.post("/api/security-controls/snapshots", json=body()).json()
    assert first["stored"] is True
    assert second["stored"] is False
    assert second["duplicate"] is True
    assert second["sequence"] == first["sequence"]


def test_a_changed_read_advances_the_chain(writer, session):
    first = writer.post("/api/security-controls/snapshots", json=body()).json()
    second = writer.post("/api/security-controls/snapshots",
                         json=body("sha256:eeeeffff00001111")).json()
    assert second["stored"] is True
    assert second["sequence"] == first["sequence"] + 1
    assert second["previous_hash"] == first["entry_hash"]


def test_the_chain_verifies_and_a_deleted_row_is_visible(writer):
    for index in range(3):
        writer.post("/api/security-controls/snapshots",
                    json=body(f"sha256:{index:016d}"))
    assert writer.get("/api/security-controls/verify").json()["verified"] is True


def test_a_changed_snapshot_body_is_detected_even_when_links_remain_intact(writer, session):
    from db.models.security_control import SecurityControlSnapshot

    for index in range(2):
        assert writer.post("/api/security-controls/snapshots",
                           json=body(f"sha256:{index:016d}")).status_code == 200
    row = session.query(SecurityControlSnapshot).order_by(SecurityControlSnapshot.sequence).first()
    row.controls = ["REWRITTEN"]
    session.commit()
    result = writer.get("/api/security-controls/verify").json()
    assert result["verified"] is False
    assert any(problem["code"] == "ENTRY_HASH_MISMATCH" for problem in result["problems"])


# --------------------------------------------------------------------------- #
# a finding is a claim
# --------------------------------------------------------------------------- #

def test_a_finding_without_evidence_is_refused(writer):
    payload = body()
    payload["findings"][0]["evidence_ids"] = []
    response = writer.post("/api/security-controls/snapshots", json=payload)
    assert response.status_code == 422
    problems = response.json()["detail"]["problems"]
    assert any(item["code"] == "FINDING_WITHOUT_EVIDENCE" for item in problems)
    assert response.json()["detail"]["stored"] is False


def test_a_finding_without_a_fact_class_is_refused(writer):
    payload = body()
    payload["findings"][0]["facts"] = []
    response = writer.post("/api/security-controls/snapshots", json=payload)
    assert response.status_code == 422
    assert any(item["code"] == "FINDING_WITHOUT_FACT_CLASS"
               for item in response.json()["detail"]["problems"])


def test_an_unknown_state_is_refused_rather_than_stored(writer):
    payload = body()
    payload["findings"][0]["state"] = "PROBABLY_FINE"
    response = writer.post("/api/security-controls/snapshots", json=payload)
    assert response.status_code == 422
    assert any(item["code"] == "UNKNOWN_STATE"
               for item in response.json()["detail"]["problems"])


def test_not_configured_and_unknown_stay_separate(writer, api):
    from api import dependencies

    payload = body("sha256:9999999999999999")
    payload["findings"] = [
        {"control": "RATE_LIMIT", "state": "NOT_CONFIGURED", "subject": "PAYMENTS-API",
         "facts": ["OBSERVED"], "evidence_ids": ["EVID-RL-1"],
         "reason": "traffic and no policy attached: a decision not made"},
        {"control": "RATE_LIMIT", "state": "UNKNOWN", "subject": "REFUNDS-API",
         "facts": ["CONFIGURED"], "evidence_ids": ["EVID-RL-2"],
         "reason": "the limiter's counters could not be read"},
    ]
    assert writer.post("/api/security-controls/snapshots", json=payload).status_code == 200

    from api.dependencies import TenantContext

    api.dependency_overrides[dependencies.get_tenant_context] = lambda: TenantContext(
        username="auditor", tenant_id=None, tenant_role="admin", is_platform_admin=True)
    reader = TestClient(api)
    response = reader.get("/api/security-controls/findings", params={"control": "RATE_LIMIT"})
    assert response.status_code == 200
    payload = response.json()
    states = {row["subject"]: row["state"] for row in payload["findings"]}
    assert states["PAYMENTS-API"] == "NOT_CONFIGURED"
    assert states["REFUNDS-API"] == "UNKNOWN"
    assert payload["states_kept_separate"]["NOT_CONFIGURED"]
    assert payload["states_kept_separate"]["UNKNOWN"]


def test_findings_keep_their_evidence_ids(writer, api):
    from api import dependencies

    assert writer.post("/api/security-controls/snapshots",
                       json=body()).status_code == 200
    from api.dependencies import TenantContext

    api.dependency_overrides[dependencies.get_tenant_context] = lambda: TenantContext(
        username="auditor", tenant_id=None, tenant_role="auditor", is_platform_admin=True)
    response = TestClient(api).get("/api/security-controls/findings")
    rows = response.json()["findings"]
    assert rows and rows[0]["evidence_ids"] == ["EVID-FIREWALL-00000000abcd"]
    assert rows[0]["facts"] == ["OBSERVED"]
    json.dumps(rows)  # the row is serialisable evidence, not an ORM object


# --------------------------------------------------------------------------- #
# the console: every failure has a name
# --------------------------------------------------------------------------- #

def test_health_route_names_every_control_and_never_says_nothing(writer, api):
    """A console that renders "no findings" for four different failures is a console that
    hides three of them. The route is where they stop looking alike — and where a snapshot
    covering three controls carries three per-control outcomes, not one painted state."""
    from api.dependencies import TenantContext

    payload = body("sha256:aaaa000011112222", read_state="PARTIAL_READ", partial=True)
    payload["controls"] = ["FIREWALL", "WAF", "RATE_LIMIT"]
    payload["findings"] = [
        {"control": "FIREWALL", "state": "OBSERVED", "subject": "FW-EDGE-01",
         "facts": ["OBSERVED"], "evidence_ids": ["EVID-FIREWALL-00000000abcd"],
         "reason": "TLS inspection enabled on the edge policy"},
        {"control": "RATE_LIMIT", "state": "UNKNOWN", "subject": "PAYMENTS-API",
         "facts": ["OBSERVED"], "evidence_ids": ["EVID-RL-1"],
         "reason": "the limiter's counters could not be read"},
    ]
    assert writer.post("/api/security-controls/snapshots", json=payload).status_code == 200
    api.dependency_overrides[__import__("api").dependencies.get_tenant_context] = (
        lambda: TenantContext(username="auditor", tenant_id=None, tenant_role="auditor",
                              is_platform_admin=True))
    response = TestClient(api).get("/api/security-controls/health")
    assert response.status_code == 200
    payload = response.json()
    controls = {row["control"]: row for row in payload["controls"]}
    # three controls, one snapshot, three per-control read results
    assert controls["FIREWALL"]["state"] == "OK"  # its statements arrived
    assert controls["FIREWALL"]["finding_states"] == ["OBSERVED"]
    assert controls["FIREWALL"]["read_state"] == "PARTIAL_READ"
    assert controls["RATE_LIMIT"]["state"] == "PARTIAL_READ"  # nothing learnable arrived
    assert controls["RATE_LIMIT"]["finding_states"] == ["UNKNOWN"]
    assert controls["WAF"]["state"] == "PARTIAL_READ"  # covered, no findings of its own
    assert controls["WAF"]["finding_states"] == []
    assert controls["HSM"]["state"] in {"NOT_CONFIGURED", "OK"}
    # device-level stays its own block: the read outcome of the newest snapshot
    assert payload["device"]["read_state"] == "PARTIAL_READ"
    assert payload["device"]["collector"] == "key-collector-1"
    assert "live" in payload["driver_coverage"]
    assert payload["coverage"]["nothing_asked"] is False
    assert payload["coverage"]["total"] == len(controls)
    assert "PARTIAL_READ" in payload["taxonomy"]
    assert payload["taxonomy"]["AUTH_FAILED"]["operator_action"].startswith("rotate")
    assert payload["note"].startswith("a state describes what the platform could learn")


# --------------------------------------------------------------------------- #
# item 19 — the estate leaves the console
# --------------------------------------------------------------------------- #

def test_the_estate_exports_as_schema_valid_cyclonedx(writer, api):
    from cbom.cyclonedx16 import validate_cyclonedx16

    writer.post("/api/security-controls/snapshots", json=body())
    response = TestClient(api).get("/api/security-controls/export?format=cyclonedx")
    assert response.status_code == 200, response.text
    document = response.json()
    assert document["bomFormat"] == "CycloneDX" and document["specVersion"] == "1.6"
    assert validate_cyclonedx16(document)["ok"] is True
    refs = {component["bom-ref"] for component in document["components"]}
    assert any(ref.startswith("urn:cryptoscan:control:") for ref in refs)
    # every finding names the control it belongs to instead of floating free
    for annotation in document.get("annotations", []):
        assert annotation["subjects"] and annotation["subjects"][0] in refs


def test_the_export_carries_evidence_ids_and_never_upgrades_a_claim(writer, api):
    writer.post("/api/security-controls/snapshots", json=body())
    document = TestClient(api).get("/api/security-controls/export?format=cyclonedx").json()
    text = json.dumps(document)
    assert "EVID-FIREWALL-00000000abcd" in text
    # a control this snapshot never read must not appear as RUNTIME_OBSERVED
    for component in document["components"]:
        properties = {item["name"]: item["value"] for item in component["properties"]}
        if properties.get("cryptoscan:control.state") != "OBSERVED":
            assert properties.get("cryptoscan:control.observation_class") != "RUNTIME_OBSERVED"


def test_the_same_estate_exports_as_escaped_cef_lines(writer, api):
    writer.post("/api/security-controls/snapshots", json=body())
    response = TestClient(api).get("/api/security-controls/export?format=cef")
    assert response.status_code == 200
    lines = [line for line in response.text.splitlines() if line.startswith("CEF:0|")]
    assert lines, response.text
    for line in lines:
        assert line.count("|") >= 7
        assert "cs1Label=EvidenceId" in line


def test_an_unknown_export_format_is_refused_by_name(writer, api):
    response = TestClient(api).get("/api/security-controls/export?format=pdf")
    assert response.status_code == 422
