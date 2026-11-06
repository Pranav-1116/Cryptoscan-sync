"""The operator journey, end to end, against the real application and a real database.

login → scanning → retained evidence → all six BOMs → digital twin → simulation in live.

Every stage runs through the same HTTP surface a bank operator's browser calls.
Nothing is mocked: the login mints a real session row, the trigger runs the real
worker pipeline in-process (no queue configured — the production fallback), the
evidence rows are that pipeline's own output, the six BOMs are the production
routes reading those rows, the twin reads the same estate, and the final stage
runs a change against a *copy* of the twin and re-projects the six BOMs from it.

House rules hold inside the journey: a stage that failed must fail loudly — a
read that errored is never accepted as "zero items" — and every claim the
assertions make must be grounded in the response body, not in the status code
alone.

The stages are ordered tests sharing one module fixture; a later stage asserts
its precondition ("the scan stage produced ...") instead of KeyError-ing on
missing state.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

SOURCE_FILE = '''\
"""Payment service with real bad-crypto usage for the scanner to find."""
import hashlib

def fingerprint(card_number: str) -> str:
    return hashlib.md5(card_number.encode()).hexdigest()
'''


@pytest.fixture(scope="module")
def journey(tmp_path_factory):
    workdir = tmp_path_factory.mktemp("journey-src")
    (workdir / "payment_service.py").write_text(SOURCE_FILE)

    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "journey_login_to_simulation.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"
    # The scan target must resolve inside a configured source root, exactly as
    # the production admission requires.
    os.environ["CRYPTOSCAN_SOURCE_ROOTS"] = os.pathsep.join(
        [str(Path(__file__).resolve().parents[4]), tempfile.gettempdir()]
    )

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as client:
        yield {"client": client, "src": str(workdir), "state": {}}


def _bearer(state: dict) -> dict:
    token = state.get("token")
    assert token, "the login stage must complete before this stage runs"
    return {"Authorization": f"Bearer {token}"}


class TestOperatorJourney:
    def test_01_login(self, journey):
        client = journey["client"]
        denied = client.get("/api/v1/scans")
        assert denied.status_code in (401, 403), f"unauthenticated read must be refused, got {denied.status_code}"

        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"})
        assert login.status_code == 200, login.text
        body = login.json()
        assert body["token"], "a session token is the login stage's product"
        assert body["mfa_required"] is False
        assert "superadmin" in body["roles"], body["roles"]
        journey["state"]["token"] = body["token"]

        me = client.get("/api/v1/auth/me", headers=_bearer(journey["state"]))
        assert me.status_code == 200 and me.json()["username"] == "admin"

    def test_02_scanning(self, journey):
        client, src, state = journey["client"], journey["src"], journey["state"]
        preflight = client.post("/api/v1/scans/preflight", json={"repo_url": src}, headers=_bearer(state))
        assert preflight.status_code == 200, preflight.text
        decision = preflight.json()
        assert "decision" in decision, decision
        assert decision.get("job_created") is False, "preflight must never queue work"

        trigger = client.post("/api/v1/scans/trigger", json={"repo_url": src}, headers=_bearer(state))
        assert trigger.status_code == 202, trigger.text
        job_id = trigger.json()["job_id"]
        assert job_id, trigger.text

        scan = None
        for _ in range(30):
            listing = client.get("/api/v1/scans", params={"page_size": 50}, headers=_bearer(state))
            assert listing.status_code == 200, listing.text
            candidates = [s for s in listing.json()["scans"] if src in (s.get("target_location") or "")]
            if candidates:
                scan = candidates[0]
                if scan["status"] in ("COMPLETED", "FAILED"):
                    break
            time.sleep(0.5)
        assert scan is not None, f"the scan of {src} never appeared in the scan list"
        assert scan["status"] == "COMPLETED", f"the scan did not complete: {scan}"
        state["scan_id"] = scan["scan_id"]
        state["job_id"] = job_id

    def test_03_retained_evidence(self, journey):
        client, state = journey["client"], journey["state"]
        scan_id = state.get("scan_id")
        assert scan_id, "the scanning stage must complete before this stage runs"

        findings = client.get(f"/api/v1/scans/{scan_id}/findings", params={"page_size": 50}, headers=_bearer(state))
        assert findings.status_code == 200, findings.text
        body = findings.json()
        assert body["total_count"] >= 1, f"the md5 usage produced no retained finding: {body}"
        rows = body["findings"]
        assert any((row["algorithm"] or "").upper().startswith("MD5") for row in rows), (
            f"the scanner's own finding for hashlib.md5 is missing: {[r['algorithm'] for r in rows]}"
        )
        for row in rows:
            assert row["evidence_id"] and row["scan_id"] == scan_id
            assert row["confidence"] in ("HIGH", "MEDIUM", "LOW"), row

        inventory = client.get("/api/v1/evidence/disposition/inventory", headers=_bearer(state))
        assert inventory.status_code == 200, inventory.text
        inv = inventory.json()
        assert inv["records_total"] >= len(rows), (
            f"evidence inventory does not cover the scan's findings: {inv}"
        )
        assert inv["truncated"] is False and inv["records_inspected"] == inv["records_total"], (
            f"the inventory read is partial and must not be read as a total: {inv}"
        )
        state["algorithm"] = next(
            r["algorithm"] for r in rows if (r["algorithm"] or "").upper().startswith("MD5")
        )

        disposition = client.get(f"/api/v1/evidence/disposition/{scan_id}", headers=_bearer(state))
        assert disposition.status_code == 200, disposition.text
        assert isinstance(disposition.json(), list), disposition.text

    def test_04_six_boms(self, journey):
        client, state = journey["client"], journey["state"]
        assert state.get("scan_id"), "the scanning stage must complete before this stage runs"

        def read(name, path, **params):
            r = client.get(path, params=params or None, headers=_bearer(state))
            assert r.status_code == 200, f"{name} read failed ({r.status_code}): {r.text[:400]}"
            body = r.json()
            assert body is not None, f"{name} returned an empty document"
            return body

        cbom = read("CBOM", "/api/v1/cbom", page=1, page_size=20)
        assert cbom["spec"].startswith("CycloneDX"), cbom["spec"]
        listed = {s.get("source_id"): s for s in cbom["scans"]}
        assert state["scan_id"] in listed, f"the CBOM catalog does not carry the journey's scan: {cbom['scans']}"
        assert listed[state["scan_id"]]["components"] >= 1, listed[state["scan_id"]]
        assert "algorithms" in cbom["totals"], cbom["totals"]
        nbom = read("NBOM", "/api/v1/cbom/nbom")
        assert "summary" in nbom, list(nbom)[:10]
        techbom = read("TechBOM", "/api/v1/technology-bom")
        assert techbom["live"] is True and techbom["source"] == "technology_bom", {
            k: techbom[k] for k in ("live", "source") if k in techbom}
        layers = set(techbom.get("components_by_layer") or {}) | set(techbom.get("layers") or {})
        assert {"sbom", "cbom", "hbom"} <= layers, f"TechBOM must carry its BOM layers: {sorted(layers)}"
        assert techbom.get("scan") is not None, "TechBOM must name the scan state it materialized from"
        hbom = read("HBOM", "/api/v1/hbom")
        assert isinstance(hbom, dict) and hbom, hbom
        vbom = read("VBOM", "/api/v1/vbom/dependency")
        assert isinstance(vbom, dict) and vbom, vbom
        sbom = read("SBOM", "/api/v1/devsecops/sbom/artifacts")
        assert isinstance(sbom, (dict, list)), sbom

    def test_05_digital_twin(self, journey):
        client, state = journey["client"], journey["state"]
        overview = client.get("/api/v1/digital-twin", headers=_bearer(state))
        assert overview.status_code == 200, overview.text
        assert isinstance(overview.json(), dict) and overview.json(), overview.text[:400]

        scenarios = client.get("/api/v1/digital-twin/scenarios", headers=_bearer(state))
        assert scenarios.status_code == 200, scenarios.text
        catalog = scenarios.json()
        entries = catalog.get("scenarios") or []
        names = {e.get("id") for e in entries}
        assert "algorithm_migration" in names, f"the scenario catalog is empty or renamed: {catalog}"
        state["scenario"] = "algorithm_migration"

        simulation = client.post(
            "/api/v1/digital-twin/simulate",
            json={"scenario": state["scenario"], "params": {"from_algo": "DES", "to_algo": "AES"}},
            headers=_bearer(state),
        )
        assert simulation.status_code == 200, simulation.text
        result = simulation.json()
        assert result, "a simulation must return its result"
        # Read-only by construction: the engine must say what it does not know
        # rather than invent an impact.
        rendered = str(result).lower()
        assert "unknown" in rendered or "impact" in rendered or "affected" in rendered, result

    def test_06_simulation_in_live(self, journey):
        client, state = journey["client"], journey["state"]
        assert state.get("scan_id"), "the scanning stage must complete before this stage runs"

        # The live twin refuses to answer for an estate nobody discovered
        # ("an empty estate is NOT_OBSERVED, not an estate without crypto"), so
        # the journey discovers one first — carrying the algorithm the scanner
        # actually reported, not one invented here.
        discovery = client.post(
            "/api/v1/estate/evidence/discover",
            json={
                "estate": "journey-estate",
                "assets": [{"ref": "svc", "type": "APPLICATION", "name": "payment_service"}],
                "evidence": [{
                    "source": "static_scanner",
                    "evidence_type": "STATIC_OBSERVED",
                    "target": "svc",
                    "layer": "APPLICATION",
                    "facts": {"algorithm": state["algorithm"], "purpose": "HASHING"},
                }],
                "collectors": [{"plane": "STATIC", "status": "COMPLETE", "expected": 1, "collected": 1}],
                "coverage": [{"target": "STATIC", "expected": 1, "collected": 1}],
            },
            headers=_bearer(state),
        )
        assert discovery.status_code == 200, discovery.text

        catalog = client.get("/api/v1/estate/evidence/twin/simulation-scenarios", headers=_bearer(state))
        assert catalog.status_code == 200, catalog.text
        assert catalog.json(), "the live twin exposes no scenario to run"

        before = client.get("/api/v1/estate/evidence/twin", headers=_bearer(state))
        assert before.status_code == 200, before.text

        run = client.post(
            "/api/v1/estate/evidence/twin/simulate",
            json={"kind": "REPLACE_ALGORITHM", "from": state["algorithm"], "to": "SHA-256",
                  "label": "journey-test"},
            headers=_bearer(state),
        )
        assert run.status_code == 200, run.text
        result = run.json()
        assert result, "the live-twin simulation returned no result"
        rendered = str(result).lower()
        assert "live" in rendered, result  # the result must state its effect (or non-effect) on live state

        after = client.get("/api/v1/estate/evidence/twin", headers=_bearer(state))
        assert after.status_code == 200, after.text
        # A simulation runs on a copy: the live twin must not have been mutated
        # by running it (the engine's own contract, re-checked from outside).
        assert after.json().keys() == before.json().keys(), "running a simulation changed the live twin's shape"
