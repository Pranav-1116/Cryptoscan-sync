"""Anchored BOM sets and estate drift (spec 93 §12, §18).

Two properties carry the trust story of the unified estate:

* a projected BOM set can be **anchored** — signed with a key the database does
  not hold — so a later rewrite cannot pass off different BOMs as the published
  ones; and refusing to anchor without a key is part of the property;
* **drift** between two snapshots reports what moved, and refuses to read a
  coverage loss as an estate change or an empty-in-both BOM as "unchanged".
"""

from __future__ import annotations

import pytest

from api import estate_drift
from api.security.estate_bom_anchor import bom_digest, sign_receipt, verify_anchor

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

KEY_ENV = "CRYPTOSCAN_ANCHOR_KEY"


def _payload(tls_version: str = "TLSv1.2") -> dict:
    return {
        "estate": "anchor-estate",
        "scope": "production",
        "assets": [
            {"ref": "api", "type": "APPLICATION", "name": "payments-api"},
            {"ref": "ep", "type": "NETWORK_ENDPOINT", "name": "10.0.0.5:443",
             "identity": {"endpoint": "10.0.0.5:443"}},
        ],
        "evidence": [
            {"source": "static_scanner", "evidence_type": "STATIC_OBSERVED", "target": "api",
             "layer": "APPLICATION", "facts": {"algorithm": "RSA", "key_size": 2048}},
            {"source": "network_scanner", "evidence_type": "NETWORK_ACTIVE_OBSERVED", "target": "ep",
             "layer": "NETWORK_TRANSPORT", "facts": {"tls_version": tls_version,
                                                     "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384"}},
        ],
        "collectors": [{"plane": "NETWORK", "status": "COMPLETE", "expected": 1, "collected": 1},
                       {"plane": "STATIC", "status": "COMPLETE", "expected": 1, "collected": 1}],
        "coverage": [{"target": "NETWORK", "expected": 1, "collected": 1},
                     {"target": "STATIC", "expected": 1, "collected": 1}],
    }


def _discover(http, tls_version: str = "TLSv1.2"):
    response = http.post("/api/v1/estate/evidence/discover", json=_payload(tls_version))
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------- #
# anchoring
# --------------------------------------------------------------------------- #
def test_anchor_refuses_without_a_key(api, monkeypatch):
    http, _session = api
    monkeypatch.delenv(KEY_ENV, raising=False)
    _discover(http)
    response = http.post("/api/v1/estate/evidence/boms/anchor", json={})
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["error"] == "anchor_key_not_configured"
    assert "claim, not evidence" in detail["reason"]


def test_anchor_signs_every_bom_and_verifies_intact(api, monkeypatch):
    http, _session = api
    monkeypatch.setenv(KEY_ENV, "test-anchor-key")
    discovered = _discover(http)

    created = http.post("/api/v1/estate/evidence/boms/anchor", json={"note": "board pack"})
    assert created.status_code == 200, created.text
    receipt = created.json()
    assert receipt["schema"] == "cryptoscan.estate-bom-anchor/1"
    assert receipt["projection_id"] == discovered["projection_id"]
    assert receipt["bom_count"] == len(discovered["boms"])
    assert set(receipt["bom_digests"]) == set(discovered["boms"])
    assert receipt["external"] is False
    assert receipt["signature"]

    listed = http.get("/api/v1/estate/evidence/boms/anchors").json()
    assert listed["count"] == 1
    assert listed["key"]["configured"] is True

    verified = http.post("/api/v1/estate/evidence/boms/anchor/verify", json={})
    assert verified.status_code == 200, verified.text
    body = verified.json()
    assert body["status"] == "PROJECTION_INTACT"
    assert body["signature_valid"] is True
    assert body["changed_boms"] == []


def test_verify_without_any_anchor_is_404(api, monkeypatch):
    http, _session = api
    monkeypatch.setenv(KEY_ENV, "test-anchor-key")
    _discover(http)
    response = http.post("/api/v1/estate/evidence/boms/anchor/verify", json={})
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_bom_anchor"


def test_verify_with_an_unknown_anchor_id_is_404(api, monkeypatch):
    http, _session = api
    monkeypatch.setenv(KEY_ENV, "test-anchor-key")
    _discover(http)
    http.post("/api/v1/estate/evidence/boms/anchor", json={})
    response = http.post("/api/v1/estate/evidence/boms/anchor/verify", json={"anchor_id": "nope"})
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "unknown_bom_anchor"


def test_a_tampered_receipt_fails_its_signature():
    key = b"test-anchor-key"
    boms = {"CBOM": {"bom": "CBOM", "components": [{"name": "RSA-2048", "bom-ref": "a"}]}}
    receipt = {
        "schema": "cryptoscan.estate-bom-anchor/1",
        "anchor_id": "estate-anchor-test",
        "projection_id": "proj-1",
        "bom_count": 1,
        "bom_digests": {kind: bom_digest(bom) for kind, bom in boms.items()},
    }
    receipt["signature"] = sign_receipt(receipt, key)
    assert verify_anchor(receipt, boms, key=key)["status"] == "PROJECTION_INTACT"

    forged = {**receipt, "projection_id": "proj-2"}
    verdict = verify_anchor(forged, boms, key=key)
    assert verdict["status"] == "SIGNATURE_INVALID"
    assert verdict["signature_valid"] is False


def test_a_changed_bom_is_reported_as_changed_not_intact():
    key = b"test-anchor-key"
    boms = {"CBOM": {"bom": "CBOM", "components": [{"name": "RSA-2048", "bom-ref": "a"}]},
            "SBOM": {"bom": "SBOM", "components": []}}
    receipt = {"anchor_id": "estate-anchor-test", "projection_id": "proj-1",
               "bom_digests": {kind: bom_digest(bom) for kind, bom in boms.items()}}
    receipt["signature"] = sign_receipt(receipt, key)

    changed = {"CBOM": {"bom": "CBOM", "components": [{"name": "RSA-1024", "bom-ref": "a"}]},
               "SBOM": {"bom": "SBOM", "components": []},
               "NBOM": {"bom": "NBOM", "components": []}}
    verdict = verify_anchor(receipt, changed, key=key)
    assert verdict["status"] == "PROJECTION_CHANGED"
    assert verdict["changed_boms"] == ["CBOM"]
    assert verdict["added_boms"] == ["NBOM"]
    assert "not automatically tampering" in verdict["note"]


def test_verification_without_a_key_refuses_to_claim_anything():
    verdict = verify_anchor({"anchor_id": "x", "bom_digests": {}}, {}, key=None)
    assert verdict["status"] == "KEY_UNKNOWN"
    assert verdict["signature_valid"] is None


# --------------------------------------------------------------------------- #
# drift
# --------------------------------------------------------------------------- #
def test_drift_with_one_snapshot_is_no_baseline(api):
    http, _session = api
    _discover(http)
    body = http.get("/api/v1/estate/evidence/drift").json()
    assert body["verdict"] == "NO_BASELINE"
    assert "not 'no drift'" in body["note"]


def test_drift_without_any_snapshot_says_how_to_start(api):
    http, _session = api
    body = http.get("/api/v1/estate/evidence/drift").json()
    assert body["verdict"] == "NO_BASELINE"
    assert "baseline" in body["note"]


def test_drift_detects_a_changed_estate(api):
    http, _session = api
    first = _discover(http, "TLSv1.2")
    second = _discover(http, "TLSv1.0")
    body = http.get("/api/v1/estate/evidence/drift").json()
    assert body["verdict"] == "DRIFT"
    assert body["baseline_projection_id"] == first["projection_id"]
    assert body["current_projection_id"] == second["projection_id"]
    # a TLS version change moves the network-facing projections, not the
    # application CBOM: layers stay separate even in a diff
    assert set(body["changed_boms"]) & {"NBOM", "TECHBOM"}
    changed = [kind for kind in body["changed_boms"] if body["boms"][kind]["counts"]["changed"]]
    assert changed, "a changed projection must name at least one changed component"
    assert body["same_snapshot"] is False


def test_drift_between_identical_snapshots_is_no_drift(api):
    http, _session = api
    _discover(http)
    _discover(http)
    body = http.get("/api/v1/estate/evidence/drift").json()
    assert body["verdict"] == "NO_DRIFT"
    assert body["same_snapshot"] is True


def test_drift_treats_a_plane_present_in_one_snapshot_only_as_not_comparable():
    previous = {"projection_id": "p1", "boms": {"CBOM": {"a": "1"}}, "coverage": {}, "collectors": {}}
    current = {"projection_id": "p2", "boms": {"CBOM": {"a": "1"}, "HBOM": {"h": "1"}},
               "coverage": {}, "collectors": {}}
    report = estate_drift.compare(previous, current)
    assert report["boms"]["HBOM"]["status"] == "NOT_COMPARABLE"
    assert "cannot be diffed" in report["boms"]["HBOM"]["reason"]
    assert report["boms"]["CBOM"]["status"] == "UNCHANGED"


def test_drift_marks_an_empty_in_both_bom_as_not_comparable():
    previous = {"projection_id": "p1", "boms": {"VBOM": {}}, "coverage": {}, "collectors": {}}
    current = {"projection_id": "p1", "boms": {"VBOM": {}}, "coverage": {}, "collectors": {}}
    report = estate_drift.compare(previous, current)
    assert report["boms"]["VBOM"]["status"] == "NOT_COMPARABLE"
    assert "not evidence of no change" in report["boms"]["VBOM"]["reason"]


def test_drift_reports_coverage_debt_rather_than_an_estate_change():
    previous = {"projection_id": "p1", "boms": {}, "collectors": {"NETWORK": "COMPLETE"},
                "coverage": {"NETWORK": {"expected": 10, "collected": 10, "status": "COMPLETE"}}}
    current = {"projection_id": "p2", "boms": {}, "collectors": {"NETWORK": "FAILED"},
               "coverage": {"NETWORK": {"expected": 10, "collected": 4, "status": "PARTIAL"}}}
    report = estate_drift.compare(previous, current)
    assert report["verdict"] == "DRIFT"
    coverage = report["coverage"]["NETWORK"]
    assert coverage["delta_collected"] == -6
    assert "coverage debt grew" in coverage["note"]
    assert report["degraded_planes"] == ["NETWORK"]
    assert "not an estate change" in report["meaning"]


# --------------------------------------------------------------------------- #
# external export (spec 67 §31 — an anchor in our own database is not external)
# --------------------------------------------------------------------------- #
def test_export_without_a_sink_is_409_and_says_why(api, monkeypatch):
    http, _session = api
    monkeypatch.setenv(KEY_ENV, "test-anchor-key")
    for name in ("ANCHOR_EXPORT_DIR", "ANCHOR_EXPORT_S3_BUCKET", "ANCHOR_EXPORT_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    _discover(http)
    assert http.post("/api/v1/estate/evidence/boms/anchor", json={}).status_code == 200

    status = http.get("/api/v1/estate/evidence/boms/anchor/export/status")
    assert status.status_code == 200 and status.json()["configured"] is False

    response = http.post("/api/v1/estate/evidence/boms/anchor/export", json={})
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["error"] == "anchor_export_not_configured"
    assert "not external" in detail["reason"]


def test_export_to_a_write_once_directory_confirms_the_write(api, monkeypatch, tmp_path):
    http, _session = api
    monkeypatch.setenv(KEY_ENV, "test-anchor-key")
    monkeypatch.setenv("ANCHOR_EXPORT_DIR", str(tmp_path))
    _discover(http)
    created = http.post("/api/v1/estate/evidence/boms/anchor", json={}).json()

    exported = http.post("/api/v1/estate/evidence/boms/anchor/export", json={})
    assert exported.status_code == 200, exported.text
    body = exported.json()
    assert body["external"] is True
    assert body["sink"] == "FILESYSTEM"
    assert body["anchor_id"] == created["anchor_id"]
    assert (tmp_path / f"{created['anchor_id']}.json").exists()

    # the sink is write-once: a second export of the same receipt is refused
    again = http.post("/api/v1/estate/evidence/boms/anchor/export", json={})
    assert again.status_code == 409
    assert again.json()["detail"]["error"] == "already_exported"


def test_export_without_any_anchor_asks_for_one_first(api, monkeypatch, tmp_path):
    http, _session = api
    monkeypatch.setenv("ANCHOR_EXPORT_DIR", str(tmp_path))
    response = http.post("/api/v1/estate/evidence/boms/anchor/export", json={})
    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "no_bom_anchor"
