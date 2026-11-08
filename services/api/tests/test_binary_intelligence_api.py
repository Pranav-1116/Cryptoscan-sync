"""Binary Intelligence API tests (docs/binary-intelligence/
01_PRODUCT_SPEC.md §12).

Acceptance rows: the artifact is identified by content and digest, is
NEVER executed; findings carry evidence class and usage status with
unknowns left unknown; no finding is never proof of absence; private-key
contents are never in a response; coverage is separate from confidence;
tenant isolation holds.
"""

from __future__ import annotations

import base64

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2].parent /
                       "binary_intelligence"))
from tests.fixtures import (  # noqa: E402
    elf_crypto_sample, elf_plain_sample, pe_crypto_sample,
)


@pytest.fixture()
def api():
    from db.connection.session import Base
    from db.models.binary_intelligence import (
        BinaryAnalysisCoverage, BinaryArtifact, BinaryCryptoFinding,
        BinaryEvidence, BinaryScanRun, BinaryTwinEdge,
    )

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False},
        poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        BinaryArtifact.__table__, BinaryScanRun.__table__,
        BinaryCryptoFinding.__table__, BinaryEvidence.__table__,
        BinaryAnalysisCoverage.__table__, BinaryTwinEdge.__table__])
    session = sessionmaker(bind=engine)()

    from api import dependencies
    from api.routers import binary_intelligence
    from api.errors import install_error_contract

    app = FastAPI()
    app.include_router(binary_intelligence.router, prefix="/api/v1")
    install_error_contract(app)
    app.dependency_overrides[dependencies.get_db_session] = lambda: session
    app.dependency_overrides[dependencies.get_current_user] = lambda: "auditor"
    return TestClient(app)


def _submit(api, data: bytes, *, name: str = "payments-engine",
            tenant: str = "tenant_001", profile: str = "standard"):
    return api.post("/api/v1/binary/scan", json={
        "tenant_id": tenant,
        "artifact_base64": base64.b64encode(data).decode(),
        "original_filename": name,
        "source_type": "upload",
        "scan_profile": profile,
    })


def test_scan_discovers_crypto_with_evidence_and_honest_limits(api):
    created = _submit(api, elf_crypto_sample())
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["artifact"]["detected_format"] == "elf", \
        "content decides identity — the name never does"
    algorithms = {f["algorithm"] for f in body["findings"]}
    assert {"AES", "RSA", "SHA-2"} <= algorithms
    aes = next(f for f in body["findings"] if f["algorithm"] == "AES")
    assert aes["usage_status"] == "statically_referenced"
    assert aes["runtime_confirmed"] is False
    assert aes["key_size_bits"] == 256 and aes["variant"] == "AES-256-GCM"
    rsa = next(f for f in body["findings"] if f["algorithm"] == "RSA")
    assert rsa["key_size_bits"] is None, "unknown stays null"
    assert rsa["variant"] == ""
    assert body["signature_database_version"].startswith("cryptoscan-crypto")
    assert "never executed" in body["notes"][0]
    assert body["coverage"]["symbols_stripped"] is True
    assert "not finding confidence" in body["coverage"]["note"]
    assert body["pqc_assessment"]["migration_readiness"] == "Not established"


def test_no_cryptography_found_is_never_absence(api):
    created = _submit(api, elf_plain_sample(), name="plain-tool")
    body = created.json()
    assert body["findings"][0]["confidence"] == "not_detected"
    assert "never 'absent'" in body["findings"][0]["limitations"][0]


def test_artifact_identity_is_immutable(api):
    first = _submit(api, elf_crypto_sample())
    again = _submit(api, elf_crypto_sample())
    assert first.status_code == 201 and again.status_code == 200
    assert first.json()["artifact"]["artifact_id"] == \
        again.json()["artifact"]["artifact_id"]
    assert first.json()["scan_id"] != again.json()["scan_id"], \
        "each run is recorded; the artifact identity is shared"
    changed = _submit(api, elf_crypto_sample() + b"\x00", name="v2")
    assert changed.status_code == 201
    assert changed.json()["artifact"]["artifact_id"] != \
        first.json()["artifact"]["artifact_id"], \
        "a changed artifact is a new version, never an overwrite"


def test_findings_coverage_and_evidence_are_tenant_scoped(api):
    created = _submit(api, elf_crypto_sample())
    artifact_id = created.json()["artifact"]["artifact_id"]
    scan_id = created.json()["scan_id"]

    listed = api.get(f"/api/v1/binary/artifacts/{artifact_id}/findings",
                     params={"tenant_id": "tenant_001"})
    assert listed.status_code == 200
    findings = listed.json()["findings"]
    assert findings and all("evidence_class" in f for f in findings)
    assert findings[0]["evidence"], "every finding carries its evidence"

    coverage = api.get(f"/api/v1/binary/artifacts/{artifact_id}/coverage",
                       params={"tenant_id": "tenant_001"})
    assert coverage.status_code == 200
    assert "never proof of absence" in coverage.json()["note"]

    evidence = api.get(f"/api/v1/binary/artifacts/{artifact_id}/evidence",
                       params={"tenant_id": "tenant_001"})
    assert evidence.status_code == 200 and evidence.json()

    status = api.get(f"/api/v1/binary/scans/{scan_id}",
                     params={"tenant_id": "tenant_001"})
    assert status.status_code == 200
    assert status.json()["scanner_version"].startswith("cryptoscan-binary")

    cross = api.get(f"/api/v1/binary/artifacts/{artifact_id}/findings",
                    params={"tenant_id": "tenant_002"})
    assert cross.status_code == 404, "no cross-tenant artifact access"
    cross_scan = api.get(f"/api/v1/binary/scans/{scan_id}",
                         params={"tenant_id": "tenant_002"})
    assert cross_scan.status_code == 404


def test_pe_scan_and_profile_and_bad_input(api):
    created = _submit(api, pe_crypto_sample(), name="win-tx.dll")
    body = created.json()
    assert body["artifact"]["detected_format"] == "pe"
    assert any(f["algorithm"] == "AES" for f in body["findings"])
    libs = {f["library"] for f in body["findings"]}
    assert "Windows CNG" in libs or "Windows CNG" in str(body), \
        "BCryptSignHash is recognized as a Windows CNG interface"

    deep = _submit(api, elf_plain_sample(), profile="deep")
    assert deep.status_code == 201
    assert any("deep analysis as NOT completed" in note
               or "external capabilities" in note
               for note in deep.json()["notes"])

    bad_profile = _submit(api, elf_plain_sample(), profile="extreme")
    assert bad_profile.status_code == 422
    assert "never the default" in bad_profile.json()["detail"]

    bad_bytes = api.post("/api/v1/binary/scan", json={
        "tenant_id": "tenant_001", "artifact_base64": "!!!not-base64!!!"})
    assert bad_bytes.status_code == 422
    assert "never assumed" in bad_bytes.json()["detail"]


def test_private_key_contents_never_appear_in_responses(api):
    blob = (elf_plain_sample() +
            b"-----BEGIN PRIVATE KEY-----\nTOP-SECRET-MATERIAL\n"
            b"-----END PRIVATE KEY-----\n")
    created = _submit(api, blob, name="with-key")
    assert "TOP-SECRET-MATERIAL" not in created.text, \
        "private-key contents are never a finding or response (§6)"
    assert created.json()["private_key_events"], \
        "presence IS recorded as a protected detection event"
    assert "never exported" in created.json()["private_key_events"][0]["note"]


def test_bom_endpoint_honours_provides_and_uses_discipline(api):
    created = _submit(api, elf_crypto_sample())
    artifact_id = created.json()["artifact"]["artifact_id"]
    body = api.get(f"/api/v1/binary/artifacts/{artifact_id}/bom",
                   params={"tenant_id": "tenant_001"}).json()
    assert body["bom"]["schema"].startswith("cryptoscan.binary-bom")
    edges = {(r["relationship_type"], r["source"], r["target"])
             for r in body["bom"]["relationships"]}
    assert ("dependsOn", "payments-engine", "libcrypto.so.3") in edges
    assert ("provides", "OpenSSL", "AES-256-GCM") in edges
    uses = [r for r in body["bom"]["relationships"]
            if r["relationship_type"] == "uses"]
    assert uses == [], \
        "ONE imported reference is only indicated — no `uses` edge is " \
        "created from a single reference or co-occurrence (§5)"
    assert any(r["relationship_type"] == "indicates"
               and r["target"] == "AES-256-GCM"
               for r in body["bom"]["relationships"]), \
        "the single reference is an indicator edge, not a use claim"
    assert "only when evidence supports the claim" in body["note"]
    cross = api.get(f"/api/v1/binary/artifacts/{artifact_id}/bom",
                    params={"tenant_id": "tenant_002"})
    assert cross.status_code == 404


def test_comparison_endpoint_reports_indicator_drift_only(api):
    old = _submit(api, elf_crypto_sample(), name="v1")
    new = _submit(api, pe_crypto_sample(), name="v2")
    old_id = old.json()["artifact"]["artifact_id"]
    new_id = new.json()["artifact"]["artifact_id"]
    body = api.get(
        f"/api/v1/binary/artifacts/{old_id}/comparison",
        params={"tenant_id": "tenant_001",
                "against_artifact_id": new_id}).json()
    assert body["summary"].keys() >= {"added", "removed", "changed",
                                      "unchanged"}
    assert "never drift of runtime behavior" in body["note"]
    for delta in body["deltas"]:
        if delta["change"] in ("added", "removed"):
            assert delta["caveat"], "every delta carries its caveat"


def test_rescan_requires_the_same_bytes(api):
    sample = elf_crypto_sample()
    created = _submit(api, sample)
    artifact_id = created.json()["artifact"]["artifact_id"]
    ok = api.post(f"/api/v1/binary/artifacts/{artifact_id}/rescan", json={
        "tenant_id": "tenant_001",
        "artifact_base64": base64.b64encode(sample).decode(),
        "scan_profile": "quick"})
    assert ok.status_code == 201, ok.text
    assert ok.json()["scan_profile"] == "quick"
    assert ok.json()["artifact"]["artifact_id"] == artifact_id
    assert ok.json()["scan_id"] != created.json()["scan_id"]

    changed = api.post(f"/api/v1/binary/artifacts/{artifact_id}/rescan",
                       json={"tenant_id": "tenant_001",
                             "artifact_base64": base64.b64encode(
                                 sample + b"\x00").decode()})
    assert changed.status_code == 422
    assert "NEW artifact" in changed.json()["detail"]


def test_async_queue_process_and_backpressure(api):
    from api.routers.binary_intelligence import WORKER_QUEUE
    sample = elf_crypto_sample()
    queued = api.post("/api/v1/binary/scan/async", json={
        "tenant_id": "tenant_001",
        "artifact_base64": base64.b64encode(sample).decode(),
        "original_filename": "payments-engine",
        "source_type": "upload", "scan_profile": "standard"})
    assert queued.status_code == 202, queued.text
    job_id = queued.json()["job_id"]
    assert queued.json()["status"] == "queued"
    assert "backpressure" in queued.json()["queue"]["note"] or \
        "never silently" in queued.json()["queue"]["note"]

    missing = api.post("/api/v1/binary/scan/jobs/bjob-missing/process")
    assert missing.status_code == 404

    done = api.post(f"/api/v1/binary/scan/jobs/{job_id}/process")
    assert done.status_code == 201, done.text
    body = done.json()
    assert body["status"] == "completed"
    assert body["finding_count"] > 0
    assert body["artifact"]["sha256"] == \
        __import__("hashlib").sha256(sample).hexdigest()
    assert body["coverage"]["total_bytes"] == len(sample), \
        "the worker persists through the same write path as sync scans"

    again = api.post(f"/api/v1/binary/scan/jobs/{job_id}/process")
    assert again.status_code == 404, "a job is processed exactly once"

    status = api.get("/api/v1/binary/worker/status")
    assert status.status_code == 200
    assert status.json()["queue"]["processed_total"] == 1
    assert "refusals" in status.json()["note"] or "numbers" in status.json()["note"]


def test_scan_runs_record_stage_timings(api):
    created = _submit(api, elf_crypto_sample())
    artifact_id = created.json()["artifact"]["artifact_id"]
    scan_id = created.json()["scan_id"]
    status = api.get(f"/api/v1/binary/scans/{scan_id}",
                     params={"tenant_id": "tenant_001"}).json()
    timings = (status.get("structural_report") or {}).get("timings") or {}
    for stage in ("file_intake_and_hash_seconds",
                  "cryptographic_detection_seconds",
                  "total_seconds"):
        assert stage in timings, f"§13 measures {stage}"
    assert timings["total_seconds"] > 0


def test_twin_edges_persist_with_provenance_and_honest_predicates(api):
    created = _submit(api, elf_crypto_sample())
    artifact_id = created.json()["artifact"]["artifact_id"]
    body = api.get(f"/api/v1/binary/artifacts/{artifact_id}/twin",
                   params={"tenant_id": "tenant_001"}).json()
    edges = body["edges"]
    assert edges, "scan relationships are persisted as twin edges"
    assert "never from names or co-occurrence" in body["note"]

    by_type = {}
    for e in edges:
        by_type.setdefault(e["relationship_type"], []).append(e)
    dep = by_type["dependsOn"][0]
    assert dep["subject"] == "payments-engine" and dep["object"] == "libcrypto.so.3"
    assert dep["twin_predicate"] == "depends_on"
    assert dep["provenance"] == "static_dependency"
    assert dep["evidence_class"] == "observed"

    provides = next(e for e in by_type["provides"]
                    if e["subject"] == "AES-256-GCM")
    assert provides["object"] == "OpenSSL", \
        "the twin predicate reads 'algorithm provided_by library'"
    assert provides["twin_predicate"] == "provided_by"
    assert provides["relationship_type"] == "provides", \
        "the BOM direction survives in relationship_type"

    indicates = [e for e in edges if e["relationship_type"] == "indicates"]
    assert all(e["twin_predicate"] is None for e in indicates), \
        "an indicator edge has NO twin predicate — an indicator is not " \
        "a relationship claim (§5)"

    cross = api.get(f"/api/v1/binary/artifacts/{artifact_id}/twin",
                    params={"tenant_id": "tenant_002"})
    assert cross.status_code == 404


def test_scan_rejects_malformed_input_safely(api):
    # base64 that decodes to garbage is a NOT_DETECTED finding, not a crash
    created = _submit(api, b"\x00\x01\x02not-an-executable", name="junk.bin")
    assert created.status_code == 201
    body = created.json()
    assert body["findings"][0]["confidence"] == "not_detected" or \
        body["artifact"]["detected_format"] == "unknown"
    assert body["status"] == "completed"
    if body["artifact"]["detected_format"] == "unknown":
        assert "never guessed" in body["artifact"]["format_reason"], \
            "unknown is named with its reason, never guessed"
