"""Second CBOM review: collection facts, TLS observations and evidence fallback.

The estate has a system whose stored coverage status is CURRENT but whose
latest scan failed, a key-custody system reached only through its management
TLS endpoint, a system no collector ever reached, an asset whose recorded
evidence link is missing, and a real network run persisted through
``persist_network`` (the production path).

Pins: coverage is PARTIAL and per-system inspection states come from job
facts; each TLS observation becomes a protocol component that ``provides``
its negotiated algorithms and depends on its certificate (which references
its public key and signature algorithm); relationship records carry a basis;
an unlinked asset resolves to its scan finding and says so; HSM coverage is
LIMITED; the content digest is reproducible.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app

SECRET = "collection-cbom-test-secret-" + "x" * 12
RSA_FP = "a1" * 32
EC_FP = "b2" * 32


def _props(component):
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def _finding(fid, endpoint, version, suite, enc, mode, bits, cert, group=None, status="OK"):
    crypto = {"tls_version": version, "cipher_suite": suite, "key_exchange_algorithm": "ECDHE",
              "authentication_algorithm": "RSA" if cert and cert["public_key_algorithm"] == "RSA" else "ECDSA",
              "encryption_algorithm": enc, "encryption_mode": mode, "key_size": bits}
    if group:
        crypto["negotiated_group"] = group
    return {"finding_id": fid, "endpoint": endpoint, "ip_address": endpoint.split(":")[0], "status": status,
            "scanner_id": "cryptoscan-network-scanner/2.3.1", "crypto": crypto if status == "OK" else {},
            "certificates": [cert] if cert and status == "OK" else [],
            "chain_validation": {"structural_status": "OK", "chain_completeness": "COMPLETE",
                                 "trust_status": "NOT_VERIFIED"},
            "metadata": {"confidence": "HIGH", "scan_method": "ACTIVE_TLS_HANDSHAKE"},
            "error": None if status == "OK" else "connection refused"}


@pytest.fixture()
def estate(monkeypatch):
    from db.loader.chain import content_hash
    from db.models import crypto_asset as ca, system as sysmod, system_asset as sa
    from db.models.base import Base
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.evidence_record import EvidenceRecord
    from db.models.network_scan_target import NetworkScanTarget
    from db.models.scan import Scan
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from api.security.network_collection import persist_network
    from network_scanner.inventory.network_evidence import build_evidence

    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_settings.cache_clear()
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    now = datetime.now(timezone.utc)
    with Session() as db:
        portal = sysmod.System(name="ibank-portal", criticality="critical", coverage_status="CURRENT",
                               scan_target="https://git.example/bank/portal.git")
        dwh = sysmod.System(name="data-warehouse", criticality="high", coverage_status="CURRENT",
                            scan_target="https://git.example/bank/dwh.git")
        hsm = sysmod.System(name="payment-hsm", criticality="critical", coverage_status="CURRENT",
                            extra={"system_class": "HSM"})
        idle = sysmod.System(name="archive", coverage_status="CURRENT")
        db.add_all([portal, dwh, hsm, idle])
        db.flush()
        portal_scan = Scan(scan_start=now - timedelta(days=2), scan_end=now - timedelta(days=2),
                           scanner_id="static-scanner", scanner_version="3.1.0",
                           target_location="https://git.example/bank/portal.git", target_commit="c" * 40,
                           target_branch="main", status="COMPLETED", statistics={"files_scanned": 120})
        dwh_ok = Scan(scan_start=now - timedelta(days=30), scan_end=now - timedelta(days=30),
                      scanner_id="static-scanner", scanner_version="3.1.0",
                      target_location="https://git.example/bank/dwh.git", status="COMPLETED",
                      statistics={"files_scanned": 300})
        dwh_failed = Scan(scan_start=now - timedelta(days=1), scanner_id="static-scanner", scanner_version="3.1.0",
                          target_location="https://git.example/bank/dwh.git", status="FAILED",
                          error_message="manifest unpack failed")
        db.add_all([portal_scan, dwh_ok, dwh_failed])
        db.flush()
        portal.last_scan_id, dwh.last_scan_id = portal_scan.id, dwh_failed.id
        aes = ca.CryptoAsset(algorithm="AES", key_size=256, mode="GCM", purpose="ENCRYPTION",
                             file_path="src/Vault.java", line_number=41, confidence="HIGH")
        rsa = ca.CryptoAsset(algorithm="RSA", key_size=2048, purpose="SIGNING", file_path="etl/sign.py",
                             line_number=9, confidence="HIGH")
        db.add_all([aes, rsa])
        db.flush()
        db.add_all([sa.SystemAsset(system_id=portal.id, asset_id=aes.id),
                    sa.SystemAsset(system_id=dwh.id, asset_id=rsa.id)])
        for position, (asset, scan) in enumerate(((aes, portal_scan), (rsa, dwh_ok))):
            finding = {"crypto": {"algorithm": asset.algorithm}, "metadata": {"scan_method": "AST_PATTERN"}}
            digest = content_hash(finding)
            evidence = EvidenceRecord(scan_id=scan.id, content_hash=digest, chain_hash=digest,
                                      chain_position=position, algorithm=asset.algorithm, key_size=asset.key_size,
                                      purpose=asset.purpose, confidence="HIGH", file_path=asset.file_path,
                                      line_number=asset.line_number, finding_data=finding)
            db.add(evidence)
            db.flush()
            if asset is aes:  # the dwh asset's recorded link is missing (pre-link data)
                db.add(CryptoAssetEvidence(asset_id=asset.id, evidence_id=evidence.id))
        db.add_all([NetworkScanTarget(endpoint="10.0.0.2:443", system_id=portal.id),
                    NetworkScanTarget(endpoint="10.0.0.6:8443", system_id=hsm.id),
                    NetworkScanTarget(endpoint="10.0.0.9:443", system_id=dwh.id)])
        db.flush()
        rsa_cert = {"fingerprint_sha256": RSA_FP, "subject": "CN=ibank.example", "issuer": "CN=Bank Issuing CA",
                    "serial_number": "4f2a", "public_key_algorithm": "RSA", "public_key_size": 2048,
                    "signature_algorithm": "sha256WithRSAEncryption", "not_before": "2026-01-10T00:00:00Z",
                    "not_after": "2030-01-10T00:00:00Z", "is_self_signed": False}
        ec_cert = {"fingerprint_sha256": EC_FP, "subject": "CN=hsm-mgmt", "issuer": "CN=hsm-mgmt",
                   "serial_number": "01", "public_key_algorithm": "EC", "public_key_size": 256, "curve": "P-256",
                   "signature_algorithm": "ecdsa-with-SHA256", "not_before": "2025-03-01T00:00:00Z",
                   "not_after": "2030-12-01T00:00:00Z", "is_self_signed": True}
        findings = [
            _finding("f-portal", "10.0.0.2:443", "TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", "AES-128", "GCM", 128,
                     rsa_cert),
            _finding("f-hsm", "10.0.0.6:8443", "TLSv1.3", "TLS_AES_256_GCM_SHA384", "AES-256", "GCM", 256, ec_cert,
                     group="x25519"),
            _finding("f-dwh", "10.0.0.9:443", None, None, None, None, None, None, status="PORT_CLOSED"),
        ]
        result = {"scan_id": "net-1", "findings": findings, "certificates": [rsa_cert, ec_cert],
                  "network_evidence": [build_evidence(f) for f in findings if f["status"] == "OK"],
                  "probe_telemetry": {"status": "PARTIAL", "probed": 3, "ok": 2}}

        class Run:
            job_id = "job-net-1"

        persist_network(db, result, Run())
        db.commit()
        ids = {"aes": aes.id, "rsa": rsa.id, "portal": portal.id, "dwh": dwh.id, "hsm": hsm.id, "idle": idle.id}

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        session = Session()
        try:
            yield session
        finally:
            session.close()

    application.dependency_overrides[get_db_session] = _session
    return application, ids


async def _export(application):
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get("/api/v1/cbom/portfolio?fmt=cyclonedx16")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_a_failed_scan_on_a_current_system_makes_coverage_partial(estate):
    application, _ids = estate
    bom = await _export(application)
    meta = _props(bom["metadata"])
    coverage = json.loads(meta["cryptoscan:coverage"])
    assert coverage["completeness"] == "PARTIAL" and coverage["may_report_total"] is False
    assert coverage["failed_jobs"] >= 1
    dims = json.loads(meta["cryptoscan:coverage:dimensions"])
    assert dims["crypto_discovery_completeness"]["status"] == "NOT_PROVEN"
    assert dims["jobs"]["failed_count"] >= 2  # the dwh scan and the closed dwh endpoint
    states = {c["name"]: _props(c).get("cryptoscan:system:inspection_state")
              for c in bom["components"] if c.get("type") == "application"}
    assert states["ibank-portal"] == "INSPECTED_WITH_FINDINGS"
    assert states["data-warehouse"] == "PARTIAL"
    assert states["archive"] == "NOT_INSPECTED"
    assert meta["cryptoscan:discovery_completeness"] == "NOT_PROVEN"


@pytest.mark.asyncio
async def test_key_custody_systems_state_their_limited_coverage(estate):
    application, _ids = estate
    bom = await _export(application)
    hsm = next(c for c in bom["components"] if c.get("name") == "payment-hsm")
    collection = json.loads(_props(hsm)["cryptoscan:system:collection"])
    custody = collection["key_custody_discovery"]
    assert custody["coverage"] == "LIMITED"
    assert custody["reached_by"] == ["NETWORK_TLS_HANDSHAKE"]
    assert collection["key_custody_api_collection"] == "NOT_COLLECTED"


@pytest.mark.asyncio
async def test_tls_observation_becomes_linked_protocol_certificate_and_key_components(estate):
    application, _ids = estate
    bom = await _export(application)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    deps = {d["ref"]: d for d in bom["dependencies"]}
    proto = by_ref["tls-protocol:10.0.0.2:443"]
    protocol = proto["cryptoProperties"]["protocolProperties"]
    assert (protocol["type"], protocol["version"]) == ("tls", "1.2")
    suite = protocol["cipherSuites"][0]
    assert suite["name"] == "ECDHE-RSA-AES128-GCM-SHA256"
    provided = deps[proto["bom-ref"]]["provides"]
    assert set(suite["algorithms"]) == set(provided)
    names = {by_ref[ref]["name"] for ref in provided}
    assert names == {"AES-128-GCM", "ECDH"}  # the materialized cipher row, mode restored; no duplicate
    cert_ref = f"certificate:{RSA_FP}"
    assert deps[proto["bom-ref"]]["dependsOn"] == [cert_ref]
    cert = by_ref[cert_ref]["cryptoProperties"]["certificateProperties"]
    assert cert["subjectName"] == "CN=ibank.example" and cert["notValidAfter"].startswith("2030-01-10")
    signature = by_ref[cert["signatureAlgorithmRef"]]
    assert signature["name"] == "SHA256withRSA" and signature["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.11"
    key = by_ref[cert["subjectPublicKeyRef"]]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert key["type"] == "public-key" and key["size"] == 2048 and key["algorithmRef"] in by_ref
    # the TLS assessment is computed from the handshake, not the version label
    assessment = json.loads(_props(proto)["cryptoscan:tls:assessment"])
    assert assessment["configuration_level"] == "NONE"
    assert _props(proto)["cryptoscan:risk:quantum"] == "HIGH"  # classical ECDHE + RSA certificate
    hsm_kex = by_ref["tls-kex:10.0.0.6:8443"]
    assert hsm_kex["name"] == "X25519"
    assert hsm_kex["cryptoProperties"]["algorithmProperties"]["curve"] == "Curve25519"


@pytest.mark.asyncio
async def test_relationship_records_carry_basis_and_runtime_scope(estate):
    application, ids = estate
    bom = await _export(application)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    records = json.loads(_props(by_ref["tls-protocol:10.0.0.2:443"])["cryptoscan:relationship:records"])
    provides = [r for r in records if r["type"] == "PROTOCOL_PROVIDES_ALGORITHM"]
    assert provides and all(r["basis"] == "RUNTIME_VERIFIED" and r["evidence_id"] for r in provides)
    assert all("not proof of internal use" in r["scope"] for r in provides)
    summary = json.loads(_props(bom["metadata"])["cryptoscan:export:relationship_summary"])
    assert summary["runtime_verified_edges"] == summary["relationship_records_by_basis"]["RUNTIME_VERIFIED"] > 0
    assert summary["human_approved_edges"] == 0
    assert summary["provides_edges"] == 4
    membership = json.loads(_props(by_ref[ids["aes"]])["cryptoscan:relationship:membership"])
    assert membership["type"] == "SYSTEM_CONTAINS_CRYPTO_ASSET" and membership["basis"] == "OBSERVED"
    for component in bom["components"]:
        value = _props(component).get("cryptoscan:runtime_dependency_verified")
        assert value in (None, "false")


@pytest.mark.asyncio
async def test_mapping_fields_name_basis_evidence_confidence_and_verification(estate):
    application, ids = estate
    bom = await _export(application)
    aes = _props(next(c for c in bom["components"] if c["bom-ref"] == ids["aes"]))
    assert aes["cryptoscan:mapping_basis"] == "SCAN_OF_THE_SYSTEMS_REGISTERED_TARGET"
    assert aes["cryptoscan:mapping_evidence_id"] != "NOT_RECORDED"
    assert aes["cryptoscan:mapping_confidence"] == "HIGH"
    assert aes["cryptoscan:mapping_verification_status"] == "EVIDENCE_CORROBORATED_NOT_HUMAN_APPROVED"
    assert aes["cryptoscan:runtime_dependency_verified"] == "false"


@pytest.mark.asyncio
async def test_an_unlinked_asset_resolves_to_its_scan_finding_and_says_so(estate):
    application, ids = estate
    bom = await _export(application)
    rsa = _props(next(c for c in bom["components"] if c["bom-ref"] == ids["rsa"]))
    assert rsa["cryptoscan:evidence_link_status"] == "RESOLVED"
    assert rsa["cryptoscan:evidence:link_basis"] == "MATCHED_BY_LOCATION_AND_ALGORITHM"
    record = json.loads(rsa["cryptoscan:evidence:records"])[0]
    assert record["file"] == "etl/sign.py" and record["line_start"] == 9
    assert record["sha256_basis"] == "CONTENT_HASH_RECOMPUTED_MATCH"
    assert "commit" in record["fields_not_recorded"]
    # a resolved link is weaker than a recorded one
    assert rsa["cryptoscan:mapping_confidence"] == "MEDIUM"
    summary = json.loads(_props(bom["metadata"])["cryptoscan:export:evidence_summary"])
    assert summary["by_link_status"]["LINKED"] == 1 and summary["by_link_status"]["RESOLVED"] == 1


@pytest.mark.asyncio
async def test_collector_provenance_and_reproducible_digest(estate):
    application, _ids = estate
    first, second = await _export(application), await _export(application)
    meta1, meta2 = _props(first["metadata"]), _props(second["metadata"])
    assert meta1["cryptoscan:export:content_sha256"] == meta2["cryptoscan:export:content_sha256"]
    collectors = json.loads(meta1["cryptoscan:export:collectors"])
    kinds = {c["kind"] for c in collectors}
    assert kinds == {"SOURCE_REPOSITORY_SCAN", "NETWORK_TLS_HANDSHAKE"}
    assert all(c["build_digest"] == "NOT_RECORDED" for c in collectors)
    revisions = json.loads(meta1["cryptoscan:export:source_revisions"])
    assert any(r["commit"] == "c" * 40 for r in revisions)
    assert any(r["commit"] == "NOT_RECORDED" for r in revisions)
    reproducibility = json.loads(meta1["cryptoscan:export:reproducibility"])
    assert reproducibility["models"]["risk"].endswith("/2.0.0")
    assert len(reproducibility["asset_id_set_sha256"]) == 64
