"""Estate CBOM (CycloneDX 1.6) realism contract.

Pins the audit fixes: normalized variants instead of AES/AES-GCM duplicates,
protocols as protocols, placeholder rows excluded, content-addressed evidence
with the hash re-verified, confidence kept apart from verification, ownership
mapping with a reason for every unmapped asset, system→system edges with
basis/confidence/verification, and corrected document counts.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient

from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app

SECRET = "realistic-cbom-test-secret-" + "x" * 12


def _props(component):
    return {p["name"]: p["value"] for p in component.get("properties", [])}


@pytest.fixture()
def estate(monkeypatch):
    from db.loader.chain import content_hash
    from db.models import crypto_asset as ca, system as sysmod, system_asset as sa
    from db.models.base import Base
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    from db.models.evidence_record import EvidenceRecord
    from db.models.scan import Scan
    from db.models.system_dependency import SystemDependency
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-webhook-secret-abc123")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("ENVIRONMENT", "test")
    get_settings.cache_clear()
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    when = datetime(2026, 11, 1, tzinfo=timezone.utc)
    with Session() as db:
        payments = sysmod.System(name="payments-api", environment="prod", criticality="critical",
                                 scan_target="https://git.example/bank/payments.git")
        hsm = sysmod.System(name="hsm-gateway", environment="prod")
        idle = sysmod.System(name="archive-service", environment="prod")  # no assets
        db.add_all([payments, hsm, idle])
        db.flush()
        scan = Scan(scan_start=when, scanner_id="static-java-scanner", scanner_version="2.4.1",
                    target_type="GIT_REPOSITORY", target_location="https://ci:token@git.example/bank/payments.git",
                    target_commit="a" * 40, target_branch="main", operator="ci", status="COMPLETED")
        other_scan = Scan(scan_start=when, scanner_id="static-java-scanner", scanner_version="2.4.1",
                          target_type="GIT_REPOSITORY", target_location="https://git.example/bank/payments",
                          operator="ci", status="COMPLETED")
        failed = Scan(scan_start=when, target_location="https://git.example/bank/ledger.git", status="FAILED",
                      error_message="clone failed")
        db.add_all([scan, other_scan, failed])
        db.flush()
        assets = {
            "aes_gcm": ca.CryptoAsset(algorithm="AES", key_size=256, mode="GCM", purpose="ENCRYPTION",
                                      file_path="src/Vault.java", line_number=41, confidence="HIGH"),
            "aes_gcm_named": ca.CryptoAsset(algorithm="AES-GCM", key_size=256, purpose="ENCRYPTION",
                                            file_path="src/Token.java", line_number=9, confidence="HIGH",
                                            lifecycle_state="VERIFIED"),
            "tls": ca.CryptoAsset(algorithm="TLS 1.2", purpose="NETWORK_ENCRYPTION", file_path="conf/nginx.conf",
                                  line_number=3, confidence="MEDIUM"),
            "mlkem": ca.CryptoAsset(algorithm="ML-KEM", key_size=768, purpose="KEY_EXCHANGE",
                                    file_path="src/pq/Kem.java", line_number=12, confidence="HIGH"),
            "md5": ca.CryptoAsset(algorithm="MD5", purpose="CHECKSUM", file_path="src/Etag.java", line_number=5,
                                  confidence="HIGH"),
            "dhe": ca.CryptoAsset(algorithm="DHE", key_size=1024, purpose="KEY_EXCHANGE", file_path="hsm/ssl.conf",
                                  line_number=8, confidence="MEDIUM"),
            "marker": ca.CryptoAsset(algorithm="MARKER", purpose="SEED", file_path="seed.txt", line_number=1,
                                     confidence="LOW"),
            "orphan_scanned": ca.CryptoAsset(algorithm="SHA-1", purpose="SIGNING", file_path="lib/Legacy.java",
                                             line_number=77, confidence="HIGH"),
            "orphan_bare": ca.CryptoAsset(algorithm="RC4", file_path="vendor/rc4.c", line_number=2, confidence="LOW"),
        }
        db.add_all(assets.values())
        db.flush()
        for key, system in (("aes_gcm", payments), ("aes_gcm_named", payments), ("tls", payments),
                            ("mlkem", payments), ("md5", payments), ("dhe", hsm), ("marker", payments)):
            db.add(sa.SystemAsset(system_id=system.id, asset_id=assets[key].id))
        for position, (key, target) in enumerate((("aes_gcm", scan), ("orphan_scanned", other_scan))):
            finding = {"crypto": {"algorithm": assets[key].algorithm}, "metadata": {"scan_method": "AST_PATTERN"},
                       "source": {"type": "SOURCE_CODE", "file_path": assets[key].file_path}}
            digest = content_hash(finding)
            evidence = EvidenceRecord(scan_id=target.id, content_hash=digest, chain_hash=digest,
                                      chain_position=position, algorithm=assets[key].algorithm, confidence="HIGH",
                                      file_path=assets[key].file_path, line_number=assets[key].line_number,
                                      class_name="Vault" if key == "aes_gcm" else None,
                                      method_name="seal" if key == "aes_gcm" else None, finding_data=finding)
            db.add(evidence)
            db.flush()
            db.add(CryptoAssetEvidence(asset_id=assets[key].id, evidence_id=evidence.id))
        db.add(SystemDependency(parent_id=payments.id, child_id=hsm.id, relation="calls", source="imported",
                                confidence=1.0, evidence_ref="cryptoscan-systems.yml#payments-api"))
        db.commit()
        ids = {key: asset.id for key, asset in assets.items()}

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


async def _export(application, fmt="cyclonedx16"):
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get(f"/api/v1/cbom/portfolio?fmt={fmt}")
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_components_are_normalized_and_placeholders_excluded(estate):
    application, ids = estate
    bom = await _export(application)
    from cbom.cyclonedx16 import validate_cyclonedx16
    assert validate_cyclonedx16(bom)["ok"]
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    assert ids["marker"] not in by_ref, "a placeholder row must not become a crypto asset"
    meta = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    excluded = json.loads(meta["cryptoscan:export:excluded_candidates"])
    assert excluded["count"] == 1 and excluded["items"][0]["ref"] == ids["marker"]
    for ref in [d["ref"] for d in bom["dependencies"]] + [r for d in bom["dependencies"] for r in d.get("dependsOn", [])]:
        assert ref != ids["marker"]
    # AES + GCM and AES-GCM collapse to one variant name, two separate occurrences
    a, b = by_ref[ids["aes_gcm"]], by_ref[ids["aes_gcm_named"]]
    assert a["name"] == b["name"] == "AES-256-GCM"
    assert a["cryptoProperties"]["algorithmProperties"]["primitive"] == "ae"
    assert a["cryptoProperties"]["algorithmProperties"]["mode"] == "gcm"
    assert a["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 5
    assert _props(a)["cryptoscan:identity:algorithm"] == _props(b)["cryptoscan:identity:algorithm"]
    # protocol, not an algorithm with primitive unknown
    tls = by_ref[ids["tls"]]
    assert tls["cryptoProperties"] == {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "1.2"}}
    assert _props(tls)["cryptoscan:classification"] == "CONFIGURATION_FINDING"
    # ML-KEM: 768 is a parameter set with FIPS 203 sizes, deployment not established
    kem = by_ref[ids["mlkem"]]
    assert kem["name"] == "ML-KEM-768"
    assert kem["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "768"
    assert kem["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    facts = json.loads(_props(kem)["cryptoscan:parameter_facts"])
    assert (facts["public_key_bytes"], facts["ciphertext_bytes"]) == (1184, 1088)
    assert _props(kem)["cryptoscan:deployment_stage"] == "DETECTED_IN_SOURCE"
    assert _props(kem)["cryptoscan:risk:quantum_exposure"].endswith("DEPLOYMENT_NOT_ESTABLISHED")
    # purpose-aware weak-algorithm risk
    assert _props(by_ref[ids["md5"]])["cryptoscan:risk:algorithm_risk"] == "LOW"
    assert _props(by_ref[ids["orphan_scanned"]])["cryptoscan:risk:algorithm_risk"] == "HIGH"
    dhe = by_ref[ids["dhe"]]
    assert dhe["name"] == "DHE-1024" and _props(dhe)["cryptoscan:risk:algorithm_risk"] == "HIGH"
    for component in bom["components"]:
        assert _props(component).get("cryptoscan:risk:finding_status", "DETECTION_FINDING_NOT_CONFIRMED_VULNERABILITY") \
            == "DETECTION_FINDING_NOT_CONFIRMED_VULNERABILITY"


@pytest.mark.asyncio
async def test_evidence_is_content_addressed_and_verification_is_not_confidence(estate):
    application, ids = estate
    bom = await _export(application)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    linked = _props(by_ref[ids["aes_gcm"]])
    assert linked["cryptoscan:evidence_link_status"] == "LINKED"
    assert linked["cryptoscan:evidence:content_hash"].startswith("sha256:")
    assert linked["cryptoscan:evidence:hash_verification"] == "CONTENT_HASH_RECOMPUTED_MATCH"
    assert linked["cryptoscan:evidence:commit"] == "a" * 40
    assert linked["cryptoscan:evidence:collector_version"] == "2.4.1"
    assert linked["cryptoscan:evidence:detection_method"] == "AST_PATTERN"
    assert "token" not in linked["cryptoscan:evidence:source_repository"], "credentials never leak into the BOM"
    assert "build_digest" in json.loads(linked["cryptoscan:evidence:fields_not_recorded"])
    occurrence = by_ref[ids["aes_gcm"]]["evidence"]["occurrences"][0]
    assert occurrence["symbol"] == "Vault.seal" and occurrence["additionalContext"].startswith("evidence:")
    # HIGH confidence, yet unverified; a lifecycle-verified asset says so
    assert linked["cryptoscan:confidence"] == "HIGH"
    assert linked["cryptoscan:verification_status"] == "UNVERIFIED_DETECTION"
    assert _props(by_ref[ids["aes_gcm_named"]])["cryptoscan:verification_status"] == "HUMAN_VERIFIED_LIFECYCLE"
    assert _props(by_ref[ids["aes_gcm_named"]])["cryptoscan:evidence_link_status"] == "NO_EVIDENCE_RECORD"


@pytest.mark.asyncio
async def test_mapping_basis_and_unmapped_reasons_never_guess(estate):
    application, ids = estate
    bom = await _export(application)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    assert _props(by_ref[ids["aes_gcm"]])["cryptoscan:mapping_status"] == "EVIDENCE_BACKED"
    assert _props(by_ref[ids["aes_gcm"]])["cryptoscan:mapping_basis"] == "SCAN_OF_THE_SYSTEMS_REGISTERED_TARGET"
    assert _props(by_ref[ids["tls"]])["cryptoscan:mapping_status"] == "RECORDED_BASIS_UNKNOWN"
    # evidence from a scan of payments' registered repo, but no link: proposed, not assigned
    pending = _props(by_ref[ids["orphan_scanned"]])
    assert pending["cryptoscan:mapping_status"] == "PENDING_REVIEW"
    assert pending["cryptoscan:mapping_candidate_system"] == "system:payments-api"
    bare = _props(by_ref[ids["orphan_bare"]])
    assert bare["cryptoscan:mapping_status"] == "UNMAPPED"
    assert bare["cryptoscan:mapping_reason"] == "NO_EVIDENCE_LINK_AND_NO_SYSTEM_LINK"
    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom["dependencies"]}
    assert deps["system:unassigned"] == {ids["orphan_scanned"], ids["orphan_bare"]}
    assert _props(by_ref["system:unassigned"])["cryptoscan:system:kind"] == "UNMAPPED_BUCKET_NOT_A_SYSTEM"


@pytest.mark.asyncio
async def test_relationships_carry_provenance_and_counts_are_consistent(estate):
    application, ids = estate
    bom = await _export(application)
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    edges = json.loads(_props(by_ref["system:payments-api"])["cryptoscan:system:dependency_edges"])
    assert len(edges) == 1
    edge = edges[0]
    assert edge["source"] == "system:payments-api" and edge["target"] == "system:hsm-gateway"
    assert edge["basis"] == "DECLARED" and edge["confidence"] == 1.0
    assert edge["verification_status"] == "NOT_VERIFIED"
    assert edge["evidence_ref"] == "cryptoscan-systems.yml#payments-api"
    assert edge["id"].startswith("edge:") and edge["first_seen"] and edge["last_seen"]
    meta = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert meta["cryptoscan:discovery_completeness"] == "NOT_PROVEN"
    assert meta["cryptoscan:systems"] == "3", "registered systems, including those without assets"
    system_components = [c for c in bom["components"] if c["bom-ref"].startswith("system:")]
    assert meta["cryptoscan:portfolio:system_components"] == str(len(system_components)) == "4"
    assert json.loads(meta["cryptoscan:export:relationship_summary"])["runtime_verified_edges"] == 0
    failures = json.loads(meta["cryptoscan:collection:failures"])
    assert failures["failed_scans_listed"] == 1
    summary = json.loads(meta["cryptoscan:inventory_summary"])
    assert summary["components_total"] == len(bom["components"])
    assert summary["dependency_records"] == len(bom["dependencies"])
    assert meta["cryptoscan:normalizer_version"].startswith("cryptoscan-cbom-normalizer/")
    revisions = json.loads(meta["cryptoscan:export:source_revisions"])
    assert any(r["repository"] == "https://git.example/bank/payments.git" and r["commit"] == "a" * 40 for r in revisions)
    from cbom.inventory import records_from_bom
    assert len(records_from_bom(bom)) == 8  # 9 assets minus the excluded marker; systems are not crypto


@pytest.mark.asyncio
async def test_xml_nests_dependencies_and_keeps_every_occurrence_line(estate):
    import xml.etree.ElementTree as ET

    application, ids = estate
    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as client:
        response = await client.get("/api/v1/cbom/portfolio?fmt=xml")
    assert response.status_code == 200
    root = ET.fromstring(response.text)
    ns = {"c": root.tag.split("}")[0].strip("{")}
    top = root.find("c:dependencies", ns)
    assert all(child.tag.endswith("dependency") for child in top)
    payments = [d for d in top.findall("c:dependency", ns) if d.get("ref") == "system:payments-api"][0]
    assert {d.get("ref") for d in payments.findall("c:dependency", ns)} >= {"system:hsm-gateway", ids["aes_gcm"]}
    lines = [el.text for el in root.findall(".//c:occurrence/c:line", ns)]
    assert "41" in lines
