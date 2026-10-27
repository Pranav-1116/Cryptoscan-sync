"""End-to-end through the real PipelineRunner (SQLite, local:// repos, real scanner):

  1. a source repository with cryptoscan-systems.yml  → cascade persisted, systems rollup, key_references
  2. a key-export drop (CRYPTOSCAN_KEY_INVENTORY=1)   → KEY_INVENTORY evidence, KEYINV policy results,
                                                        certificates table rows, reconciliation + drift events
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from db.models.certificate import Certificate
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from worker.pipeline.pipeline_runner import PipelineRunner

FIXTURES = Path(__file__).resolve().parents[4] / "services" / "scanner" / "tests" / "fixtures" / "key_inventory"


def _source_repo(root: Path) -> Path:
    repo = root / "core-banking"
    (repo / "core/src/main/java/com/bank/core").mkdir(parents=True)
    (repo / "cards/src/main/java/com/bank/cards").mkdir(parents=True)
    (repo / "core/src/main/java/com/bank/core/CryptoUtil.java").write_text(
        "package com.bank.core;\nimport javax.crypto.Cipher;\nimport java.security.KeyStore;\n"
        "public class CryptoUtil {\n  static final String KS = \"payments.jks\";\n"
        "  public static Cipher aes() throws Exception { return Cipher.getInstance(\"AES/GCM/NoPadding\"); }\n"
        "  public static KeyStore ks() throws Exception { KeyStore k = KeyStore.getInstance(\"JKS\"); return k; }\n}\n")
    (repo / "cards/src/main/java/com/bank/cards/CardSigner.java").write_text(
        "package com.bank.cards;\nimport com.bank.core.CryptoUtil;\nimport java.security.KeyPairGenerator;\n"
        "public class CardSigner {\n  void gen() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance(\"RSA\"); g.initialize(1024); CryptoUtil.aes(); }\n"
        "  String alias = \"PAY.ZPK.ACQ001\";\n}\n")
    (repo / "cryptoscan-systems.yml").write_text(
        "systems:\n  - system: CORE-CRYPTO-LIB\n    paths: [core/]\n    criticality: high\n    owner: platform@bank\n"
        "  - system: CARDS\n    paths: [cards/**]\n    criticality: critical\n")
    return repo


def _key_drop(root: Path) -> Path:
    drop = root / "key-exports"
    drop.mkdir()
    for name in ("ckds.lst", "keytool.txt", "racdcert.txt", "payshield-export.txt"):
        shutil.copy(FIXTURES / name, drop / name)
    return drop


def _run(runner, db, tmp_path, target: Path, job_id: str) -> str:
    ws = tmp_path / f"ws-{job_id}"
    ws.mkdir()
    return runner.run(job_id=job_id, target_repo=f"local://{target}", target_branch="main", triggered_by="e2e", db=db, workspace_dir=str(ws))


@pytest.mark.timeout(180)
def test_estate_pipeline_source_then_key_inventory(tmp_path, test_db, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_KEY_INVENTORY", "1")
    runner = PipelineRunner()

    # ---- 1. source repository ---------------------------------------------------------------
    src_repo = _source_repo(tmp_path)
    src_scan_id = _run(runner, test_db, tmp_path, src_repo, "job-src")
    src = test_db.get(Scan, src_scan_id)
    assert src.status == "COMPLETED", src.error_message
    stats = src.statistics
    assert stats["evidence_sources"].get("SOURCE_CODE", 0) >= 3
    cascade = stats["cascade"]
    systems = {s["system"]: s for s in cascade["systems"]}
    assert systems["CARDS"]["depends_on_systems"] == ["CORE-CRYPTO-LIB"] and systems["CORE-CRYPTO-LIB"]["dependent_systems"] == ["CARDS"]
    assert systems["CORE-CRYPTO-LIB"]["criticality"] == "high" and systems["CORE-CRYPTO-LIB"]["providers"] >= 1
    refs = {(r["kind"], r["identifier"]) for r in cascade["key_references"]}
    assert ("key_file", "payments.jks") in refs and ("key_alias", "PAY.ZPK.ACQ001") in refs
    assert any(w["algorithm"] == "RSA" and w["key_size"] == 1024 for w in cascade["weak_parameters"])
    assert cascade["truncated"]["providers"] == 0
    # declared systems are persisted: DB System rows, asset ownership and dependency edges (portfolio CBOM / graph)
    from db.models.system import System
    from db.models.system_dependency import SystemDependency
    from db.repositories.system_repository import SystemRepository
    srepo = SystemRepository(test_db)
    core, cards = srepo.get_by_name("CORE-CRYPTO-LIB"), srepo.get_by_name("CARDS")
    assert core is not None and cards is not None
    assert core.criticality == "high" and core.owner == "platform@bank"
    assert {a.file_path.split("/")[0] for a in srepo.assets_for(core.id)} == {"core"}
    assert len(srepo.assets_for(cards.id)) >= 1
    edges = {(e.parent_id, e.child_id, e.relation) for e in test_db.execute(select(SystemDependency)).scalars().all()}
    assert (cards.id, core.id, "imports-crypto") in edges
    repo_sys = [s for s in test_db.execute(select(System)).scalars().all() if s.id not in (core.id, cards.id)]
    assert repo_sys and (repo_sys[0].id, core.id, "contains") in edges
    # idempotent: a second scan of the same repo adds no duplicate systems/edges
    src_scan_id_2 = _run(runner, test_db, tmp_path, src_repo, "job-src-2")
    assert len(test_db.execute(select(System)).scalars().all()) == 3
    assert len(test_db.execute(select(SystemDependency)).scalars().all()) == len(edges)
    # no key-inventory drift on a code scan
    assert test_db.execute(select(DriftEvent).where(DriftEvent.current_scan_id == src_scan_id)).scalars().all() == []

    # ---- 2. key-export drop ------------------------------------------------------------------
    inv_scan_id = _run(runner, test_db, tmp_path, _key_drop(tmp_path), "job-inv")
    inv = test_db.get(Scan, inv_scan_id)
    assert inv.status == "COMPLETED", inv.error_message
    assert inv.statistics["evidence_sources"]["KEY_INVENTORY"] >= 15
    rows = test_db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == inv_scan_id)).scalars().all()
    inv_rows = [r for r in rows if (r.finding_data.get("source") or {}).get("type") == "KEY_INVENTORY"]
    assert inv_rows and all(r.finding_data.get("inventory") is not None for r in inv_rows)

    # policy: KEYINV rules evaluated on export records (expired cert in keytool.txt, TR-31 A in the payShield export)
    keyinv = {}
    for r in inv_rows:
        for res in (r.policy_evaluation or {}).get("rules_evaluated") or []:
            if res["rule_id"].startswith("KEYINV"):
                keyinv.setdefault(res["rule_id"], set()).add(res["evaluation_result"])
    assert "FAIL" in keyinv.get("KEYINV-003", set()), keyinv  # expired ebank-tls certificate
    assert "FAIL" in keyinv.get("KEYINV-002", set()), keyinv  # TR-31 version A key block
    assert all(res["evaluation_result"] == "NOT_APPLICABLE" for r in test_db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == src_scan_id)).scalars()
               for res in (r.policy_evaluation or {}).get("rules_evaluated") or [] if res["rule_id"].startswith("KEYINV"))

    # certificates table: export-discovered certificates with derived fingerprints
    certs = test_db.execute(select(Certificate)).scalars().all()
    assert certs and all((c.extra or {}).get("source") == "KEY_INVENTORY" and (c.extra or {}).get("fingerprint_derived") for c in certs)
    assert any("ebank" in (c.subject or "") and c.expiry_status == "EXPIRED" for c in certs)

    # reconciliation against the source scan + drift events without any approved baseline
    rec = inv.statistics["key_reconciliation"]
    assert rec["source_scans"] == [src_scan_id_2] and rec["summary"]["consumers"] >= 1  # latest scan of the repo wins  # PAY.ZPK.ACQ001 used by CardSigner
    assert any(o["label"] == "PAY.ZMK.VISA" for o in rec["orphans"])
    assert any(n["identifier"] == "payments.jks" for n in rec["not_in_inventory"])
    drift = test_db.execute(select(DriftEvent).where(DriftEvent.current_scan_id == inv_scan_id)).scalars().all()
    types = {d.drift_type for d in drift}
    assert {"KEY_ORPHAN", "KEY_UNACCOUNTED"} <= types and all(d.baseline_id is None for d in drift)
    assert any(d.drift_type == "KEY_UNACCOUNTED" and d.drift_details["identifier"] == "payments.jks" and d.severity == "HIGH" for d in drift)

    # ---- 3. same export again: nothing new → no new drift events --------------------------------
    inv2_scan_id = _run(runner, test_db, tmp_path, tmp_path / "key-exports", "job-inv2")
    assert test_db.get(Scan, inv2_scan_id).status == "COMPLETED"
    assert test_db.execute(select(DriftEvent).where(DriftEvent.current_scan_id == inv2_scan_id)).scalars().all() == []
    assert test_db.get(Scan, inv2_scan_id).statistics["key_reconciliation"]["previous_inventory_scan"] == inv_scan_id
    assert len(test_db.execute(select(Certificate)).scalars().all()) == len(certs)  # idempotent upsert
