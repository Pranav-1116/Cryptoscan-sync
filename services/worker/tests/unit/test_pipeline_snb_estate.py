"""End-to-end: a Saudi-bank (SNB-profile) estate through the real PipelineRunner.

The wave-16 blind corpus (mada switch, SARIE/SWIFT, SADAD, ZATCA e-invoicing, Nafath, SAMA-CSF hardening,
core COBOL/ICSF, Oracle/SQL Server, mobile, Arabic-commented code) is laid out as one repository with a
``cryptoscan-systems.yml`` naming the bank's systems, and an HSM/KMS key-export drop shaped like the same
estate (payShield LMK export, Luna partition, ICSF CKDS, keytool). The test asserts what a bank pilot would
check:

* discovery accuracy **through the pipeline** (evidence rows in the DB, not scan_file) against the labels;
* the systems rollup, persisted systems/edges and the migration-relevant cascade facts;
* policy verdicts on the SAMA-relevant weak spots (RC4/TLS1.0 GPO, MD5 password hash, 1024-bit RSA…);
* key reconciliation between the HSM export and the key identifiers the code references.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import select

from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.system import System
from db.models.system_dependency import SystemDependency
from db.repositories.system_repository import SystemRepository
from evidence.intelligence.key_reconciliation import reconcile_key_inventory
from worker.pipeline.pipeline_runner import PipelineRunner

ROOT = Path(__file__).resolve().parents[4]
FIXTURES = ROOT / "services" / "scanner" / "tests" / "fixtures" / "key_inventory"
for p in ("services/scanner", "services/scanner/tests", "shared/shared_models"):
    if str(ROOT / p) not in sys.path:
        sys.path.insert(0, str(ROOT / p))

from accuracy.corpus import canonical_families, spec_families  # noqa: E402
from accuracy.corpus_wave16_saudi_bank import register  # noqa: E402

# repo layout: corpus language dir → business system path
LAYOUT = {
    "MADA-SWITCH": ("mada-switch/src/main/java", {"MadaPinTranslator.java", "MadaCvvService.java", "PayShieldKeyBlockExporter.java", "Tr34RemoteKeyLoader.java"}),
    "SARIE-HUB": ("sarie-hub", {"SarieLauSigner.java", "sarie-alliance-gateway.xml", "CBTRFENC.cbl", "SARIEKEY.jcl"}),
    "SADAD-GATEWAY": ("sadad", {"SadadBillerClient.cs", "SadadBillModels.cs"}),
    "ZATCA-EINVOICE": ("zatca", {"ZatcaInvoiceSigner.cs", "ZatcaCsrBuilder.cs"}),
    "DIGITAL-IDENTITY": ("identity", {"NafathTokenValidator.cs", "yakeen_client.py", "otpService.ts", "openBankingJws.js"}),
    "CORE-LEDGER": ("core-ledger", {"AlwaysEncryptedIban.cs", "tde_core_ledger.sql", "pkg_customer_pii.pks", "legacy_pwd_hash.sql", "CBPINVER.cbl", "CBSTMTAR.cbl", "HijriDateConverter.java", "iban_validate.py", "iban_tokenizer.go"}),
    "SNB-MOBILE": ("mobile", {"SecureStore.kt", "PinnedClient.kt", "DeviceBinding.swift"}),
    "INFRA-HARDENING": ("infra", {"sama-csf-tls.conf", "krb5.conf", "legacy-branch-gpo.inf", "mq-ams-policy.yaml", "was-ssl.properties", "sama-reporting-schedule.yaml", "payshield-lmk-migration.hsm", "simah_report_cipher.py"}),
}
DEPENDS = {"MADA-SWITCH": ["CORE-LEDGER"], "SARIE-HUB": ["CORE-LEDGER"], "SADAD-GATEWAY": ["CORE-LEDGER"], "DIGITAL-IDENTITY": ["CORE-LEDGER"], "SNB-MOBILE": ["DIGITAL-IDENTITY"]}
CRITICALITY = {"MADA-SWITCH": "critical", "SARIE-HUB": "critical", "CORE-LEDGER": "critical", "SADAD-GATEWAY": "high", "ZATCA-EINVOICE": "high", "DIGITAL-IDENTITY": "high", "SNB-MOBILE": "high", "INFRA-HARDENING": "medium"}


def _cases() -> list[tuple[str, str, str, set[str], str]]:
    out: list = []
    register(lambda lang, fname, code, expected, category="positive": out.append((lang, fname, code.strip("\n") + "\n", set(expected), category)))
    return out


def _estate(root: Path) -> tuple[Path, dict[str, set[str]]]:
    repo = root / "snb-estate"
    labels: dict[str, set[str]] = {}
    where = {f: sys_ for sys_, (_, files) in LAYOUT.items() for f in files}
    for lang, fname, code, expected, _cat in _cases():
        system = where[fname]
        rel = Path(LAYOUT[system][0]) / fname
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(code, encoding="utf-8")
        labels[str(rel)] = expected
    lines = ["systems:"]
    for system, (path, _files) in LAYOUT.items():
        lines.append(f"  - system: {system}\n    paths: [{path}/**]\n    criticality: {CRITICALITY[system]}\n    owner: {system.lower()}@snb.example")
        if DEPENDS.get(system):
            lines.append(f"    depends_on: {DEPENDS[system]}")
    (repo / "cryptoscan-systems.yml").write_text("\n".join(lines) + "\n")
    return repo, labels


def _key_drop(root: Path) -> Path:
    drop = root / "snb-key-exports"
    drop.mkdir()
    for name in ("payshield-export.txt", "luna-cmu.txt", "ckds.lst", "keytool.txt"):
        (drop / name).write_text((FIXTURES / name).read_text())
    # the mada / SARIE keys the code actually names (labels reconciled against key_references)
    (drop / "ckds-mada.lst").write_text((FIXTURES / "ckds.lst").read_text()
                                        .replace("PAY.ZPK.ACQ001", "MADA.ZPK.ACQ.001").replace("payments.jks", "sarie-client.p12"))
    return drop


def _run(runner, db, tmp_path, target: Path, job_id: str) -> str:
    ws = tmp_path / f"ws-{job_id}"
    ws.mkdir()
    return runner.run(job_id=job_id, target_repo=f"local://{target}", target_branch="main", triggered_by="snb-pilot", db=db, workspace_dir=str(ws))


JWT_EXPANSION = {"RSA", "ECDSA", "HMAC", "SHA-256", "SHA-384", "SHA-512", "ED25519"}  # the pipeline resolves PS256/ES256/HS256 to primitives


def _families(row: EvidenceRecord) -> set[str]:
    # EvidenceRecord.algorithm is the *normalised family* (SHA-256 → "SHA2"); score the scanner's algorithm name kept in finding_data
    fd = row.finding_data if isinstance(row.finding_data, dict) else {}
    crypto = fd.get("crypto") or {}
    fams = canonical_families(crypto.get("algorithm") or row.algorithm)
    lang = str(((fd.get("source") or {}).get("language")) or "").upper()
    if lang in {"JAVA", "KOTLIN", "SCALA"}:
        fams |= spec_families(crypto.get("hash_algorithm"))
    return fams


@pytest.mark.timeout(300)
def test_snb_profile_estate_end_to_end(tmp_path, estate_db, monkeypatch):
    test_db = estate_db
    monkeypatch.setenv("CRYPTOSCAN_KEY_INVENTORY", "1")
    runner = PipelineRunner()
    repo, labels = _estate(tmp_path)

    # ---- 1. the bank's code estate -----------------------------------------------------------
    scan_id = _run(runner, test_db, tmp_path, repo, "job-snb-code")
    scan = test_db.get(Scan, scan_id)
    assert scan.status == "COMPLETED", scan.error_message
    rows = test_db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars().all()
    assert rows, "no evidence persisted"

    # discovery accuracy *through the pipeline* (dedup, normalisation, DB) against the blind labels
    predicted: dict[str, set[str]] = {p: set() for p in labels}
    for r in rows:
        path = str(r.file_path).split("!", 1)[0].lstrip("./")
        if path in predicted:
            predicted[path] |= _families(r)
    tp = fn = fp = 0
    misses: list[str] = []
    for path, exp in labels.items():
        got = predicted[path]
        if "JWT" in exp:
            got = got - JWT_EXPANSION | (got & exp)
        tp += len(exp & got)
        fn += len(exp - got)
        fp += len(got - exp)
        if exp - got or got - exp:
            misses.append(f"{path}: FN={sorted(exp - got)} FP={sorted(got - exp)}")
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    exact = len(labels) - len(misses)
    assert precision >= 0.97 and recall >= 0.97, (precision, recall, "\n".join(misses))
    assert exact / len(labels) >= 0.95, misses
    # the five Arabic-commented negatives stay silent (Hijri dates, IBAN mod-97, SADAD models, statement print, SAMA schedule)
    for neg in ("core-ledger/HijriDateConverter.java", "core-ledger/iban_validate.py", "sadad/SadadBillModels.cs", "core-ledger/CBSTMTAR.cbl", "infra/sama-reporting-schedule.yaml"):
        assert predicted[neg] == set(), (neg, predicted[neg])

    # ---- 2. estate structure: systems rollup, persisted systems + edges, cascade facts -----------
    stats = scan.statistics
    cascade = stats["cascade"]
    systems = {s["system"]: s for s in cascade["systems"]}
    assert set(systems) == set(LAYOUT)
    assert systems["MADA-SWITCH"]["criticality"] == "critical" and systems["MADA-SWITCH"]["files"] >= 4
    assert "3DES" in systems["MADA-SWITCH"]["algorithms"], "mada PIN/CVV path must surface TDES on the switch"
    assert any(w["algorithm"] == "RSA" and w["key_size"] == 1024 for w in cascade["weak_parameters"]) is False  # no 1024-bit RSA declared in this estate
    refs = {(r["kind"], r["identifier"]) for r in cascade["key_references"]}
    assert ("key_alias", "MADA.ZPK.ACQ.001") in refs or any(i == "MADA.ZPK.ACQ.001" for _, i in refs), sorted(refs)[:20]
    srepo = SystemRepository(test_db)
    persisted = {s.name: s for s in test_db.execute(select(System)).scalars().all()}
    assert set(LAYOUT) <= set(persisted)
    assert persisted["MADA-SWITCH"].criticality == "critical" and persisted["INFRA-HARDENING"].criticality == "medium"
    owned = {name: {a.file_path.split("/")[0] for a in srepo.assets_for(persisted[name].id)} for name in LAYOUT}
    assert owned["SNB-MOBILE"] == {"mobile"} and owned["CORE-LEDGER"] == {"core-ledger"} and owned["INFRA-HARDENING"] == {"infra"}
    edges = {(e.parent_id, e.child_id) for e in test_db.execute(select(SystemDependency)).scalars().all()}
    for parent, children in DEPENDS.items():
        for child in children:
            assert (persisted[parent].id, persisted[child].id) in edges, (parent, child)

    # ---- 3. SAMA-relevant policy verdicts on the weak spots ---------------------------------------
    by_file: dict[str, list[EvidenceRecord]] = {}
    for r in rows:
        by_file.setdefault(str(r.file_path).split("!", 1)[0].lstrip("./"), []).append(r)

    def verdicts(path: str) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {}
        for r in by_file.get(path, []):
            out.setdefault(r.algorithm.upper(), set()).add(str(r.compliance_status or "").upper())
        return out

    gpo = verdicts("infra/legacy-branch-gpo.inf")
    assert "RC4" in gpo and gpo["RC4"] & {"NON_COMPLIANT", "FAIL", "VIOLATION"}, gpo
    # the DB column carries the normaliser's display name ("TLS 1.0"); the policy engine must still FAIL it (BASELINE-005 lists "TLS1.0")
    tls10 = {k: v for k, v in gpo.items() if k.replace(" ", "").upper() == "TLS1.0"}
    assert tls10 and all(v & {"NON_COMPLIANT", "FAIL", "VIOLATION"} for v in tls10.values()), gpo
    legacy = verdicts("core-ledger/legacy_pwd_hash.sql")
    assert legacy.get("MD5") & {"NON_COMPLIANT", "FAIL", "VIOLATION"}, legacy
    hardened = verdicts("infra/sama-csf-tls.conf")
    assert not any(v & {"NON_COMPLIANT", "FAIL", "VIOLATION"} for k, v in hardened.items() if k.startswith(("TLS1.2", "TLS1.3", "AES", "X25519"))), hardened
    # every record is on the evidence chain with a content hash
    assert all(r.content_hash and r.chain_hash for r in rows)

    # ---- 4. HSM / KMS key export drop → reconciliation against the code ----------------------------
    inv_scan_id = _run(runner, test_db, tmp_path, _key_drop(tmp_path), "job-snb-keys")
    inv = test_db.get(Scan, inv_scan_id)
    assert inv.status == "COMPLETED", inv.error_message
    assert inv.statistics["evidence_sources"].get("KEY_INVENTORY", 0) >= 15
    rec = inv.statistics["key_reconciliation"]
    assert scan_id in rec["source_scans"]
    # stats keep summary/orphans/not_in_inventory; consumers come from the same pure join the API serves
    src = test_db.get(Scan, scan_id)
    refs = [(scan_id, r) for r in (src.statistics["cascade"].get("key_references") or [])]
    inventory = [r.finding_data for r in test_db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == inv_scan_id)).scalars()
                 if ((r.finding_data or {}).get("source") or {}).get("type") == "KEY_INVENTORY"]
    full = reconcile_key_inventory(inventory, refs)
    assert full["summary"] == rec["summary"]
    consumers = {c["label"] for c in full["consumers"]}
    assert "MADA.ZPK.ACQ.001" in consumers, (consumers, rec["summary"])
    assert rec["summary"]["orphans"] >= 1 and rec["summary"]["not_in_inventory"] >= 1
    unaccounted = {n["identifier"] for n in rec["not_in_inventory"]}
    assert {"MADA.PVK.2024A", "SARIE.OUT.AES256.DATA"} & unaccounted, unaccounted
