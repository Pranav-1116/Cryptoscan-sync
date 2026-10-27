"""End-to-end pipeline run over a *representative* GCC (Qatar + Bahrain) bank estate — QCB / PDPPL / CBB / Bahrain PDPL.

Not any real bank's code. The 22 blind-labelled wave-19 corpus files are laid out as the business systems a Gulf bank
with a Doha and a Manama entity would declare in ``cryptoscan-systems.yml``, each with its own ``compliance_scopes``.
Beyond what the SNB / UAE runs assert (accuracy through the pipeline, per-file scopes, persisted systems), this one
pins the **cross-jurisdiction guarantee**: the Qatari KYC store tagged ``[PDPPL, PERSONAL_DATA]`` is judged under the
Qatar pack only — no UAE PDPL/DIFC/ADGM, no Bahrain PDPL — and vice versa for the Bahraini eKYC system.
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
from worker.pipeline.pipeline_runner import PipelineRunner

ROOT = Path(__file__).resolve().parents[4]
for p in ("services/scanner", "services/scanner/tests", "shared/shared_models"):
    if str(ROOT / p) not in sys.path:
        sys.path.insert(0, str(ROOT / p))

from accuracy.corpus import canonical_families, spec_families  # noqa: E402
from accuracy.corpus_wave19_gcc_bank import register  # noqa: E402

# business system → (repo path, files, compliance scopes)
LAYOUT: dict[str, tuple[str, set[str], list[str]]] = {
    "QA-HIMYAN-SWITCH": ("qa/card-switch", {"HimyanPinBlockTranslator.java", "CBHIMPIN.cbl"}, ["QCB", "PAYMENT", "CARD"]),
    "QA-FAWRAN-IPP": ("qa/fawran", {"FawranIso20022Signer.java", "fawran-cutoff-schedule.yaml"}, ["QCB", "PAYMENT"]),
    "QA-QMP-WALLET": ("qa/qmp", {"QmpWalletTokenService.cs", "QmpDeviceBinding.swift", "i18n.ar-QA.json"}, ["QCB", "CUSTOMER-FACING"]),
    "QA-NAS-IDENTITY": ("qa/identity", {"NasOidcValidator.cs"}, ["QCB", "CUSTOMER-FACING"]),
    "QA-KYC-VAULT": ("qa/kyc", {"pkg_qid_vault.pks", "qid_validate.py"}, ["PDPPL", "PERSONAL_DATA"]),
    "QA-REG-REPORTING": ("qa/reporting", {"qcb_fx_report_signer.py", "README.ar.md"}, ["QCB"]),
    "BH-BENEFIT-SWITCH": ("bh/benefit", {"fawri_plus_hmac.go", "benefitpay_qr_signer.go", "BenefitPaySdk.kt", "benefit-sftp-sshd_config"}, ["CBB", "PAYMENT"]),
    "BH-OPEN-BANKING": ("bh/obf", {"openBankingBh.ts"}, ["CBB", "OPEN-BANKING", "CUSTOMER-FACING"]),
    "BH-EKYC": ("bh/ekyc", {"benefit_ekyc_client.py", "legacy_cpr_hash.sql"}, ["BH-PDPL", "PERSONAL_DATA"]),
    "GCC-EDGE-INFRA": ("infra", {"paloalto-ssl-decrypt.set", "f5-clientssl.tmsh", "cisco-asa-ssl.cfg"}, ["QCB", "CBB", "REMOTE-ACCESS"]),
}
DEPENDS = {"QA-HIMYAN-SWITCH": ["QA-KYC-VAULT"], "QA-QMP-WALLET": ["QA-NAS-IDENTITY", "QA-KYC-VAULT"], "BH-OPEN-BANKING": ["BH-EKYC"], "BH-BENEFIT-SWITCH": ["BH-EKYC"]}
CRITICALITY = {"QA-HIMYAN-SWITCH": "critical", "QA-FAWRAN-IPP": "critical", "BH-BENEFIT-SWITCH": "critical", "QA-QMP-WALLET": "high", "QA-NAS-IDENTITY": "high",
               "QA-KYC-VAULT": "critical", "BH-OPEN-BANKING": "high", "BH-EKYC": "high", "QA-REG-REPORTING": "medium", "GCC-EDGE-INFRA": "medium"}
FAIL = {"NON_COMPLIANT", "FAIL", "VIOLATION"}
UAE_RULES = {"CBUAE-002", "CBUAE-003", "CBUAE-004", "CBUAE-005", "PDPL-001", "PDPL-002", "DIFC-001", "DIFC-002", "ADGM-001"}
QA_RULES = {"QCB-001", "QCB-002", "QCB-003", "PDPPL-001", "PDPPL-002"}
BH_RULES = {"CBB-001", "CBB-002", "CBB-003", "BHPDPL-001", "BHPDPL-002"}
JWT_EXPANSION = {"RSA", "ECDSA", "HMAC", "SHA-256", "SHA-384", "SHA-512", "ED25519"}


def _cases() -> list[tuple[str, str, str, set[str], str]]:
    out: list = []
    register(lambda lang, fname, code, expected, category="positive": out.append((lang, fname, code.strip("\n") + "\n", set(expected), category)))
    return out


def _estate(root: Path) -> tuple[Path, dict[str, set[str]]]:
    repo = root / "gcc-estate"
    labels: dict[str, set[str]] = {}
    where = {f: sys_ for sys_, (_, files, _s) in LAYOUT.items() for f in files}
    cases = _cases()
    assert set(where) == {c[1] for c in cases}, set(where) ^ {c[1] for c in cases}
    for _lang, fname, code, expected, _cat in cases:
        rel = Path(LAYOUT[where[fname]][0]) / fname
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(code, encoding="utf-8")
        labels[str(rel)] = expected
    lines = ["systems:"]
    for system, (path, _files, scopes) in LAYOUT.items():
        lines.append(f"  - system: {system}\n    paths: [{path}/**]\n    criticality: {CRITICALITY[system]}\n    owner: {system.lower()}@bank.gcc.example")
        if scopes:
            lines.append(f"    compliance_scopes: {scopes}")
        if DEPENDS.get(system):
            lines.append(f"    depends_on: {DEPENDS[system]}")
    (repo / "cryptoscan-systems.yml").write_text("\n".join(lines) + "\n")
    return repo, labels


def _families(row: EvidenceRecord) -> set[str]:
    fd = row.finding_data if isinstance(row.finding_data, dict) else {}
    crypto = fd.get("crypto") or {}
    fams = canonical_families(crypto.get("algorithm") or row.algorithm)
    lang = str(((fd.get("source") or {}).get("language")) or "").upper()
    if lang in {"JAVA", "KOTLIN", "SCALA"}:
        fams |= spec_families(crypto.get("hash_algorithm"))
    return fams


def _path(row: EvidenceRecord) -> str:
    return str(row.file_path).split("!", 1)[0].lstrip("./")


APPLIED = {"PASS", "FAIL", "WARN"}  # out-of-scope rules are recorded as NOT_APPLICABLE ("Finding is outside required scopes")


def _rules(row: EvidenceRecord, status: set[str] = APPLIED) -> set[str]:
    ev = row.policy_evaluation or {}
    return {r["rule_id"] for r in ev.get("rules_evaluated", []) if str(r.get("evaluation_result", "")).upper() in status}


@pytest.mark.timeout(300)
def test_gcc_profile_estate_end_to_end(tmp_path, estate_db):
    test_db = estate_db
    runner = PipelineRunner()
    repo, labels = _estate(tmp_path)
    ws = tmp_path / "ws"
    ws.mkdir()
    scan_id = runner.run(job_id="job-gcc-code", target_repo=f"local://{repo}", target_branch="main", triggered_by="gcc-pilot", db=test_db, workspace_dir=str(ws))
    scan = test_db.get(Scan, scan_id)
    assert scan.status == "COMPLETED", scan.error_message
    rows = test_db.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == scan_id)).scalars().all()
    assert rows

    # ---- 1. discovery accuracy through the pipeline -------------------------------------------------
    predicted: dict[str, set[str]] = {p: set() for p in labels}
    for r in rows:
        if _path(r) in predicted:
            predicted[_path(r)] |= _families(r)
    tp = fn = fp = 0
    misses: list[str] = []
    for path, exp in labels.items():
        got = predicted[path]
        if "JWT" in exp:
            got = got - JWT_EXPANSION | (got & exp)
        tp += len(exp & got)
        fn += len(exp - got)
        fp += len(got - exp)
        if exp ^ got:
            misses.append(f"{path}: FN={sorted(exp - got)} FP={sorted(got - exp)}")
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    assert precision >= 0.97 and recall >= 0.97, (precision, recall, "\n".join(misses))
    assert (len(labels) - len(misses)) / len(labels) >= 0.95, misses
    for neg in ("qa/reporting/README.ar.md", "qa/qmp/i18n.ar-QA.json", "qa/kyc/qid_validate.py", "qa/fawran/fawran-cutoff-schedule.yaml"):
        assert predicted[neg] == set(), (neg, predicted[neg])

    # ---- 2. per-file compliance scopes ---------------------------------------------------------------
    by_system: dict[str, list[EvidenceRecord]] = {}
    for r in rows:
        for name, (path, _f, _s) in LAYOUT.items():
            if _path(r).startswith(path + "/"):
                by_system.setdefault(name, []).append(r)
    assert set(by_system) == set(LAYOUT), set(LAYOUT) - set(by_system)
    for name, (_p, _f, scopes) in LAYOUT.items():
        for r in by_system[name]:
            assert set((r.finding_data or {}).get("compliance_scopes") or []) == set(scopes), (name, _path(r))

    # ---- 3. jurisdiction packs follow the declared regulator, never the generic data tag ------------
    fired: dict[str, set[str]] = {name: set() for name in LAYOUT}
    failed: dict[str, set[str]] = {name: set() for name in LAYOUT}
    for name, rs in by_system.items():
        for r in rs:
            fired[name] |= _rules(r)
            failed[name] |= _rules(r, FAIL)
    # nothing in this estate is UAE: the UAE gated pack never evaluates anywhere
    for name in LAYOUT:
        assert not (fired[name] & UAE_RULES), (name, fired[name] & UAE_RULES)
    # Qatar-only systems see no Bahrain rules and vice versa
    for name in ("QA-HIMYAN-SWITCH", "QA-FAWRAN-IPP", "QA-QMP-WALLET", "QA-NAS-IDENTITY", "QA-KYC-VAULT", "QA-REG-REPORTING"):
        assert not (fired[name] & BH_RULES), (name, fired[name] & BH_RULES)
    for name in ("BH-BENEFIT-SWITCH", "BH-OPEN-BANKING", "BH-EKYC"):
        assert not (fired[name] & QA_RULES), (name, fired[name] & QA_RULES)
    # the personal-data stores: PDPPL for Doha, Bahrain PDPL for Manama — and no QCB/CBB gated rules on either
    assert {"PDPPL-001", "PDPPL-002"} & fired["QA-KYC-VAULT"] and not (fired["QA-KYC-VAULT"] & {"QCB-001", "QCB-002", "QCB-003", "BHPDPL-001", "BHPDPL-002"})
    assert "BHPDPL-001" in failed["BH-EKYC"], failed["BH-EKYC"]  # SHA-1 over CPR numbers
    assert not (fired["BH-EKYC"] & {"CBB-001", "CBB-002", "CBB-003", "PDPPL-001", "PDPPL-002"})
    # concrete verdicts
    assert "QCB-001" in failed["QA-HIMYAN-SWITCH"], failed["QA-HIMYAN-SWITCH"]  # TDES PIN translation
    assert {"QCB-002", "CBB-002"} <= failed["GCC-EDGE-INFRA"], failed["GCC-EDGE-INFRA"]  # Palo Alto min-version tls1-0 / tls1-1 on shared edge
    assert "CBB-002" not in failed["BH-OPEN-BANKING"] and "CBB-001" not in failed["BH-OPEN-BANKING"], failed["BH-OPEN-BANKING"]  # PS256 + SHA-256 only
    # the hardened ASA (TLS 1.2 only, AES-GCM, group14/19) must not fail the TLS floors
    asa = [r for r in by_system["GCC-EDGE-INFRA"] if _path(r).endswith("cisco-asa-ssl.cfg")]
    assert asa and not any({"QCB-002", "CBB-002"} & _rules(r, FAIL) for r in asa), [(r.algorithm, _rules(r, FAIL)) for r in asa]
    assert all(r.content_hash and r.chain_hash for r in rows)

    # ---- 4. declared systems persisted ---------------------------------------------------------------
    persisted = {s.name: s for s in test_db.execute(select(System)).scalars().all()}
    assert set(LAYOUT) <= set(persisted)
    for name, (_p, _f, scopes) in LAYOUT.items():
        assert set(persisted[name].compliance_scopes or []) == set(scopes) and persisted[name].criticality == CRITICALITY[name], name
    edges = {(e.parent_id, e.child_id) for e in test_db.execute(select(SystemDependency)).scalars().all()}
    for parent, children in DEPENDS.items():
        for child in children:
            assert (persisted[parent].id, persisted[child].id) in edges, (parent, child)
    cascade = scan.statistics["cascade"]
    systems = {s["system"]: s for s in cascade["systems"]}
    assert set(systems) == set(LAYOUT)
    assert "3DES" in systems["QA-HIMYAN-SWITCH"]["algorithms"]
