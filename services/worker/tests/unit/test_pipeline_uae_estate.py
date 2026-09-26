"""End-to-end pipeline run over a *representative* UAE-bank estate (CBUAE / PDPL / DIFC profile).

Not any real bank's code. The 24 blind-labelled wave-18 corpus files are laid out as the business systems a UAE
retail bank would declare in ``cryptoscan-systems.yml`` — UAESWITCH/Jaywan card switch, Aani instant payments,
Open Finance (Nebras FAPI), UAE PASS identity, T24 core + KYC, WPS/FTA regulatory filing, mobile, branch
infrastructure — each with its own ``compliance_scopes``. The test then checks, through the real pipeline
(discover → scan → normalise → persist → policy → dedup → systems):

1. discovery accuracy against the blind labels (≥ 97 % P/R after normalisation + DB round-trip),
2. per-file compliance scopes = repo scopes ∪ declared-system scopes (finding_data.compliance_scopes),
3. the scope-gated UAE rules fire only in systems that carry the matching scope — PDPL/DIFC never on the
   card switch, CBUAE-003 on the branch SSL-VPN (REMOTE-ACCESS) but not on the FTA filer (no scopes),
4. declared systems persisted with scopes/criticality/dependencies.
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
from accuracy.corpus_wave18_uae_bank import register  # noqa: E402

# business system → (repo path, files, compliance scopes)
LAYOUT: dict[str, tuple[str, set[str], list[str]]] = {
    "UAESWITCH-CARD": ("card-switch/src/main/java", {"UaeSwitchPinTranslator.java", "JaywanTokenizer.kt"}, ["CBUAE", "PAYMENT", "CARD"]),
    "AANI-IPP": ("aani", {"AaniPacs008Signer.java", "aaniProxyPay.ts", "mq-aep-channel.mqsc"}, ["CBUAE", "PAYMENT"]),
    "OPEN-FINANCE": ("open-finance", {"NebrasFapiClient.cs"}, ["CBUAE", "CUSTOMER-FACING"]),
    "UAEPASS-IDENTITY": ("identity", {"UaePassSamlValidator.cs", "EmiratesIdVgClient.cs", "UaePassLogin.swift", "i18n.ar-AE.json"}, ["PDPL", "PERSONAL_DATA"]),
    "T24-CORE-KYC": ("core", {"T24OfsSessionCipher.java", "pkg_kyc_pii.pks", "legacy_customer_pwd.sql", "tde_uae_core.sql", "CBEIDENC.cbl", "iban_ae_validate.py", "README.ar.md"}, ["PDPL", "DIFC", "PERSONAL_DATA"]),
    "REG-FILING": ("reg-filing", {"wps_sif_uploader.py", "fta_peppol_as4.py", "wps-schedule.yaml"}, []),
    "BRANCH-INFRA": ("infra", {"branch-sslvpn.conf", "rdgateway.reg", "cbuae-tls-baseline.conf"}, ["CBUAE", "REMOTE-ACCESS"]),
}
DEPENDS = {"UAESWITCH-CARD": ["T24-CORE-KYC"], "AANI-IPP": ["T24-CORE-KYC"], "OPEN-FINANCE": ["UAEPASS-IDENTITY", "T24-CORE-KYC"], "UAEPASS-IDENTITY": ["T24-CORE-KYC"]}
CRITICALITY = {"UAESWITCH-CARD": "critical", "AANI-IPP": "critical", "T24-CORE-KYC": "critical", "OPEN-FINANCE": "high", "UAEPASS-IDENTITY": "high", "REG-FILING": "medium", "BRANCH-INFRA": "medium"}
FAIL = {"NON_COMPLIANT", "FAIL", "VIOLATION"}
PDPL_DIFC_RULES = {"PDPL-001", "PDPL-002", "DIFC-001", "DIFC-002", "ADGM-001"}
CBUAE_GATED = {"CBUAE-002", "CBUAE-003", "CBUAE-004", "CBUAE-005"}
JWT_EXPANSION = {"RSA", "ECDSA", "HMAC", "SHA-256", "SHA-384", "SHA-512", "ED25519"}


def _cases() -> list[tuple[str, str, str, set[str], str]]:
    out: list = []
    register(lambda lang, fname, code, expected, category="positive": out.append((lang, fname, code.strip("\n") + "\n", set(expected), category)))
    return out


def _estate(root: Path) -> tuple[Path, dict[str, set[str]]]:
    repo = root / "uae-estate"
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
        lines.append(f"  - system: {system}\n    paths: [{path}/**]\n    criticality: {CRITICALITY[system]}\n    owner: {system.lower()}@bank.ae.example")
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
        fams |= spec_families(crypto.get("raw_transformation"))
    return fams


def _path(row: EvidenceRecord) -> str:
    return str(row.file_path).split("!", 1)[0].lstrip("./")


APPLIED = {"PASS", "FAIL", "WARN"}  # out-of-scope rules are recorded as NOT_APPLICABLE ("Finding is outside required scopes")


def _rules(row: EvidenceRecord, status: set[str] = APPLIED) -> set[str]:
    ev = row.policy_evaluation or {}
    return {r["rule_id"] for r in ev.get("rules_evaluated", []) if str(r.get("evaluation_result", "")).upper() in status}


@pytest.mark.timeout(300)
def test_uae_profile_estate_end_to_end(tmp_path, test_db):
    runner = PipelineRunner()
    repo, labels = _estate(tmp_path)
    ws = tmp_path / "ws"
    ws.mkdir()
    scan_id = runner.run(job_id="job-uae-code", target_repo=f"local://{repo}", target_branch="main", triggered_by="uae-pilot", db=test_db, workspace_dir=str(ws))
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
    for neg in ("core/README.ar.md", "identity/i18n.ar-AE.json", "core/iban_ae_validate.py", "reg-filing/wps-schedule.yaml"):
        assert predicted[neg] == set(), (neg, predicted[neg])

    # ---- 2. per-file compliance scopes from the declared systems ------------------------------------
    by_system: dict[str, list[EvidenceRecord]] = {}
    for r in rows:
        top = _path(r).split("/")[0]
        for name, (path, _f, _s) in LAYOUT.items():
            if path.split("/")[0] == top:
                by_system.setdefault(name, []).append(r)
    assert set(by_system) >= {"UAESWITCH-CARD", "AANI-IPP", "OPEN-FINANCE", "UAEPASS-IDENTITY", "T24-CORE-KYC", "REG-FILING", "BRANCH-INFRA"}
    for name, (_p, _f, scopes) in LAYOUT.items():
        for r in by_system[name]:
            assert set((r.finding_data or {}).get("compliance_scopes") or []) == set(scopes), (name, _path(r), r.finding_data.get("compliance_scopes"))

    # ---- 3. scope-gated UAE rules fire only where the scope applies ---------------------------------
    fired: dict[str, set[str]] = {name: set() for name in LAYOUT}
    failed: dict[str, set[str]] = {name: set() for name in LAYOUT}
    for name, rs in by_system.items():
        for r in rs:
            fired[name] |= _rules(r)
            failed[name] |= _rules(r, FAIL)
    # card switch / Aani / open finance / infra: CBUAE-only — no personal-data rules
    for name in ("UAESWITCH-CARD", "AANI-IPP", "OPEN-FINANCE", "BRANCH-INFRA"):
        assert not (fired[name] & PDPL_DIFC_RULES), (name, fired[name] & PDPL_DIFC_RULES)
    # identity / core: PDPL (and DIFC for the core) fire; the CBUAE gated rules do not
    assert fired["UAEPASS-IDENTITY"] & {"PDPL-001", "PDPL-002"}, fired["UAEPASS-IDENTITY"]
    assert fired["T24-CORE-KYC"] & {"PDPL-002", "DIFC-002"}, fired["T24-CORE-KYC"]
    assert not (fired["UAEPASS-IDENTITY"] & CBUAE_GATED) and not (fired["T24-CORE-KYC"] & CBUAE_GATED)
    # the un-scoped regulatory filer gets no UAE scope rules at all
    assert not (fired["REG-FILING"] & (PDPL_DIFC_RULES | CBUAE_GATED)), fired["REG-FILING"]
    # concrete verdicts: TLS 1.0 on the branch SSL-VPN / RD Gateway is a CBUAE-003 FAIL (REMOTE-ACCESS)
    assert "CBUAE-003" in failed["BRANCH-INFRA"], failed["BRANCH-INFRA"]
    # 3DES PIN translation on the switch is a CBUAE-001 FAIL, and DES/MD5 in core is PDPL-002 + DIFC-002 FAIL
    assert "CBUAE-001" in failed["UAESWITCH-CARD"], failed["UAESWITCH-CARD"]
    assert {"PDPL-002", "DIFC-002"} <= failed["T24-CORE-KYC"], failed["T24-CORE-KYC"]
    # the hardened CBUAE TLS baseline itself stays clean
    baseline = [r for r in by_system["BRANCH-INFRA"] if _path(r).endswith("cbuae-tls-baseline.conf")]
    assert baseline and not any(_rules(r, FAIL) for r in baseline if r.algorithm.upper().replace(" ", "") in {"TLS1.2", "TLS1.3", "AES", "X25519"}), [(r.algorithm, _rules(r, FAIL)) for r in baseline]
    assert all(r.content_hash and r.chain_hash for r in rows)

    # ---- 4. declared systems persisted with scopes, criticality and dependencies -----------------
    persisted = {s.name: s for s in test_db.execute(select(System)).scalars().all()}
    assert set(LAYOUT) <= set(persisted)
    for name, (_p, _f, scopes) in LAYOUT.items():
        assert set(persisted[name].compliance_scopes or []) == set(scopes), (name, persisted[name].compliance_scopes)
        assert persisted[name].criticality == CRITICALITY[name]
    edges = {(e.parent_id, e.child_id) for e in test_db.execute(select(SystemDependency)).scalars().all()}
    for parent, children in DEPENDS.items():
        for child in children:
            assert (persisted[parent].id, persisted[child].id) in edges, (parent, child)
    cascade = scan.statistics["cascade"]
    systems = {s["system"]: s for s in cascade["systems"]}
    assert set(systems) == set(LAYOUT)
    assert "3DES" in systems["UAESWITCH-CARD"]["algorithms"]
    assert systems["T24-CORE-KYC"]["criticality"] == "critical"
