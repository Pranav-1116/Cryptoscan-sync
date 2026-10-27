"""Org readiness check: measures the operational documents the auditor
asks for first (risk register, rep letter, board report, training, JML)."""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))

import compliance_pack as cp
import org_readiness_check as orc

REPO = Path(__file__).resolve().parents[4]
DOCS = REPO / "docs"


def _write_ready_tree(root: Path) -> None:
    for sub in ("compliance", "org"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "compliance" / "risk-register.md").write_text(
        "# Risk Register\n"
        "| ID | Risk | L | I | Score | Treatment | Owner | Target | Review | Status |\n"
        "|----|------|---|---|-------|-----------|-------|--------|--------|--------|\n"
        "| R-001 | a | 2 | 2 | 4 | prevent | Jane Doe | 2026-12 | 2026-12-01 | CLOSED |\n"
        "| R-002 | b | 2 | 2 | 4 | detect | John Roe | 2026-12 | 2026-12-01 | OPEN |\n"
        "| R-003 | c | 2 | 2 | 4 | accept | Al Bo | 2026-12 | 2026-12-01 | OPEN |\n"
        "| R-004 | d | 2 | 2 | 4 | transfer | Cy Lee | 2026-12 | 2026-12-01 | OPEN |\n"
        "| R-005 | e | 2 | 2 | 4 | respond | Ed It | 2026-12 | 2026-12-01 | OPEN |\n")
    reps = ["Responsibility", "Understanding of requirements",
            "Completeness of information", "Effectiveness of controls",
            "No management override", "No fraud", "IT general controls",
            "Incidents", "Data protection", "Sub-services", "Subsequent events"]
    (root / "compliance" / "management-rep-letter.md").write_text(
        "# MRL\n" + "\n".join(f"{i}. **{r}.** text" for i, r in enumerate(reps, 1))
        + "\n\n| CISO | Jane Doe — Signature: X |\n"
          "| CEO | John Roe — Signature: X |\n| Date | 2026-12-31 |\n")
    (root / "compliance" / "quarterly-board-report.md").write_text(
        "# QBR\n## 1. Executive summary\nx\n## 2. Security posture\n"
        "| Metric | v | Source |\n|---|---|---|\n| a | 1 | access-review |\n"
        "risk-register\n## 3. Incidents\nx\n"
        "## 4. Resilience & DR\n| d | P | drill |\n"
        "## 5. Compliance & evidence\nx\n## 6. Forward look\nx\n")
    (root / "org" / "training-and-awareness.md").write_text(
        "# Training\n| ID | Course | Audience | Cadence | Owner |\n"
        "|---|---|---|---|---|\n"
        "| T-01 | a | all | annual | Jane |\n"
        "| T-02 | b | eng | annual | John |\n"
        "| T-03 | c | dpo | annual | Al |\n"
        "| T-04 | d | oncall | semiannual | Cy |\n"
        "## 3. Completion records\n| Person | T-01 |\n|---|---|\n| X | 2026-01 |\n")
    rows = []
    for prefix, n in (("J", 7), ("M", 4), ("L", 6)):
        for i in range(1, n + 1):
            rows.append(f"| JML-{prefix}{i} | step | owner | same day |")
    jml = "\n".join(rows)
    jml = jml.replace("| JML-J4 | step |", "| JML-J4 | **Enforced:** mfa |", 1)
    jml = jml.replace("| JML-L1 | step |", "| JML-L1 | **Enforced:** deactivate |", 1)
    (root / "org" / "joiner-mover-leaver.md").write_text(
        "# JML\n| Step | Action | Owner | Deadline |\n|---|---|---|---|\n" + jml + "\n")


def test_real_org_docs_are_quantified():
    report = orc.scan(DOCS)
    # five documents, each present
    assert len(report["documents"]) == 5
    assert all(d["status"] != "MISSING" for d in report["documents"])

    reg = next(d for d in report["documents"] if d["name"] == "risk-register")
    by_name = {c["name"]: c for c in reg["checks"]}
    assert by_name["has risks"]["pass"] and int(by_name["has risks"]["detail"].split()[0]) >= 12
    assert by_name["unique risk IDs"]["pass"]
    assert by_name["every risk has a valid treatment"]["pass"]
    # owners are [ORG:] at drafting — the check must say PENDING, not pass
    assert by_name["every risk has a named owner"]["pass"] is False

    jml = next(d for d in report["documents"] if d["name"] == "joiner-mover-leaver")
    assert jml["status"] == "READY"  # fully drafted at build time

    rep = next(d for d in report["documents"] if d["name"] == "management-rep-letter")
    by_name = {c["name"]: c for c in rep["checks"]}
    assert by_name["all representations present"]["pass"]
    assert by_name["signed (no open placeholders)"]["pass"] is False

    assert report["ready"] is False
    assert report["failed"] == sum(
        1 for d in report["documents"] for c in d["checks"] if not c["pass"])


def test_ready_tree_passes(tmp_path):
    _write_ready_tree(tmp_path)
    report = orc.scan(tmp_path)
    assert report["ready"] is True
    assert report["failed"] == 0


def test_unnamed_risk_owner_fails(tmp_path):
    _write_ready_tree(tmp_path)
    text = (tmp_path / "compliance" / "risk-register.md").read_text()
    (tmp_path / "compliance" / "risk-register.md").write_text(
        text.replace("| R-001 | a | 2 | 2 | 4 | prevent | Jane Doe |",
                     "| R-001 | a | 2 | 2 | 4 | prevent |  |"))
    report = orc.scan(tmp_path)
    assert report["ready"] is False
    reg = next(d for d in report["documents"] if d["name"] == "risk-register")
    failed = [c for c in reg["checks"] if not c["pass"]]
    assert any("owner" in c["name"] for c in failed)


def test_invalid_treatment_fails(tmp_path):
    _write_ready_tree(tmp_path)
    text = (tmp_path / "compliance" / "risk-register.md").read_text()
    (tmp_path / "compliance" / "risk-register.md").write_text(
        text.replace("| R-002 | b | 2 | 2 | 4 | detect |",
                     "| R-002 | b | 2 | 2 | 4 | hope-for-the-best |"))
    report = orc.scan(tmp_path)
    reg = next(d for d in report["documents"] if d["name"] == "risk-register")
    failed = [c for c in reg["checks"] if not c["pass"]]
    assert any("treatment" in c["name"] for c in failed)


def test_missing_jml_step_fails(tmp_path):
    _write_ready_tree(tmp_path)
    text = (tmp_path / "org" / "joiner-mover-leaver.md").read_text()
    (tmp_path / "org" / "joiner-mover-leaver.md").write_text(
        text.replace("| JML-L3 | step | owner | same day |\n", ""))
    report = orc.scan(tmp_path)
    jml = next(d for d in report["documents"] if d["name"] == "joiner-mover-leaver")
    assert jml["status"] == "PENDING"
    assert "JML-L3" in next(c for c in jml["checks"] if not c["pass"])["detail"]


def test_missing_document_reported(tmp_path):
    _write_ready_tree(tmp_path)
    (tmp_path / "org" / "training-and-awareness.md").unlink()
    report = orc.scan(tmp_path)
    missing = next(d for d in report["documents"]
                   if d["name"] == "training-and-awareness")
    assert missing["status"] == "MISSING"
    assert report["ready"] is False


def test_compliance_pack_embeds_org_readiness(tmp_path):
    out = cp.build(tmp_path, db_url=None)
    with zipfile.ZipFile(out) as z:
        data = {n: z.read(n) for n in z.namelist()}
    assert cp.verify(str(out)) == 0

    org = json.loads(data["org-readiness.json"])
    assert org["failed"] > 0 and org["ready"] is False
    manifest = json.loads(data["manifest.json"])
    notes = " ".join(manifest["missing"])
    assert "ORG_READINESS_PENDING" in notes

    # the artifacts themselves ride in the pack, not just the measurement
    assert "compliance/risk-register.md" in data
    assert "org/joiner-mover-leaver.md" in data
    assert "ops/on-call-and-comms.md" in data
