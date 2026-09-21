"""Policy sign-off check: measures what still needs an owner's signature."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "scripts"))

import compliance_pack as cp
import policy_signoff_check as psc

REPO = Path(__file__).resolve().parents[4]
POLICIES = REPO / "docs" / "policies"


def test_real_policy_pack_is_quantified():
    report = psc.scan(POLICIES)
    # the pack is drafted, not signed — the checker must say so, precisely
    assert report["total_open"] > 0
    assert report["signed"] is False
    assert len(report["policies"]) == 12  # README + 11 policies
    for p in report["policies"]:
        assert (POLICIES / p["file"]).exists()
        assert p["open_items"] == len(p["items"])
        for it in p["items"]:
            assert it["text"].startswith("[ORG:")
            assert it["line"] >= 1
    # a known item is present (README approval table)
    readme = next(p for p in report["policies"] if p["file"] == "README.md")
    assert any("CISO name" in it["text"] for it in readme["items"])


def test_fully_signed_pack_is_zero(tmp_path):
    (tmp_path / "policy.md").write_text(
        "# Policy\n\nOwner: Jane Doe\nReview: 2027-01-01\n"
        "Approved by: Board, 2026-09-21\n", encoding="utf-8")
    report = psc.scan(tmp_path)
    assert report["total_open"] == 0
    assert report["signed"] is True


def test_multiline_placeholder_counts_once(tmp_path):
    (tmp_path / "multi.md").write_text(
        "Transfer controls: [ORG: state the mechanism —\n"
        "  standard contractual clauses or adequacy assessment —\n"
        "  for cross-border data].\n"
        "Owner: [ORG: CISO name]\n", encoding="utf-8")
    report = psc.scan(tmp_path)
    assert report["total_open"] == 2
    items = report["policies"][0]["items"]
    joined = " ".join(i["text"] for i in items)
    assert "standard contractual clauses" in joined
    assert all("\n" not in i["text"] for i in items)  # whitespace-normalized


def test_strict_exit_code(tmp_path, capsys):
    (tmp_path / "open.md").write_text("Owner: [ORG: CISO name]\n")
    rc = psc.main(["--policies-dir", str(tmp_path), "--strict", "--json"])
    assert rc == 1
    (tmp_path / "open.md").write_text("Owner: Jane Doe\n")
    rc = psc.main(["--policies-dir", str(tmp_path), "--strict", "--json"])
    assert rc == 0


def test_compliance_pack_embeds_signoff_state(tmp_path):
    out = cp.build(tmp_path, db_url=None)
    data = {}
    import zipfile
    with zipfile.ZipFile(out) as z:
        data = {n: z.read(n) for n in z.namelist()}
    assert cp.verify(str(out)) == 0

    signoff = json.loads(data["policy-signoff.json"])
    assert signoff["total_open"] > 0  # current state: drafted, unsigned
    assert signoff["signed"] is False
    manifest = json.loads(data["manifest.json"])
    notes = " ".join(manifest["missing"])
    assert "POLICY_SIGNOFF_PENDING" in notes
    assert str(signoff["total_open"]) in notes
