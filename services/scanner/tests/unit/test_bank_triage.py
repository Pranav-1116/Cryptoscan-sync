"""scripts/bank_triage.py — workbook + score round trip on a tiny estate."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def _load():
    spec = importlib.util.spec_from_file_location("bank_triage", ROOT / "scripts" / "bank_triage.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bank_triage"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_workbook_and_score(tmp_path):
    bt = _load()
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Enc.java").write_text('import javax.crypto.Cipher;\nclass Enc { Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); }\n')
    # crypto signal, zero findings → candidate miss
    (repo / "src" / "Probe.java").write_text('import javax.crypto.Cipher;\nclass Probe { int n = Cipher.getMaxAllowedKeyLength("AES"); }\n')
    (repo / "src" / "Plain.java").write_text("class Plain { int x = 1; }\n")
    (repo / "legacy.foo").write_text("SOMETHING\n" * 50)  # unowned extension
    out = tmp_path / "wb.json"
    md = tmp_path / "wb.md"
    assert bt.main(["workbook", str(repo), "-o", str(out), "--md", str(md)]) == 0
    wb = json.loads(out.read_text())
    assert any(r["file"] == "src/Enc.java" and r["algorithm"] == "AES" for r in wb["findings"])
    miss_files = {m["file"] for m in wb["candidate_misses"]}
    assert "src/Probe.java" in miss_files and "src/Plain.java" not in miss_files and "src/Enc.java" not in miss_files
    assert any(u["ext"] == ".foo" for u in wb["unowned_extensions"])
    assert "Triage workbook" in md.read_text()

    for r in wb["findings"]:
        r["verdict"] = "TP"
    for m in wb["candidate_misses"]:
        m["verdict"] = "FN"
        m["expected"] = ["AES"]
    out.write_text(json.dumps(wb))
    cases = tmp_path / "cases.py"
    assert bt.main(["score", str(out), "--corpus-out", str(cases)]) == 0
    assert "Probe.java" in cases.read_text()
