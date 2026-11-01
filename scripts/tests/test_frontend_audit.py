"""The frontend-hardening audit, including the claim that it can fail.

An audit whose rows cannot go red is decoration. These tests pin the graders'
inputs on a scratch console — so they do not depend on the real `frontend/src`
drifting — and then run the same graders against the real console to make sure
the current verdicts are reproducible.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "frontend_audit.py"


def _module():
    sys.path.insert(0, str(ROOT / "scripts"))
    import frontend_audit  # noqa: PLC0415

    return frontend_audit


def _console(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "src"
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    return root


@pytest.fixture()
def scratch(monkeypatch, tmp_path):
    audit = _module()
    root = _console(tmp_path, {
        "pages/Good.tsx": (
            'import { useApi } from "../lib/apiUi.js";\n'
            "export default function Good() {\n"
            "  const r = useApi<unknown>(() => Promise.resolve({ source: 'live', data: null }));\n"
            "  if (r.error) return <div role=\"alert\">could not be read</div>;\n"
            "  return <div role=\"status\">nothing yet</div>;\n"
            "}\n"
        ),
        "pages/Good.test.tsx": "// a rendered test exists\n",
        "lib/realtime.tsx": "new EventSource('/events/stream');\n// Last-Event-ID resume\n",
        "lib/realtime.test.tsx": "// EventSource covered\n",
    })
    monkeypatch.setattr(audit, "FRONTEND", root)
    return audit, root


def test_collection_truncation_ignores_label_shortening():
    audit = _module()
    assert audit._collection_truncations("const s = id.slice(0, 12);") == []
    assert audit._collection_truncations("rows.slice(0, 20).map(x => x)") == [("rows", 20)]
    # a bound under 8 is a label cut, not a list cut
    assert audit._collection_truncations("rows.slice(0, 3)") == []


def test_silent_truncation_is_caught_and_a_notice_clears_it(scratch, tmp_path):
    audit, root = scratch
    page = root / "pages" / "Good.tsx"
    page.write_text(page.read_text() + "const shown = rows.length ? rows.slice(0, 50) : [];\n")
    row = audit.large_graphs()
    assert row.verdict != audit.PASS
    assert row.measured["silent_truncation_count"] == 1

    page.write_text(page.read_text().replace(
        "const shown", "// showing the first 50 of them\nconst shown"))
    assert audit.large_graphs().measured["silent_truncation_count"] == 0


def test_a_table_passing_total_counts_as_declaring_its_cut(scratch):
    audit, root = scratch
    (root / "pages" / "Good.tsx").write_text(
        (root / "pages" / "Good.tsx").read_text()
        + "const t = <Table total={rows.length} rows={rows.slice(0, 50).map(r => [r])} />;\n")
    row = audit.large_graphs()
    assert row.measured["silent_truncation_count"] == 0


def test_a_page_without_a_failure_branch_is_reported(scratch):
    audit, root = scratch
    (root / "pages" / "Silent.tsx").write_text(
        'import { useApi } from "../lib/apiUi.js";\n'
        "export default function Silent() {\n"
        "  const r = useApi<unknown>(() => Promise.resolve({ source: 'live', data: null }));\n"
        "  return <div>{String(r.data)}</div>;\n"
        "}\n"
    )
    row = audit.error_handling()
    silent = row.measured["files_that_read_without_a_failure_branch"]
    assert any(name.endswith("Silent.tsx") for name in silent), silent


def test_missing_realtime_resume_is_not_a_pass(scratch):
    audit, root = scratch
    (root / "lib" / "realtime.tsx").write_text("new EventSource('/events/stream');\n")
    row = audit.realtime()
    assert row.verdict != audit.PASS
    assert "no surface reads the API's replay-gap flag" in row.gaps


def test_the_negative_control_removes_the_pass_verdicts():
    """The instrument must be able to fail: strip the behaviour, and it does."""
    report = _module().measure()
    control = report["negative_control"]
    assert report["counts"]["PASS"] > 0
    assert control["stripped_counts"]["PASS"] == 0
    degraded = [row for row in report["rows"]
                if control["stripped_verdicts"][row["id"]] != row["verdict"]]
    assert len(degraded) >= 4, [(row["id"], row["verdict"],
                                 control["stripped_verdicts"][row["id"]])
                                for row in report["rows"]]


def test_this_repository_s_report_is_reproducible():
    report = _module().measure()
    assert report["schema"] == "cryptoscan.frontend-hardening/1"
    assert len(report["rows"]) == 9
    ids = {row["id"] for row in report["rows"]}
    assert {"contract_coverage", "error_handling", "authorization_views",
            "large_graphs", "realtime"} <= ids
    assert report["counts"]["FAIL"] == 0, report["counts"]


def test_cli_writes_both_artifacts(tmp_path):
    out_json = tmp_path / "audit.json"
    out_md = tmp_path / "audit.md"
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", str(out_json), "--md", str(out_md)],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    report = json.loads(out_json.read_text())
    assert report["schema"] == "cryptoscan.frontend-hardening/1"
    markdown = out_md.read_text()
    assert "Negative control" in markdown
    assert "WHAT THIS" not in markdown
