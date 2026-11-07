"""``docs/CURRENT-STATE.md`` is generated — and this test is why it stays current.

The repository's status claims had drifted across README, three status documents
and four scripts (0106 vs 0107 vs the real head, 75 vs 77 vs 92 surfaces). The
current-state document collapses them into computed numbers; this test regenerates
it and requires byte-identical output, so a structural change in the tree fails
here until someone regenerates — and every number change lands in review as a diff
of the document, never as drift behind it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def test_the_current_state_document_is_not_stale():
    generated = subprocess.run(
        [sys.executable, str(ROOT / "scripts/gen_current_state.py")],
        capture_output=True, text=True, cwd=ROOT, timeout=120,
        env={"ENVIRONMENT": "test", "PATH": "/usr/bin:/bin"},
    )
    assert generated.returncode == 0, generated.stderr
    committed = (ROOT / "docs/CURRENT-STATE.md").read_text(encoding="utf-8")
    assert generated.stdout == committed, (
        "docs/CURRENT-STATE.md is stale: the tree's numbers no longer match the "
        "document. Regenerate with "
        "'.venv/bin/python scripts/gen_current_state.py --write' and review the diff.")


def test_the_document_reports_the_real_migration_head():
    sys.path.insert(0, str(ROOT / "scripts"))
    from gen_current_state import migration_head

    text = (ROOT / "docs/CURRENT-STATE.md").read_text(encoding="utf-8")
    assert f"`{migration_head()}`" in text, (
        "the document must state the computed alembic head, not a remembered one")


def test_the_document_labels_historical_snapshots_instead_of_rewriting_them():
    text = (ROOT / "docs/CURRENT-STATE.md").read_text(encoding="utf-8")
    for claim in ("0106", "0107", "92 vs 87", "75 surfaces", "77 surfaces"):
        assert claim in text, f"the reconciliation table must name the stale claim {claim!r}"
    assert "historical" in text
    assert "GENERATED FILE" in text
