"""The readiness documentation gate must be deterministic.

A readiness result must not change merely because frontend dependencies or a
build directory exists on the machine running it. These tests exercise the
link scanner against a miniature repository instead of relying on today's
large documentation tree.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
GATE = ROOT / "scripts" / "bank_readiness.py"


def _gate():
    spec = importlib.util.spec_from_file_location("bank_readiness", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_documentation_scan_ignores_dependencies_and_build_output(tmp_path):
    gate = _gate()
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "ok.md").write_text("# ok\n", encoding="utf-8")
    (tmp_path / "docs" / "index.md").write_text(
        "[relative](ok.md) [site-root](/docs/ok.md) "
        "[external](https://example.test/missing)\n",
        encoding="utf-8",
    )
    # These links are not product documentation and must not affect the gate.
    for directory in (tmp_path / "node_modules/pkg", tmp_path / ".venv/lib"):
        directory.mkdir(parents=True)
        (directory / "README.md").write_text(
            "[package source](./does-not-exist.md)\n", encoding="utf-8"
        )

    broken, checked = gate.documentation_link_findings(tmp_path)

    assert broken == []
    assert checked == 2


def test_documentation_scan_reports_missing_product_links(tmp_path):
    gate = _gate()
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "index.md").write_text(
        "[missing](not-there.md)\n", encoding="utf-8"
    )

    broken, checked = gate.documentation_link_findings(tmp_path)

    assert checked == 1
    assert broken == ["docs/index.md -> not-there.md"]
