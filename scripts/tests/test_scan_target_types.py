"""Every scan target type the code writes is one the database accepts.

`scans_target_type_check` allowed the three tree-scan types and nothing else.
`POST /api/v1/host-evidence/approvals/{id}/intake` writes `HOST_SNAPSHOT_IMPORT`,
so on a migrated PostgreSQL that import raised `CheckViolation` — and the route
reported it as `409 Concurrent approval consumption`. Nothing caught it, for two
reasons: `create_all` never built the constraint (the model declared none), and no
test compared the literals the code writes with the literals the schema allows.

The second half of that is cheap to fix and belongs here. The writers are found by
parsing, not grepping: a `Scan(...)` call and the column dict handed to
`insert_scan_with_evidence(...)` are the only two places a scan row is built, so
`status="ACTIVE"` on a baseline — a different table with its own constraint —
is not mistaken for a scan status.

The check is static on purpose. A runtime probe only reaches the paths a test
happens to call, which is exactly how `HOST_SNAPSHOT_IMPORT` stayed invisible.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from db.models.scan import SCAN_STATUSES, SCAN_TARGET_TYPES

ROOT = Path(__file__).resolve().parents[2]

#: Where a `Scan` row can be built.
WRITER_GLOBS = (
    "services/api/api/**/*.py",
    "services/database/db/**/*.py",
    "services/scanner/**/*.py",
    "services/evidence/**/*.py",
    "services/inventory/**/*.py",
)

#: Calls whose arguments are scan columns.
SCAN_CALLS = frozenset({"Scan", "insert_scan_with_evidence"})
COLUMNS = ("target_type", "status")


def _writer_files() -> list[Path]:
    files: list[Path] = []
    for pattern in WRITER_GLOBS:
        files.extend(path for path in ROOT.glob(pattern) if path.is_file() and "__pycache__" not in str(path))
    return sorted(set(files))


def _literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _scan_literals() -> dict[str, dict[str, list[str]]]:
    """{column: {value: [file:line, …]}} for every literal scan column in a Scan call."""
    found: dict[str, dict[str, list[str]]] = {column: {} for column in COLUMNS}
    for path in _writer_files():
        try:
            tree = ast.parse(path.read_text(errors="ignore"), filename=str(path))
        except SyntaxError:  # pragma: no cover - a broken file is a different failure
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name not in SCAN_CALLS:
                continue
            pairs: list[tuple[str, ast.AST]] = [
                (keyword.arg, keyword.value) for keyword in node.keywords if keyword.arg
            ]
            for argument in node.args:
                if isinstance(argument, ast.Dict):
                    pairs.extend(
                        (key.value, value)
                        for key, value in zip(argument.keys, argument.values)
                        if isinstance(key, ast.Constant) and isinstance(key.value, str)
                    )
            for column, value_node in pairs:
                if column not in COLUMNS:
                    continue
                value = _literal(value_node)
                if value is None:
                    continue  # computed at runtime; nothing static to check
                where = f"{path.relative_to(ROOT)}:{value_node.lineno}"
                found[column].setdefault(value, []).append(where)
    return found


@pytest.fixture(scope="module")
def literals() -> dict[str, dict[str, list[str]]]:
    return _scan_literals()


def test_the_writer_scan_finds_the_known_writers(literals):
    """A parser that silently finds nothing would pass every check below."""
    assert "COMPLETED" in literals["status"], "the scan found no scan-row status literals at all"
    assert "HOST_SNAPSHOT_IMPORT" in literals["target_type"], (
        "the host-evidence intake target type was not found — the parser or the intake changed"
    )


@pytest.mark.parametrize(
    ("column", "allowed"),
    [("target_type", SCAN_TARGET_TYPES), ("status", SCAN_STATUSES)],
)
def test_literals_written_to_a_scan_row_are_allowed(literals, column, allowed):
    unexpected = {
        value: where for value, where in literals[column].items() if value not in set(allowed)
    }
    assert unexpected == {}, (
        f"scan `{column}` literals the code writes but the schema rejects {sorted(allowed)} — "
        "each would be a CheckViolation on a migrated PostgreSQL:\n  "
        + "\n  ".join(f"{value}: {', '.join(wheres[:3])}" for value, wheres in sorted(unexpected.items()))
    )


def test_the_host_snapshot_import_type_is_declared_and_migrated():
    """The specific defect: the type is allowed by the model *and* by the chain."""
    assert "HOST_SNAPSHOT_IMPORT" in SCAN_TARGET_TYPES
    migrations = ROOT / "services/database/migrations/versions"
    adders = [
        path.name for path in migrations.glob("*.py")
        if "HOST_SNAPSHOT_IMPORT" in path.read_text(errors="ignore")
    ]
    assert adders, (
        "no migration admits HOST_SNAPSHOT_IMPORT in scans_target_type_check — "
        "installations built by running the chain would reject the host import"
    )
