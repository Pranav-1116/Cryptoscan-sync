"""No shipped document may claim a capability the build does not have.

The five boundaries are published as data (``shared_models/capability_boundaries.py``)
and the register and the console read them. Documentation is the other half of
the same obligation: a README that says the product "traces every cryptographic
asset through the entire system" undoes the boundary statement, and it is what a
bank's security reviewer reads first.

So this test reads the checkout's Markdown and fails on an affirmative overclaim.
A line may quote one of these phrases only if the same line carries a negation —
"the generic enterprise engine is not implemented" is the sentence we want, while
"the generic enterprise engine answers arbitrary what-if questions" is not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

#: Phrases that are only true with a negation on the same line.
OVERCLAIMS = (
    r"every cryptographic asset",
    r"traces every",
    r"discovers every",
    r"complete cryptographic inventory",
    r"complete windows collector",
    r"full windows (support|coverage|sbom)",
    r"generic enterprise simulation engine",
    r"proves which algorithms executed",
)

#: Words that turn a phrase into the honest version of it.
NEGATION = re.compile(
    r"\b(not|never|no|none|cannot|absent|absent|partial|partially|candidate|only|fails?|"
    r"isn't|aren't|doesn't|don't|without)\b|n't",
    re.IGNORECASE,
)

#: Generated evidence and third-party material are not product copy.
SKIP_DIRS = {
    "node_modules",
    ".venv",
    "docs/readiness-evidence",
    "docs/templates",
    "docs/archive",
}


def _markdown_files() -> list[Path]:
    files = [ROOT / "README.md"]
    for path in sorted((ROOT / "docs").rglob("*.md")):
        rel = path.relative_to(ROOT).as_posix()
        if any(rel.startswith(skip) for skip in SKIP_DIRS):
            continue
        files.append(path)
    return [path for path in files if path.exists()]


@pytest.mark.parametrize("pattern", OVERCLAIMS)
def test_no_affirmative_overclaim_in_shipped_markdown(pattern: str):
    matcher = re.compile(pattern, re.IGNORECASE)
    offences: list[str] = []
    for path in _markdown_files():
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not matcher.search(line):
                continue
            if NEGATION.search(line):
                continue
            offences.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:160]}")
    assert offences == [], "affirmative overclaim without a stated limit:\n" + "\n".join(offences)


def test_the_readme_states_the_five_boundaries():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Not operational" in text
    for capability in ("Windows collector", "Hardware discovery", "HSM", "Runtime crypto", "Simulation"):
        assert capability in text, capability
    # and it points at the checked register rather than restating it unattended
    assert "CAPABILITY-MATURITY.md#capability-boundaries" in text


def test_the_boundary_section_is_generated_not_hand_written():
    """The doc section must come from the module the API serves."""
    generator = (ROOT / "scripts" / "gen_capability_maturity.py").read_text(encoding="utf-8")
    assert "capability_boundaries" in generator
    doc = (ROOT / "docs" / "CAPABILITY-MATURITY.md").read_text(encoding="utf-8")
    from sys import path

    path.insert(0, str(ROOT / "shared" / "shared_models"))
    from shared_models import capability_boundaries as cb

    for row in cb.STATEMENTS:
        assert row["capability"] in doc, row["id"]
        assert row["check_at"] in doc, row["id"]
