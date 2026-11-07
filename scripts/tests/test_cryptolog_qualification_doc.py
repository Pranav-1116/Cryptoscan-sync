"""The committed qualification report is generated, and generation is the
only way it changes (gen_current_state discipline)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent


def _generator():
    spec = importlib.util.spec_from_file_location(
        "gen_cryptolog_qualification",
        ROOT / "scripts" / "gen_cryptolog_qualification.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_committed_report_matches_regeneration():
    module = _generator()
    committed = (ROOT / "docs" / "cryptolog" / "11_QUALIFICATION_REPORT.md").read_text()
    assert module.build_report() == committed, (
        "docs/cryptolog/11_QUALIFICATION_REPORT.md is stale — regenerate with "
        "`.venv/bin/python scripts/gen_cryptolog_qualification.py --write`")


def test_the_report_never_claims_an_external_act():
    text = (ROOT / "docs" / "cryptolog" / "11_QUALIFICATION_REPORT.md").read_text()
    assert "EXTERNAL — NOT DONE (register only)" in text
    assert "real-bank-pilot-acceptance" in text
    assert "SYNTHETIC" in text
