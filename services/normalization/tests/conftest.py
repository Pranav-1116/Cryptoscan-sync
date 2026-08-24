from pathlib import Path

import pytest

from normalization.core.engine import NormalizationEngine


@pytest.fixture(scope="session")
def engine():
    rules = Path(__file__).resolve().parents[1] / "rule_definitions"
    return NormalizationEngine(str(rules))
