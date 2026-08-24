from pathlib import Path

import pytest

from policy.core.engine import PolicyEngine


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "rule_definitions"


@pytest.fixture(scope="session")
def engine(rules_dir: Path) -> PolicyEngine:
    return PolicyEngine(str(rules_dir))
