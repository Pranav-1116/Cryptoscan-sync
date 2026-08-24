import pytest

from drift.core.detector import DriftDetector


@pytest.fixture
def detector():
    return DriftDetector()
