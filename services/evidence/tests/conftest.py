import pytest


@pytest.fixture
def sample_findings():
    return [
        {
            "finding_id": "f1",
            "crypto": {"algorithm": "DES", "mode": "ECB"},
            "source": {"file_path": "A.java", "line_number": 10},
            "metadata": {"confidence": "HIGH"},
        },
        {
            "finding_id": "f2",
            "crypto": {"algorithm": "AES", "mode": "GCM"},
            "source": {"file_path": "B.java", "line_number": 20},
            "metadata": {"confidence": "HIGH"},
        },
    ]
