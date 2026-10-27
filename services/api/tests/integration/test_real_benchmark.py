"""Integration: real detector benchmark (no AI/ML, no simulation).

Runs the shipping universal-crypto detector over built-in labelled datasets
through the control-plane API and asserts the persisted run reflects real
measurement (precision/recall/F1 on ground truth).
"""

from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

API = "/api/v1"


def _token(roles=("superadmin",)):
    from api.security.session_manager import SessionManager

    return SessionManager(secret="test-secret-key-for-sessions-min-32-chars").create_session(
        "admin", roles=list(roles))


@pytest.fixture(scope="module")
def client():
    os.environ["SECRET_KEY"] = "test-secret-key-for-sessions-min-32-chars"
    os.environ["ENVIRONMENT"] = "development"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    db_file = os.path.join(tempfile.gettempdir(), "real_benchmark_integration_test.db")
    for ext in ("", "-wal", "-shm"):
        if os.path.exists(db_file + ext):
            os.remove(db_file + ext)
    os.environ["DATABASE_URL"] = f"sqlite:///{db_file}"

    from api.config.settings import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        c.headers["Authorization"] = f"Bearer {_token()}"
        yield c


class TestRealBenchmark:
    def test_real_detector_benchmark_meets_target(self, client):
        r = client.post(f"{API}/control/benchmark/run-real", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["mode"] == "real_detector"
        # 85 labelled cases across 9 built-in datasets
        assert body["total_cases"] >= 80
        # real detection must meet the 95% accuracy + recall target
        assert body["meets_95_target"] is True
        assert body["precision"] >= 0.95
        assert body["recall"] >= 0.95
        assert body["f1"] >= 0.95
        assert body["false_positive_rate"] <= 0.05
        # confusion matrix is internally consistent
        assert body["true_positive"] > 0
        assert (body["true_positive"] + body["false_positive"]
                + body["false_negative"] + body["true_negative"]) > 0
        assert body["per_dataset"]

    def test_benchmark_run_persisted_and_listed(self, client):
        run_id = client.post(f"{API}/control/benchmark/run-real",
                             json={"scanner_version": "test-1.0"}).json()["run_id"]
        runs = client.get(f"{API}/control/benchmark/runs").json()["runs"]
        ids = {r["id"] for r in runs}
        assert run_id in ids
        persisted = next(r for r in runs if r["id"] == run_id)
        assert persisted["scanner_id"] == "universal-crypto-real"
        assert persisted["status"] == "scored"
