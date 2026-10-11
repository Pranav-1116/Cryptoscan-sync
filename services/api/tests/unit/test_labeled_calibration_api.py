"""Labeled calibration API + benchmark integration (audits 49 + 52, round 34)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config.settings import get_settings

ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="module")
def benchmark_report():
    """The real corpus benchmark run once (same hermetic runner as the gate)."""
    spec = importlib.util.spec_from_file_location(
        "accuracy_benchmark_labeled", ROOT / "scripts" / "accuracy_benchmark.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["accuracy_benchmark_labeled"] = mod
    spec.loader.exec_module(mod)
    return mod.run()


def test_benchmark_carries_per_detector_reports(benchmark_report):
    cases = benchmark_report["cases"]
    assert cases, "corpus produced no cases"
    reports = [r for c in cases for r in c.get("reports") or []]
    assert reports, "benchmark lost per-detector reports"
    assert all({"scanner", "family"} <= set(r) for r in reports)
    # every report on a labeled hit or miss is against that case's labels
    for case in cases:
        for r in case.get("reports") or []:
            assert r["family"] in case["expected"] or r["family"] in case["fp"]
    # the pre-existing report keys stay intact
    assert {"tp", "fn", "fp", "expected", "predicted"} <= set(cases[0])


def test_labeled_metrics_over_real_corpus(benchmark_report):
    from scanner.labeled_calibration import labeled_detector_metrics

    out = labeled_detector_metrics(benchmark_report["cases"])
    assert out["model"] == "labeled-ground-truth/detector-calibration-v1"
    assert out["detector_metrics"], "no detectors reported over the corpus"
    for det in out["detector_metrics"]:
        assert det["tp"] + det["fp"] > 0
        assert det["precision"] is None or 0.0 <= det["precision"] <= 1.0
        assert isinstance(det["sufficient_data"], bool)
    # corpus is labeled truth: negatives exist and every family is explicit
    assert out["corpus"]["negative_cases"] > 0
    assert out["corpus"]["labeled_families"] > 0
    # the gate's own bar backs the labeled numbers
    assert benchmark_report["overall"]["precision"] >= 0.95


# ── API endpoint ─────────────────────────────────────────────────────


@pytest.fixture()
def sqlite_app(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("ADMIN_PASSWORD_HASH", "")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/labeled.db")
    monkeypatch.setenv("NEO4J_URI", "")
    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client


def _login(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": "cryptoscan"})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_labeled_calibration_endpoint(sqlite_app):
    client = sqlite_app
    r = client.get("/api/v1/findings/detectors/labeled-calibration")
    assert r.status_code == 401  # anon rejected first

    r = client.get("/api/v1/findings/detectors/labeled-calibration",
                   headers=_login(client))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["model"] == "labeled-ground-truth/detector-calibration-v1"
    assert body["detector_metrics"], "no detector metrics over the corpus"
    assert body["corpus_overall"]["precision"] >= 0.95
    assert "proxies" in body["relation_to_scorecards"]
    assert body["scanner_level"]["fn_families"] >= 0
