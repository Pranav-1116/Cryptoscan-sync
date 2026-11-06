"""The labeled-calibration endpoint must not scan the whole labelled corpus to answer a GET.

`GET /api/v1/findings/detectors/labeled-calibration` ran the whole labeled
accuracy corpus inside the request — the production scanner over the full labelled
corpus (851 files as of wave 20; it only grows), plus
the scanner registry import — and cached the result only in memory, so every
worker process paid it once. Measured at 6.9–10 s on a cold live server, on a
thread that could have served another request.

`scripts/build_labeled_calibration.py` writes the same report ahead of time. These
tests hold the endpoint to it:

* with an artifact present, the corpus is **not** run (the benchmark is replaced
  with a function that fails if called);
* the answer is still the full calibration, not a stub;
* an artifact built from a different corpus is refused rather than served as
  current — a stale report reads as a measurement of today's tree;
* with no artifact at all the endpoint still works, computes once, and leaves the
  artifact behind for the next process.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for extra in ("scripts", "services/api", "services/scanner", "services/scanner/tests", "shared/shared_models"):
    candidate = str(ROOT / extra)
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


def _app():
    """A minimal app with the findings router, and a caller who passes the gate."""
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "labeled-calibration-" + "c" * 21)
    from fastapi import FastAPI

    from api.config.settings import get_settings
    from api.dependencies import get_current_user, get_db_session

    get_settings.cache_clear()
    from api.routers import findings as findings_router

    app = FastAPI()
    app.include_router(findings_router.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: "calibration-reviewer"
    app.dependency_overrides[get_db_session] = lambda: None
    return app, findings_router


@pytest.fixture()
def artifact(tmp_path, monkeypatch):
    """A real artifact, built from the shipped corpus."""
    import build_labeled_calibration

    path = tmp_path / "labeled-calibration.json"
    payload = build_labeled_calibration.build(path)
    monkeypatch.setenv("ACCURACY_LABELED_CALIBRATION", str(path))
    return path, payload


def test_the_endpoint_serves_the_artifact_without_running_the_corpus(artifact, monkeypatch):
    path, payload = artifact
    app, findings_router = _app()
    findings_router._corpus_benchmark.cache_clear()

    def explode():  # pragma: no cover - the assertion is that this never runs
        raise AssertionError("the endpoint ran the 842-file corpus instead of reading the artifact")

    monkeypatch.setattr(findings_router, "_run_accuracy_benchmark", explode, raising=False)

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.get("/api/v1/findings/detectors/labeled-calibration")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["report"]["source"] == "precomputed"
    assert body["report"]["cases"] == len(payload["cases"])
    assert body["corpus_overall"]["files"] == len(payload["cases"])
    assert body["detector_metrics"], "per-detector calibration is empty"


def test_a_stale_artifact_is_not_served_as_current(artifact, tmp_path):
    path, payload = artifact
    payload["input_fingerprint"] = "0" * 64
    path.write_text(json.dumps(payload))

    from api.routers import findings as findings_router

    findings_router._corpus_benchmark.cache_clear()
    assert findings_router._load_calibration_artifact(path) is None


def test_an_artifact_for_another_corpus_is_rejected_after_a_corpus_change(tmp_path, monkeypatch):
    """The fingerprint has to be over the *inputs*, not over time."""
    import build_labeled_calibration

    from api.routers import findings as findings_router

    path = tmp_path / "calibration.json"
    payload = build_labeled_calibration.calibration_payload({"overall": {}, "cases": []})
    path.write_text(json.dumps(payload))
    assert findings_router._load_calibration_artifact(path) is not None, (
        "a freshly built artifact must be accepted before the corpus changes"
    )
    # The corpus module changed under the artifact: same file, different inputs.
    monkeypatch.setattr(findings_router, "_calibration_fingerprint", lambda: "f" * 64)
    assert findings_router._load_calibration_artifact(path) is None


def test_without_an_artifact_the_endpoint_computes_once_and_stores_it(tmp_path, monkeypatch):
    path = tmp_path / "missing" / "calibration.json"
    monkeypatch.setenv("ACCURACY_LABELED_CALIBRATION", str(path))
    from api.routers import findings as findings_router

    findings_router._corpus_benchmark.cache_clear()
    try:
        report = findings_router._corpus_benchmark()[0]
        assert len(report["cases"]) >= 842  # the labelled corpus only grows as waves are added
        assert path.exists(), "the computed report was not stored for the other workers"
        stored = json.loads(path.read_text())
        assert stored["input_fingerprint"] == findings_router._calibration_fingerprint()
        # and the second call reads the file instead of rescanning
        assert findings_router._corpus_benchmark()[0]["generated_at"] == report["generated_at"]
    finally:
        findings_router._corpus_benchmark.cache_clear()
