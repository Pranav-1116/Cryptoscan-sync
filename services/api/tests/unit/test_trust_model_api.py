"""Trust-model endpoint (report 79 P0#3, round 27).

The endpoint publishes the platform's enforced trust rules as one document,
imported live from the governing modules — so the test asserts agreement
with those modules, not with a hardcoded copy.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")


def _client(monkeypatch):
    from fastapi.testclient import TestClient

    import api.dependencies
    from api.main import create_app

    monkeypatch.setattr(api.dependencies, "_resolve_api_key",
                        lambda request: ("apikey:test", ["viewer"], "test-key"))
    app = create_app()
    orig = api.dependencies.get_current_user
    app.dependency_overrides[orig] = lambda: "viewer"
    return TestClient(app)


def _headers() -> dict[str, str]:
    return {"x-api-key": "test"}


def test_trust_model_publishes_the_enforced_rules(monkeypatch):
    c = _client(monkeypatch)
    r = c.get("/api/v1/trust-model", headers=_headers())
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "trust_model"

    # authority tiers come from the enforcement module, all six, ordered
    from normalization.authority import AUTHORITY_TIERS
    tiers = body["authority"]["tiers"]
    assert [t["label"] for t in tiers] == [AUTHORITY_TIERS[i] for i in sorted(AUTHORITY_TIERS)]
    assert tiers[0]["label"] == "RUNTIME" and tiers[-1]["label"] == "UNRANKED"
    assert "never guessed" in tiers[-1]["meaning"]

    # confidence bands agree with the calibrated thresholds
    from universal_crypto.confidence import CONFIRMED_MIN, DEFAULT_WEIGHTS
    assert body["confidence"]["base_weights"] == DEFAULT_WEIGHTS
    bands = body["confidence"]["bands"]
    assert bands[0]["band"] == "CONFIRMED" and bands[0]["min"] == CONFIRMED_MIN

    # freshness decay: class-aware half-lives + verified floor
    from privacy.state import (EVIDENCE_HALF_LIVES, SOURCE_RELIABILITY,
                               VERIFIED_DECAY_FLOOR)
    decay = body["freshness"]["decay"]
    assert decay["half_life_seconds_by_evidence_class"] == EVIDENCE_HALF_LIVES
    assert decay["verified_floor"] == VERIFIED_DECAY_FLOOR
    assert decay["model"].startswith("exponential")
    assert body["freshness"]["source_reliability"] == SOURCE_RELIABILITY

    # conflicts: the three classes, never auto-resolved
    assert set(body["conflicts"]["classes"]) == {
        "ALGORITHM_MISMATCH", "PARAMETER_MISMATCH", "STATUS_MISMATCH"}
    assert "never auto-resolved" in body["conflicts"]["resolution"]

    # AI boundary statement is part of the model
    assert "no AI" in body["ai_boundary"]["deterministic_path"]


def test_trust_model_requires_auth(monkeypatch):
    from fastapi.testclient import TestClient

    from api.main import create_app

    app = create_app()
    client = TestClient(app)  # no key, no session
    r = client.get("/api/v1/trust-model")
    assert r.status_code in (401, 403)
