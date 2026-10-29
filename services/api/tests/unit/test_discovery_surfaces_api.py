"""Discovery surface coverage registry — the matrix may not claim more than the code.

The registry exists so the product's coverage sentence is compiled from detectors
that actually resolve in this build. These tests pin that contract:

* every declared detector resolves (a rename breaks the test, not the claim);
* a surface whose detector is missing degrades to NOT_IMPLEMENTED by itself;
* configuration and observation are separate, honest axes (NOT_OBSERVED is not 0);
* the endpoint answers without a discovery run and refuses an unknown surface.
"""

from __future__ import annotations

import dataclasses

import pytest

from api import estate_surfaces as S

PATH = "/api/v1/estate/evidence/discovery/surfaces"


# --------------------------------------------------------------------------- #
# registry invariants
# --------------------------------------------------------------------------- #
def test_ids_are_unique_and_vocabulary_is_closed():
    ids = [surface.id for surface in S.SURFACES]
    assert len(ids) == len(set(ids)) >= 12
    assert {surface.kind for surface in S.SURFACES} <= set(S.KINDS)
    assert {surface.maturity for surface in S.SURFACES} <= set(S.MATURITIES)


def test_every_surface_states_what_it_reads_and_what_it_cannot_claim():
    for surface in S.SURFACES:
        assert surface.label
        assert surface.planes, surface.id
        assert surface.reads, surface.id
        # A surface with no limitation stated is a surface that overclaims.
        assert surface.cannot_claim, surface.id
        assert surface.detectors, surface.id


def test_every_declared_detector_resolves_in_this_build():
    absent = [
        (surface.id, ref, S.resolve_detector(ref)["reason"])
        for surface in S.SURFACES
        for ref in surface.detectors
        if not S.resolve_detector(ref)["present"]
    ]
    assert absent == [], f"detectors declared but absent: {absent}"


def test_missing_detector_degrades_the_surface_by_itself(monkeypatch):
    broken = dataclasses.replace(
        S.SURFACE_INDEX["linux_host"],
        detectors=("definitely_not_a_module_xyz:thing",) + S.SURFACE_INDEX["linux_host"].detectors,
    )
    row = S.row(broken)
    # The ceiling is still what the collector would establish, but the reported
    # maturity is the truth about this build.
    assert row["declared_maturity"] == S.MATURITY_PARTIAL
    assert row["maturity"] == S.MATURITY_PARTIAL  # one detector still resolves
    assert any("absent" in note for note in row["notes"])

    gone = dataclasses.replace(broken, detectors=("definitely_not_a_module_xyz:thing",))
    row = S.row(gone)
    assert row["maturity"] == S.MATURITY_NOT_IMPLEMENTED
    assert row["detectors"][0]["present"] is False


def test_resolve_detector_reports_absence_as_data():
    assert S.resolve_detector("no.such.module:thing")["present"] is False
    assert S.resolve_detector("api.estate_surfaces:registry")["present"] is True
    assert S.resolve_detector("api.estate_surfaces:not_a_symbol")["present"] is False


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def test_configuration_uses_the_planes_own_resolver(monkeypatch):
    from api.estate_planes import PlaneNotConfigured
    import api.estate_cloud as cloud

    def not_configured(environ=None):
        raise PlaneNotConfigured("no AWS credentials in this environment")

    monkeypatch.setattr(cloud, "cloud_config", not_configured)
    state = S.configuration(S.SURFACE_INDEX["cloud"], {})
    assert state["state"] == S.NOT_CONFIGURED
    assert "AWS credentials" in state["reason"]


def test_configuration_unknown_is_not_reported_as_not_configured(monkeypatch):
    import api.estate_kubernetes as k8s

    def broken(environ=None):
        raise ValueError("kubeconfig unreadable: permission denied")

    monkeypatch.setattr(k8s, "cluster_config", broken)
    state = S.configuration(S.SURFACE_INDEX["kubernetes"], {})
    assert state["state"] == S.CONFIGURATION_UNKNOWN
    assert "permission denied" in state["reason"]


def test_surfaces_without_credentials_say_so():
    state = S.configuration(S.SURFACE_INDEX["code_static"], {})
    assert state["state"] == S.CONFIGURED
    assert "no external credentials" in state["reason"]


# --------------------------------------------------------------------------- #
# observation
# --------------------------------------------------------------------------- #
def test_observation_is_absent_not_zero_without_a_run():
    row = S.row(S.SURFACE_INDEX["hsm"])
    assert row["observed"]["state"] == "NOT_OBSERVED"
    assert "collected" not in row["observed"]
    assert "no estate discovery run" in row["observed"]["reason"]


def test_observation_reports_what_the_run_actually_did():
    collectors = [
        {"plane": "HSM", "status": "COMPLETE", "collected": 3, "reason": None},
        {"plane": "NETWORK", "status": "NOT_ATTEMPTED", "collected": 0,
         "reason": "no adapter registered"},
    ]
    hsm = S.row(S.SURFACE_INDEX["hsm"], collectors=collectors)
    assert hsm["observed"]["state"] == "COMPLETE"
    assert hsm["observed"]["collected"] == 3

    net = S.row(S.SURFACE_INDEX["network_device"], collectors=collectors)
    assert net["observed"]["state"] == "NOT_ATTEMPTED"
    assert net["observed"]["collected"] == 0

    # A surface whose planes were never attempted is not "0 collected" but "not asked".
    empty = S.row(S.SURFACE_INDEX["kubernetes"], collectors=collectors)
    assert empty["observed"]["state"] == "NOT_OBSERVED"

    failed = S.row(
        S.SURFACE_INDEX["cloud"],
        collectors=[{"plane": "CLOUD", "status": "FAILED", "collected": 0,
                     "reason": "AccessDenied"}],
    )
    assert failed["observed"]["state"] == "FAILED"
    assert "AccessDenied" in (failed["observed"]["reason"] or "")


def test_multi_plane_surface_sums_its_planes():
    collectors = [
        {"plane": "NETWORK", "status": "COMPLETE", "collected": 4},
        {"plane": "CLOUD", "status": "COMPLETE", "collected": 2},
    ]
    row = S.row(S.SURFACE_INDEX["database"], collectors=collectors)
    assert row["observed"]["collected"] == 6
    assert row["observed"]["state"] == "COMPLETE"


# --------------------------------------------------------------------------- #
# the whole matrix
# --------------------------------------------------------------------------- #
def test_registry_rollup_and_claim_agree_with_the_rows():
    doc = S.registry()
    rows = doc["surfaces"]
    assert doc["schema"] == S.SCHEMA
    assert doc["rollup"]["surfaces"] == len(rows) == len(S.SURFACES)
    assert sum(doc["rollup"]["by_maturity"].values()) == len(rows)
    assert sum(doc["rollup"]["by_kind"].values()) == len(rows)
    assert doc["rollup"]["observed_in_last_run"] == 0
    # nothing claims completeness
    assert doc["rollup"]["by_maturity"][S.MATURITY_MEASURED] == 0
    assert "no surface is claimed complete" in doc["claim"]
    assert f"{len(rows)} cryptographic surfaces are modelled" in doc["claim"]


def test_unknown_surface_raises():
    with pytest.raises(S.UnknownSurface):
        S.surface("not_a_surface")


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "cryptoscan")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/surfaces.db")
    monkeypatch.setenv("NEO4J_URI", "")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    from api.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(create_app()) as c:
        yield c


def _headers(client):
    token = client.post(
        "/api/v1/auth/login", json={"username": "admin", "password": "cryptoscan"}
    ).json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_endpoint_requires_auth(client):
    assert client.get(PATH).status_code == 401


def test_endpoint_answers_without_a_discovery_run(client):
    body = client.get(PATH, headers=_headers(client)).json()
    assert body["run_id"] is None
    assert body["schema"] == S.SCHEMA
    assert len(body["surfaces"]) == len(S.SURFACES)
    # nothing was observed, and that is said per surface rather than as zeros
    assert body["rollup"]["observed_in_last_run"] == 0
    assert {row["observed"]["state"] for row in body["surfaces"]} == {"NOT_OBSERVED"}
    # configuration is resolved for this (credential-free) deployment
    assert body["rollup"]["credentials_resolved"] == 0
    assert body["claim"].startswith(f"{len(S.SURFACES)} cryptographic surfaces are modelled")


def test_endpoint_refuses_an_unknown_surface(client):
    response = client.get(f"{PATH}/not_a_surface", headers=_headers(client))
    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "unknown_surface"
    assert "linux_host" in detail["reason"]


def test_endpoint_returns_one_surface(client):
    body = client.get(f"{PATH}/hsm", headers=_headers(client)).json()
    assert body["id"] == "hsm"
    assert body["maturity"] == S.MATURITY_METADATA_ONLY
    assert body["kind"] == S.KIND_LIVE_CONTROL_PLANE
    assert body["cannot_claim"]
