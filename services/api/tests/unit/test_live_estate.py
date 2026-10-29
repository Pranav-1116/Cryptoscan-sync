"""Live-mode rules: store the change, not the estate; narrow the BOM impact honestly."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from shared_models import live_estate


def test_first_observation_is_a_baseline_and_a_repeat_is_nothing():
    first = live_estate.compare_state(None, "proj-a")
    assert first["state"] == live_estate.FIRST_BASELINE
    assert first["store"] is True
    assert first["full_write"] is True

    same = live_estate.compare_state("proj-a", "proj-a")
    assert same["state"] == live_estate.NO_CHANGE
    assert same["store"] is False

    moved = live_estate.compare_state("proj-a", "proj-b")
    assert moved["state"] == live_estate.CHANGED
    assert moved["store"] is True
    assert moved["full_write"] is False


def test_an_observation_without_a_state_hash_can_never_be_compared():
    with pytest.raises(ValueError):
        live_estate.compare_state("proj-a", "")


def test_a_crypto_change_moves_the_cbom_and_the_techbom_only():
    impact = live_estate.bom_impact([{"kind": "CRYPTO_DEMOTED", "subject": "payments-api"}])

    assert impact["affected"] == ["CBOM", "TECHBOM"]
    assert "SBOM" in impact["unchanged"]
    assert impact["imprecise"] is False


def test_a_new_host_moves_the_hbom():
    impact = live_estate.bom_impact([{"kind": "ASSET_ADDED", "subject": "host-02", "after": "HOST"}])

    assert set(impact["affected"]) == {"HBOM", "TECHBOM"}


def test_an_edge_change_cannot_be_narrowed_and_says_so():
    impact = live_estate.bom_impact([{"kind": "RELATIONSHIP_LOST", "subject": "api —runs_on→ host"}])

    assert set(impact["affected"]) == set(live_estate.BOM_KINDS)
    assert impact["imprecise"] is True
    assert "RELATIONSHIP_LOST" in impact["imprecise_kinds"]


def test_a_coverage_change_moves_no_component_but_every_projection_carries_it():
    impact = live_estate.bom_impact([{"kind": "COVERAGE_DEGRADED", "subject": "Linux hosts"}])

    assert impact["affected"] == [], "no component moved, so no projection gained or lost a row"
    assert set(impact["unknowns_affected"]) == set(live_estate.BOM_KINDS)
    assert impact["unchanged"] == []
    assert all("unknowns block" in reason for reasons in impact["reasons"].values() for reason in reasons)


def test_an_unknown_asset_type_is_reported_rather_than_guessed():
    impact = live_estate.bom_impact([{"kind": "ASSET_ADDED", "subject": "thing", "after": "MYSTERY"}])

    assert impact["unmapped_asset_types"] == ["MYSTERY"]
    assert set(impact["affected"]) == set(live_estate.BOM_KINDS)


def test_connection_state_is_measured_from_the_last_observation():
    now = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)

    never = live_estate.connection_state(None, now=now)
    assert never["state"] == live_estate.NEVER_CONNECTED
    assert "NOT_OBSERVED" in never["meaning"]

    fresh = live_estate.connection_state(now - timedelta(seconds=30), now=now, interval_seconds=300)
    assert fresh["state"] == live_estate.CONNECTED
    assert fresh["seconds_since"] == 30

    stale = live_estate.connection_state(now - timedelta(seconds=601), now=now, interval_seconds=300)
    assert stale["state"] == live_estate.STALE
    assert stale["stale_after_seconds"] == 600


def test_connection_state_accepts_the_iso_string_a_receipt_stores():
    now = datetime(2026, 10, 29, 12, 0, tzinfo=timezone.utc)
    state = live_estate.connection_state("2026-10-29T11:59:00+00:00", now=now, interval_seconds=300)

    assert state["state"] == live_estate.CONNECTED
    assert state["seconds_since"] == 60


def test_the_agent_and_the_platform_can_disagree_about_the_state_hash():
    assert live_estate.state_hash_report("abc", "abc")["agrees"] is True
    disagree = live_estate.state_hash_report("abc", "def")
    assert disagree["agrees"] is False
    assert "disagree" in disagree["note"]
    assert live_estate.state_hash_report("abc", None)["agrees"] is None
