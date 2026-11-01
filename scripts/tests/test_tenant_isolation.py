"""Tests for the multi-tenant isolation drill.

The drill's job is to be unable to pass by accident: the rows have to be shown to be
separated *by the scope*, and the last row has to stay honest about the difference
between a scope and a key.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for _relative in ("scripts", "services/api", "services/database", "shared/shared_models",
                  "shared/shared_config"):
    sys.path.insert(0, str(ROOT / _relative))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "tenant-isolation-test-key-32-characters")

import tenant_isolation as ti  # noqa: E402


@pytest.fixture(scope="module")
def report() -> dict:
    return ti.measure()


def _row(report: dict, row_id: str) -> dict:
    return next(row for row in report["rows"] if row["id"] == row_id)


def test_schema_and_shape(report: dict) -> None:
    assert report["schema"] == ti.SCHEMA
    assert report["counts"]["FAIL"] == 0, [
        row["id"] for row in report["rows"] if row["verdict"] == "FAIL"]
    for row in report["rows"]:
        assert row["probes"], f"{row['id']} has no probe"


def test_reading_isolation_is_executed_with_a_positive_control(report: dict) -> None:
    row = _row(report, "read_filtering")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["scope-A-sees-only-A"]["ok"] is True
    assert probes["control-A-sees-its-own-row"]["ok"] is True, (
        "an empty result would make the read-isolation probe vacuous")
    assert probes["foreign-primary-key-not-readable"]["ok"] is True
    assert probes["own-primary-key-readable"]["ok"] is True
    assert row["verdict"] == "PASS"


def test_writes_cannot_reach_the_other_tenant(report: dict) -> None:
    for row_id in ("write_stamping", "cross_tenant_mutation"):
        row = _row(report, row_id)
        assert row["verdict"] == "PASS", row["probes"]


def test_predicate_free_queries_fail_closed(report: dict) -> None:
    row = _row(report, "raw_statements")
    assert row["verdict"] == "PASS"
    assert all("refused" in probe["observed"].lower() for probe in row["probes"])


def test_spoofed_header_does_not_buy_a_scope(report: dict) -> None:
    row = _row(report, "membership_resolution")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["header-for-another-tenant-does-not-scope"]["ok"] is True
    assert probes["control-own-header-still-works"]["ok"] is True


def test_controls_show_the_separation_is_the_scope(report: dict) -> None:
    row = _row(report, "controls")
    probes = {probe["probe"]: probe for probe in row["probes"]}
    assert probes["without-a-scope-both-tenants-are-visible"]["ok"] is True
    assert probes["guard-reports-active-inside-a-scope"]["ok"] is True


def test_at_rest_row_stays_honest(report: dict) -> None:
    row = _row(report, "at_rest")
    assert row["verdict"] == "PARTIAL", "logical isolation must never be graded PASS"
    assert row["probes"][0]["ok"] is True, "the drill must actually read the store"
    assert any("cryptograph" in gap for gap in row["unproven"])


def test_the_guard_really_separates_rows() -> None:
    """Direct unit check: remove the scope and both tenants appear."""
    from sqlalchemy import select

    from db.models.tenant import TenantUsageEvent
    from db.tenancy import platform_scope, tenant_scope

    world = ti.build_world()
    try:
        ids = ti._seed(world)
        with tenant_scope(ids[ti.TENANT_A]):
            session = world.session_factory()
            try:
                inside = {row.detail for row in session.execute(
                    select(TenantUsageEvent).where(TenantUsageEvent.kind == "drill")
                ).scalars().all()}
            finally:
                session.close()
        with platform_scope():
            session = world.session_factory()
            try:
                outside = {row.detail for row in session.execute(
                    select(TenantUsageEvent).where(TenantUsageEvent.kind == "drill")
                ).scalars().all()}
            finally:
                session.close()
        assert inside == {ti.MARKER_A}
        assert outside == {ti.MARKER_A, ti.MARKER_B}
    finally:
        world.engine.dispose()
        try:
            os.unlink(world.path)
        except OSError:
            pass


def test_cli_writes_reports(tmp_path) -> None:
    json_path, md_path = tmp_path / "ti.json", tmp_path / "ti.md"
    assert ti.main(["--json", str(json_path), "--md", str(md_path)]) == 0
    payload = json.loads(json_path.read_text())
    assert payload["schema"] == ti.SCHEMA
    assert "Multi-tenant isolation" in md_path.read_text()
