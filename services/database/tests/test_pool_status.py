"""Connection-pool observability and tunability: the numbers an operator
needs BEFORE a pool shortage becomes an outage."""

from __future__ import annotations

import pytest

from db.connection.engine import create_db_engine, pool_status


class TestPoolStatus:

    def test_it_reports_honest_numbers(self):
        engine = create_db_engine("sqlite://")
        try:
            body = pool_status(engine)
            assert body["pool_size"] == 10
            assert body["max_overflow"] == 20
            assert body["capacity"] == 30  # size + overflow, the real ceiling
            assert body["checkedout"] == 0
            assert body["pressure"] is False
            assert body["dialect"] == "sqlite"
        finally:
            engine.dispose()

    def test_pool_sizing_is_env_tunable(self, monkeypatch):
        monkeypatch.setenv("DB_POOL_SIZE", "3")
        monkeypatch.setenv("DB_MAX_OVERFLOW", "2")
        monkeypatch.setenv("DB_POOL_TIMEOUT", "7")
        engine = create_db_engine("sqlite://")
        try:
            body = pool_status(engine)
            assert body["pool_size"] == 3
            assert body["max_overflow"] == 2
            assert body["pool_timeout"] == 7
            assert body["capacity"] == 5
        finally:
            engine.dispose()

    def test_bad_pool_settings_fail_loudly_not_silently(self, monkeypatch):
        monkeypatch.setenv("DB_POOL_SIZE", "enormous")
        with pytest.raises(ValueError, match="DB_POOL_SIZE"):
            create_db_engine("sqlite://")
        monkeypatch.setenv("DB_POOL_SIZE", "0")
        with pytest.raises(ValueError, match="DB_POOL_SIZE"):
            create_db_engine("sqlite://")

    def test_pressure_is_named_before_it_becomes_an_outage(self):
        engine = create_db_engine("sqlite://")
        engine.dispose()
        # A one-slot pool with the only connection checked out: 100% in use.
        import os
        os.environ["DB_POOL_SIZE"] = "1"
        os.environ["DB_MAX_OVERFLOW"] = "0"
        try:
            engine = create_db_engine("sqlite://")
            try:
                with engine.connect():
                    body = pool_status(engine)
                    assert body["checkedout"] == 1
                    assert body["capacity"] == 1
                    assert body["pressure"] is True, (
                        "a saturated pool must say so — silence is how a "
                        "shortage becomes an outage")
            finally:
                engine.dispose()
        finally:
            os.environ.pop("DB_POOL_SIZE", None)
            os.environ.pop("DB_MAX_OVERFLOW", None)

    def test_the_health_report_carries_the_pool_check(self):
        from api.routers.health import dependency_report

        report = dependency_report()
        by_name = {c["name"]: c for c in report["checks"]}
        pool = by_name["connection_pool"]
        if pool["status"] == "skipped":
            # No introspectable pool in this environment (placeholder URL):
            # the check says so with the error named, never fakes a signal.
            assert pool["error_type"]
        else:
            assert pool["status"] in ("ok", "down")
            assert "checked out" in pool["detail"]
            assert pool["pool"]["capacity"] >= pool["pool"]["checkedout"]
