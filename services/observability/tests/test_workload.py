from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import create_engine, text
from observability.workload import WorkloadMeter, measure


def test_bounded_measurement_and_honest_resource_semantics():
    meter = WorkloadMeter()
    meter.transition("scan")
    for _ in range(1000):
        meter.query(2.0)
    meter.transition("complete", final=True)
    report = meter.report()
    assert report["db_query_count"] == 1000
    assert report["db_samples"] == 512 and report["db_samples_truncated"]
    assert report["db_cursor_total_ms"] == 2000 and report["db_cursor_max_ms"] == 2
    assert report["stages"][0]["wall_seconds"] >= 0
    assert report["capacity_qualified"] is False
    assert "SQL" not in str(report) and "parameters" not in str(report)


def test_sql_context_isolation_and_no_listener_duplication():
    engine = create_engine("sqlite://")
    def workload(n):
        with measure(engine) as m:
            with engine.connect() as c:
                for _ in range(n):
                    c.execute(text("SELECT 1"))
            return m.report()["db_query_count"]
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(workload, [3, 7])) == [3, 7]
    assert workload(2) == 2
    engine.dispose()


def test_failed_query_is_measured_and_context_reset():
    import pytest
    engine = create_engine("sqlite://")
    with measure(engine) as meter:
        with engine.connect() as c:
            with pytest.raises(Exception):
                c.execute(text("SELECT * FROM nonexistent_fixture"))
    assert meter.report()["db_query_count"] == 1
    with engine.connect() as c:
        c.execute(text("SELECT 1"))
    assert meter.report()["db_query_count"] == 1
    engine.dispose()
