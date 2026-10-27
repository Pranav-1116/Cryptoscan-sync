"""The operational counters update.md section 5 asks to alert on.

These count events that leave no trace anywhere else. A cross-tenant request
the guard correctly refuses writes no row; an SSE client that reconnects
outside the retention window gets its gap event and disappears. Without a
counter the only evidence either control is working is the absence of
incidents, which is not evidence.

The test that matters most here is the last one. Publishing a permanent zero
for an event nobody instrumented does not read as "not measured" -- it reads
as "never happened", which is a stronger and false claim, and exactly the
kind this product exists to catch in other people's reports.
"""

from __future__ import annotations

import pytest

from api.observability import operational_counters as oc


@pytest.fixture(autouse=True)
def _clean():
    oc.reset_for_tests()
    yield
    oc.reset_for_tests()


def test_known_events_report_zero_before_they_happen():
    """An alert rule cannot reference a series that does not exist yet.

    A counter that springs into being on the first failure is unalertable
    until after the first failure, which is the one time you needed it.
    """
    snap = oc.snapshot()
    for name in oc.KNOWN:
        assert snap[name] == 0


def test_incrementing_is_visible_and_monotonic():
    oc.incr("tenant_isolation_violation")
    oc.incr("tenant_isolation_violation")
    oc.incr("event_replay_gap", 3)

    snap = oc.snapshot()
    assert snap["tenant_isolation_violation"] == 2
    assert snap["event_replay_gap"] == 3
    assert snap["persistence_failure"] == 0


def test_counts_survive_concurrent_increments():
    """Scan workers and request handlers increment from several threads."""
    import threading

    def bump():
        for _ in range(200):
            oc.incr("persistence_failure")

    threads = [threading.Thread(target=bump) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert oc.snapshot()["persistence_failure"] == 1600


def test_an_unknown_event_is_recorded_but_not_pre_declared():
    """Ad-hoc names still count; they just do not get a zero line."""
    assert "surprise_event" not in oc.snapshot()
    oc.incr("surprise_event")
    assert oc.snapshot()["surprise_event"] == 1


def test_only_instrumented_events_are_declared_known():
    """Guards against a zero that asserts something nobody measured.

    Every name in KNOWN is published as 0 before its first occurrence, so an
    operator reading the dashboard concludes it has not happened. That is
    only true if the event is actually counted somewhere. This pins the list
    to the increment sites that exist, so adding a name without wiring it
    fails here rather than shipping a reassuring lie.
    """
    import pathlib
    import re

    api_root = pathlib.Path(__file__).resolve().parents[2] / "api"
    sources = [p.read_text(encoding="utf-8") for p in api_root.rglob("*.py")
               if "observability/operational_counters" not in p.as_posix()]
    blob = "\n".join(sources)

    for name in oc.KNOWN:
        assert re.search(rf'incr\(\s*["\']{re.escape(name)}["\']', blob), (
            f"{name!r} is declared KNOWN and therefore published as 0, but no "
            "incr() call exists for it. Either wire it up or remove it: a zero "
            "for an unmeasured event claims it never happened."
        )
