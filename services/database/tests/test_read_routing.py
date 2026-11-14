"""Read/write splitting: replica round-robin, counted primary fallback, and
the read-your-writes pin — the honesty rules a naive router forgets."""

from __future__ import annotations

import pytest

from db.connection import read_routing
from db.connection.read_routing import ReadRouter


class FakeSession:
    def __init__(self, source: str) -> None:
        self.source = source
        self.closed = False

    def close(self) -> None:
        self.closed = True


def factory(source: str, calls: list[str]):
    def make() -> FakeSession:
        calls.append(source)
        return FakeSession(source)
    return make


def broken_factory(source: str, calls: list[str]):
    def make() -> FakeSession:
        calls.append(source)
        raise ConnectionError(f"{source} down")
    return make


@pytest.fixture(autouse=True)
def unpin():
    read_routing._pin.set(False)
    yield
    read_routing._pin.set(False)


class TestRouting:

    def test_reads_round_robin_across_replicas(self):
        calls = []
        router = ReadRouter(factory("primary", calls),
                            [factory("replica-a", calls),
                             factory("replica-b", calls)])
        sources = []
        for _ in range(4):
            with router.read_session() as session:
                sources.append(session.source)
        assert sources.count("replica-a") == 2
        assert sources.count("replica-b") == 2
        assert "primary" not in sources
        assert router.as_dict()["replica_reads_total"] == 4

    def test_writes_always_go_to_the_primary(self):
        calls = []
        router = ReadRouter(factory("primary", calls),
                            [factory("replica-a", calls)])
        with router.write_session() as session:
            assert session.source == "primary"
        assert calls == ["primary"]

    def test_a_dead_replica_falls_back_to_the_primary_and_counts(self):
        calls = []
        router = ReadRouter(factory("primary", calls),
                            [broken_factory("replica-a", calls)])
        with router.read_session() as session:
            assert session.source == "primary"
        body = router.as_dict()
        assert body["primary_fallbacks_total"] == 1
        assert body["replica_reads_total"] == 0

    def test_every_replica_down_still_serves_from_the_primary(self):
        calls = []
        router = ReadRouter(factory("primary", calls),
                            [broken_factory("replica-a", calls),
                             broken_factory("replica-b", calls)])
        with router.read_session() as session:
            assert session.source == "primary"
        assert router.as_dict()["primary_fallbacks_total"] == 2

    def test_no_replicas_is_a_pass_through(self):
        calls = []
        router = ReadRouter(factory("primary", calls))
        with router.read_session() as session:
            assert session.source == "primary"
        assert router.replica_count == 0

    def test_a_writer_reads_its_own_writes_on_the_primary(self):
        """The read-your-writes pin: once this context has written, reads
        stop going to replicas — a lagging replica must never feed a caller
        fresh from its own write the stale version."""
        calls = []
        router = ReadRouter(factory("primary", calls),
                            [factory("replica-a", calls),
                             factory("replica-b", calls)])
        with router.read_session() as session:
            assert session.source.startswith("replica")
        with router.write_session():
            pass
        assert router.as_dict()["pinned_to_primary"] is True
        for _ in range(3):
            with router.read_session() as session:
                assert session.source == "primary", (
                    "after a write, every read in this context is pinned")

    def test_sessions_always_close(self):
        calls = []
        made = []

        def make():
            session = FakeSession("primary")
            made.append(session)
            return session

        router = ReadRouter(make)
        with router.write_session():
            pass
        with router.read_session():
            pass
        assert made and all(session.closed for session in made)

    def test_as_dict_names_the_lag_boundary_honestly(self):
        body = ReadRouter(factory("primary", []), [factory("r", [])]).as_dict()
        assert "replica lag" in body["note"]
        assert "read its own writes" in body["note"] or \
            "reads its own writes" in body["note"]
        assert "synchronous_commit" in body["note"]
