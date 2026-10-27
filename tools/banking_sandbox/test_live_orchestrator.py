"""Live synthetic lab ticks must remain local, bounded and non-destructive."""

from pathlib import Path

import pytest

from tools.banking_sandbox import live_orchestrator as live


def test_live_controls_refuse_non_loopback_bind(tmp_path):
    with pytest.raises(ValueError, match="loopback only"):
        live.Orchestrator(tmp_path / "estate", tmp_path / "output", host="0.0.0.0")
    with pytest.raises(ValueError, match="interval"):
        live.Orchestrator(tmp_path / "estate", tmp_path / "output", interval=0.1)


def test_live_http_binds_loopback(tmp_path, monkeypatch):
    addresses = []

    class Finished(Exception):
        pass

    class Server:
        def __init__(self, address, handler):
            addresses.append(address)

        def serve_forever(self):
            raise Finished

    monkeypatch.setattr(live, "ThreadingHTTPServer", Server)
    orch = live.Orchestrator(tmp_path / "estate", tmp_path / "output", port=8091)
    with pytest.raises(Finished):
        orch.start_http()
    assert addresses == [("127.0.0.1", 8091)]


def test_existing_tick_output_is_never_deleted(tmp_path):
    estate = tmp_path / "estate"
    output = tmp_path / "output"
    tick = output / "tick-0001"
    tick.mkdir(parents=True)
    marker = tick / "retain.txt"
    marker.write_text("original")
    orch = live.Orchestrator(estate, output)
    assert orch.do_tick() is False
    assert marker.read_text() == "original"
    assert orch.state["tick"] == 0


def test_periodic_tick_respects_pause_and_updated_interval(tmp_path, monkeypatch):
    orch = live.Orchestrator(tmp_path / "estate", tmp_path / "output")
    orch.state["interval"] = 0.4
    monkeypatch.setattr(orch, "ensure_estate", lambda: None)
    ticks = []
    sleeps = []

    class Finished(Exception):
        pass

    def tick():
        ticks.append(len(sleeps))
        if len(ticks) == 3:
            raise Finished

    def sleep(_seconds):
        sleeps.append(len(ticks))
        if len(sleeps) == 1:
            orch.state["paused"] = True
        if len(sleeps) == 5:
            orch.state["paused"] = False
        if len(sleeps) > 20:
            raise AssertionError("Periodic ticks did not resume")

    monkeypatch.setattr(orch, "do_tick", tick)
    monkeypatch.setattr(live.time, "sleep", sleep)
    with pytest.raises(Finished):
        orch.loop()
    assert ticks[0] == 0
    assert ticks[1] >= 6
    assert len(ticks) == 3


def test_concurrent_tick_is_refused(tmp_path):
    orch = live.Orchestrator(Path(tmp_path / "estate"), Path(tmp_path / "output"))
    orch._tick_lock.acquire()
    try:
        assert orch.do_tick() is False
    finally:
        orch._tick_lock.release()
    assert orch.state["tick"] == 0
