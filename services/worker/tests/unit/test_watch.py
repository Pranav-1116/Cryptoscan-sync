"""Change-watch: probes, change detector, engine watch-triggered rescans.

Covers the enterprise live-scanning contract:
- git probe resolves a repo HEAD (real `git ls-remote` against a local repo)
- container probe degrades honestly when docker is absent
- first observation is a baseline (no alert); only transitions alert
- a watched target that changes is rescanned *immediately*, not on schedule
- probe failures never break the tick, never clobber the fingerprint, and
  never spam events (deduped per distinct error)
- jitter and bounded concurrency are opt-in and deterministic under test
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from db.connection.session import Base
from db.repositories.monitor_repository import MonitorRepository
from worker.monitor.engine import MonitorEngine
from worker.monitor.watch import (
    UNCHANGED,
    CHANGED,
    UNKNOWN,
    ChangeDetector,
    ProbeResult,
    container_probe,
    git_probe,
)

T0 = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _target(session, *, name="watched", target_type="REPO", config=None, interval_seconds=600,
            next_scan_at=None):
    return MonitorRepository(session).create(
        name=name, target_type=target_type,
        config=config or {"watch": True, "repo": "/tmp/none"},
        interval_seconds=interval_seconds,
        next_scan_at=next_scan_at or (T0 - timedelta(seconds=1)),  # due at T0 by default
    )


def _engine(session, runners, **kwargs):
    return MonitorEngine(session, runners=runners, clock=lambda: T0, **kwargs)


# ------------------------------------------------------------- git probe


def test_git_probe_resolves_local_repo_head(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    import subprocess

    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    (repo / "a.txt").write_text("crypto")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init"],
        check=True, capture_output=True,
    )
    result = git_probe({"repo": str(repo), "branch": "main"})
    assert result.ok and result.state and len(result.state) == 40
    # same repo, branch omitted -> tries main/master/HEAD and still resolves
    result2 = git_probe({"repo": str(repo)})
    assert result2.ok and result2.state == result.state


def test_git_probe_missing_repo_is_not_ok():
    result = git_probe({"repo": "/nonexistent/repo/xyz"})
    assert not result.ok and result.error


def test_git_probe_missing_repo_url_is_not_ok():
    result = git_probe({"repo": "  "})
    assert not result.ok and "repo URL" in result.error


def test_git_probe_timeout_is_reported(monkeypatch):
    import subprocess

    def boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="git ls-remote", timeout=0.001)

    monkeypatch.setattr("subprocess.run", boom)
    result = git_probe({"repo": "https://example.com/r.git", "branch": "main"}, timeout=0.001)
    assert not result.ok and "timed out" in result.error


# ---------------------------------------------------------- container probe


def test_container_probe_unsupported_without_docker(monkeypatch):
    monkeypatch.setattr("worker.monitor.watch.shutil.which", lambda _name: None)
    result = container_probe({"image": "registry/app:tag"})
    assert not result.ok and not result.supported and "docker CLI" in result.error


def test_container_probe_needs_reference(monkeypatch):
    monkeypatch.setattr("worker.monitor.watch.shutil.which", lambda _name: "/usr/bin/docker")
    result = container_probe({"image": " "})
    assert not result.ok and "image reference" in result.error


# -------------------------------------------------------- change detector


def test_change_detector_verdicts():
    assert ChangeDetector.detect(None, ProbeResult(state="abc123", ok=True)) == (UNKNOWN, "abc123")
    assert ChangeDetector.detect("abc123", ProbeResult(state="abc123", ok=True)) == (UNCHANGED, "abc123")
    assert ChangeDetector.detect("abc123", ProbeResult(state="def456", ok=True)) == (CHANGED, "def456")
    # probe failure keeps the previous fingerprint (never clobbers)
    assert ChangeDetector.detect("abc123", ProbeResult(state=None, ok=False, error="down")) == (UNKNOWN, "abc123")


# ------------------------------------------------- engine watch behaviour


def test_engine_watch_change_triggers_immediate_rescan():
    """A changed watched target runs now, even though its next window is far out."""
    session = _session()
    # previous observation already stored ("old"); the probe now sees "new"
    target = _target(session, config={"watch": True, "repo": "/r", "watch_state": {"state": "old"}},
                     next_scan_at=T0 + timedelta(hours=24))

    def fake_probe(config, *, timeout):
        return ProbeResult(state="new", ok=True)

    def runner(config, sess):
        return {"summary": {"job": "ok"}, "issues": []}

    engine = _engine(session, {"REPO": runner}, probes={"REPO": fake_probe})
    outcome = engine.tick()
    assert outcome["watch_triggered"] == 1 and outcome["ran"] == 1
    assert target.status == "OK" and target.last_scan_at == T0
    # scanned NOW and rescheduled a full interval out — the old +24h window
    # did not hold the fleet up
    assert target.next_scan_at == T0 + timedelta(seconds=600)
    events = MonitorRepository(session).list_events()
    assert sorted(e.event_type for e in events) == ["CHANGE_DETECTED", "SCAN_OK"]
    assert (target.config or {}).get("watch_state", {}).get("state") == "new"


def test_engine_watch_unchanged_defers_to_schedule():
    """No change + not due -> no scan, no events."""
    session = _session()
    _target(session, config={"watch": True, "repo": "/r"}, next_scan_at=T0 + timedelta(hours=24))
    seen = {"n": 0}

    def fake_probe(config, *, timeout):
        return ProbeResult(state="same", ok=True)

    def runner(config, sess):
        seen["n"] += 1
        return {"summary": {"job": "ok"}, "issues": []}

    engine = _engine(session, {"REPO": runner}, probes={"REPO": fake_probe})
    outcome = engine.tick()
    assert outcome["ran"] == 0 and outcome["watch_triggered"] == 0
    assert seen["n"] == 0
    assert MonitorRepository(session).list_events() == []


def test_engine_watch_first_observation_is_baseline_not_alert():
    """First probe stores the fingerprint, scans only if due, never alerts."""
    session = _session()
    target = _target(session, config={"watch": True, "repo": "/r"})  # due at T0

    def fake_probe(config, *, timeout):
        return ProbeResult(state="baseline-sha", ok=True)

    def runner(config, sess):
        return {"summary": {"job": "ok"}, "issues": []}

    engine = _engine(session, {"REPO": runner}, probes={"REPO": fake_probe})
    outcome = engine.tick()
    assert outcome["ran"] == 1 and outcome["watch_triggered"] == 0  # ran because it was due
    events = [e.event_type for e in MonitorRepository(session).list_events()]
    assert "CHANGE_DETECTED" not in events and events == ["SCAN_OK"]
    assert (target.config or {}).get("watch_state", {}).get("state") == "baseline-sha"


def test_engine_watch_probe_failure_keeps_scanning_and_dedupes_events():
    """Probe down: target still scans on schedule; WATCH_PROBE_FAILED once per error."""
    session = _session()
    target = _target(session, config={"watch": True, "repo": "/r"})  # due at T0

    def fake_probe(config, *, timeout):
        return ProbeResult(state=None, ok=False, error="remote unreachable")

    def runner(config, sess):
        return {"summary": {"job": "ok"}, "issues": []}

    engine = _engine(session, {"REPO": runner}, probes={"REPO": fake_probe})
    outcome = engine.tick()
    assert outcome["ran"] == 1  # schedule path still fires
    events = [e.event_type for e in MonitorRepository(session).list_events()]
    assert "WATCH_PROBE_FAILED" in events and "SCAN_OK" in events
    # second tick, same error -> no duplicate WATCH_PROBE_FAILED
    engine.tick()
    assert len([e for e in MonitorRepository(session).list_events() if e.event_type == "WATCH_PROBE_FAILED"]) == 1
    # recovery: a good probe clears the error, so a later failure alerts again
    state = {"n": 0}

    def recovering_probe(config, *, timeout):
        state["n"] += 1
        if state["n"] == 1:
            return ProbeResult(state="sha1", ok=True)
        return ProbeResult(state=None, ok=False, error="remote unreachable")

    engine2 = _engine(session, {"REPO": runner}, probes={"REPO": recovering_probe})
    engine2.tick()
    engine2.tick()
    failed = [e for e in MonitorRepository(session).list_events() if e.event_type == "WATCH_PROBE_FAILED"]
    assert len(failed) == 2


def test_engine_watch_unsupported_type_is_honest_and_once():
    """watch on a NETWORK target -> WATCH_UNSUPPORTED once; scheduled scans continue."""
    session = _session()
    target = _target(session, target_type="NETWORK",
                     config={"watch": True, "endpoints": ["h:443"]})

    def runner(config, sess):
        return {"summary": {"probed": 1}, "issues": []}

    engine = _engine(session, {"NETWORK": runner})  # default probes: no NETWORK
    engine.tick()
    engine.tick()
    events = MonitorRepository(session).list_events()
    unsupported = [e for e in events if e.event_type == "WATCH_UNSUPPORTED"]
    assert len(unsupported) == 1
    assert "not supported for NETWORK" in unsupported[0].detail
    assert (target.config or {}).get("watch_state", {}).get("unsupported") is True


# ------------------------------------------------------- jitter + concurrency


def test_jitter_pushes_next_scan_at_by_fraction():
    session = _session()
    target = _target(session)  # due at T0

    def runner(config, sess):
        return {"summary": {"ok": 1}, "issues": []}

    engine = _engine(session, {"REPO": runner},
                     jitter_fraction=1.0, rng=lambda lo, hi: hi * 0.5)  # exactly +50% of interval
    engine.tick()
    assert target.next_scan_at == T0 + timedelta(seconds=600 * 1.5)


def test_jitter_disabled_is_deterministic():
    session = _session()
    target = _target(session)

    def runner(config, sess):
        return {"summary": {"ok": 1}, "issues": []}

    engine = _engine(session, {"REPO": runner}, jitter_fraction=0.0)
    engine.tick()
    assert target.next_scan_at == T0 + timedelta(seconds=600)


def test_concurrent_tick_runs_all_due_targets_with_fresh_sessions():
    # One shared in-memory engine (StaticPool): every session sees the same DB,
    # but each worker gets its own ORM session — exactly like the daemon loop.
    engine_sql = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine_sql)
    SessionMaker = sessionmaker(bind=engine_sql, expire_on_commit=False)
    session = SessionMaker()
    for i in range(3):
        _target(session, name=f"t{i}", target_type="CLOUD", config={"watch": False, "account": f"a{i}"})
    session.commit()

    seen = []
    lock = __import__("threading").Lock()

    def runner(config, sess):
        with lock:
            seen.append(config["account"])
        return {"summary": {"ok": 1}, "issues": []}

    engine = _engine(session, {"CLOUD": runner},
                     session_factory=SessionMaker, concurrency=3)
    outcome = engine.tick()
    assert outcome["ran"] == 3
    assert sorted(seen) == ["a0", "a1", "a2"]
