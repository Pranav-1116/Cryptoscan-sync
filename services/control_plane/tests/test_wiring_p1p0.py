"""Tests for wired P0/P1 flow: findings pipeline + durable queue worker."""

from datetime import datetime, timezone

from control_plane import (
    classify_finding,
    finding_to_target,
    process_event,
    run_pipeline,
    worker_tick,
)

NOW = datetime(2026, 9, 6, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------- pipeline
def test_finding_to_target_tls_version():
    t = finding_to_target({"tls_version": "TLSv1.0", "hostname": "h1", "algorithm": "RSA", "key_size": 1024})
    assert t["tls"]["version"] == 1.0
    assert t["key_size"] == 1024


def test_classify_finding_uses_kb():
    c = classify_finding({"algorithm": "RSA", "key_size": 1024})
    assert c["is_risk"] is True and c["kb_status"] == "broken"
    c2 = classify_finding({"algorithm": "AES-256-GCM", "key_size": 256})
    assert c2["is_risk"] is False and c2["pqc"] is True


def test_run_pipeline_full_flow():
    findings = [
        {"algorithm": "RSA", "key_size": 1024, "hostname": "hsm-1", "asset_id": "a1",
         "status": "DISALLOWED", "weak_tls": False},
        {"algorithm": "ECDSA", "key_size": 256, "hostname": "ok-1", "asset_id": "a2",
         "status": "ALLOWED", "tls_version": "TLSv1.3"},
    ]
    policies = [{"id": "p", "rules": [
        {"id": "no-broken", "path": "status", "op": "ne", "value": "DISALLOWED"}]}]
    controls = [{"control_id": "SC-12", "framework": "NIST-CSF", "assets": ["a1", "a2"]}]
    out = run_pipeline(findings, policies, controls=controls)
    assert out["risks"] >= 1
    assert out["compliance_findings"], "risk should map to a control"
    assert out["posture"] is not None
    # a1 finding maps to NIST SC-12 -> GAP
    gap = next(c for c in out["posture"]["controls"] if c["control_id"] == "SC-12")
    assert gap["status"] == "GAP"


def test_run_pipeline_evidenced_control_compliant():
    # control with no findings but evidence passed separately -> compliant path
    controls = [{"control_id": "SC-8", "framework": "NIST-CSF", "assets": ["a9"]}]
    out = run_pipeline([], [], controls=controls)
    # no findings mapped -> control not evidenced -> NOT_EVIDENCED
    sc8 = next(c for c in out["posture"]["controls"] if c["control_id"] == "SC-8")
    assert sc8["status"] == "NOT_EVIDENCED"


# ---------------------------------------------------------------- worker
class FakeRepo:
    def __init__(self, events):
        self._events = [dict(e) for e in events]
        self.completed, self.failed = [], []

    def lease_next(self, worker_id, now=None):
        for e in self._events:
            if e["status"] == "queued":
                e["status"] = "leased"; e["leased_by"] = worker_id
                return _Row(e)
        return None

    def complete_event(self, eid):
        for e in self._events:
            if e["id"] == eid: e["status"] = "completed"
        self.completed.append(eid)

    def fail_event(self, eid, error):
        for e in self._events:
            if e["id"] == eid: e["status"] = "queued"; e["attempts"] = e.get("attempts", 0) + 1
        self.failed.append((eid, error))


class _Row:
    def __init__(self, d): self.__dict__.update(d); self._d = d
    def to_dict(self): return self._d


def test_process_event_blocked_by_emergency_policy():
    ev = {"id": "e1", "event_type": "scan.start", "payload": {"port": 22}}
    policy = {"emergency_stop": True}
    out = process_event(ev, policy_provider=lambda p: policy)
    assert out["outcome"] == "blocked"


def test_worker_tick_processes_and_completes():
    events = [
        {"id": "e1", "event_type": "scan.start", "status": "queued",
         "payload": {"domain": "cloud"}, "priority": "normal", "attempts": 0},
        {"id": "e2", "event_type": "siem.alert", "status": "queued",
         "payload": {}, "priority": "normal", "attempts": 0},
    ]
    handled = []
    repo = FakeRepo(events)
    result = worker_tick(repo, worker_id="w1", batch=5,
                         handler=lambda e: handled.append(e["id"]))
    assert result.processed == 2
    assert set(handled) == {"e1", "e2"}
    assert repo.failed == []


def test_worker_tick_failing_handler_retries():
    events = [{"id": "e1", "event_type": "siem.test", "status": "queued",
               "payload": {}, "attempts": 0}]
    def boom(_): raise RuntimeError("downstream down")
    repo = FakeRepo(events)
    result = worker_tick(repo, handler=boom)
    assert result.failed and repo.failed  # routed to backoff/retry, not completed
