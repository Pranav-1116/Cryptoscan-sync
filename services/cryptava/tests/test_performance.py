"""Live performance samples (cryptava.performance) on the fake host."""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fakehost  # noqa: E402
from cryptava.agent import host_view  # noqa: E402
from cryptava.performance import SCHEMA, Sampler, detect_scope, signed_sample  # noqa: E402
from cryptava.signing import SigningKey, canonical_bytes, verify  # noqa: E402


class FakeClock:
    """The sampler's one-second pair, but 60 s of counters pass while it 'sleeps'."""

    def __init__(self, base: Path) -> None:
        self.base, self.now, self.tick = base, 1000.0, 1
        fakehost.performance_counters(base, self.tick)

    def __call__(self) -> float:
        return self.now

    def sleep(self, _seconds: float) -> None:
        self.advance()

    def advance(self, seconds: float = 60.0) -> None:
        self.now += seconds
        self.tick += 1
        fakehost.performance_counters(self.base, self.tick)


def _tls(address, port, timeout):
    return {"ms": 4.2, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"} if port == 8443 else None


def _sampler(tmp_path, scope, **extra):
    config = fakehost.build(tmp_path / "h")
    config.update({"performance_scope": scope, **extra})
    clock = FakeClock(tmp_path / "h")
    sampler = Sampler(config, host_view(config), tls_probe=_tls, hsm_probe=lambda h, p, t: 7.5,
                      clock=clock, sleep=clock.sleep)
    return sampler, clock, config


def _by_name(sample):
    out = {}
    for metric in sample["metrics"]:
        out.setdefault(metric["name"], []).append(metric)
    return out


def test_host_scope_reads_the_whole_machine(tmp_path):
    sampler, _, _ = _sampler(tmp_path, "host")
    sample = sampler.sample()
    assert sample["schema"] == SCHEMA and sample["scope"] == "host"
    m = {name: rows[0] for name, rows in _by_name(sample).items()}
    assert m["cpu.utilization_pct"]["value"] == 25.0          # 50 busy of 200 jiffies
    assert m["ram.utilization_pct"]["value"] == pytest.approx(25.0, abs=0.01)
    assert m["system.load"]["value"] == 0.42
    assert m["process.health"]["value"] == 1 and m["process.health"]["labels"]["processes"] == "2"
    assert m["disk.iops"]["value"] == 10.0                     # 600 I/Os in 60 s, partitions not double-counted
    assert m["disk.latency_ms"]["value"] == 2.0
    assert m["network.throughput_mbps"]["value"] == 1.0        # 7.5 MB in 60 s, loopback excluded
    assert m["network.interface_errors"]["value"] == 1
    assert m["network.bandwidth_mbps"]["value"] == 25000      # link speed, kept apart from traffic
    assert m["network.connections"]["value"] == 1
    assert m["network.tcp_retransmissions"]["value"] == 3
    assert m["storage.capacity_bytes"]["value"] > 0
    assert 0 <= m["storage.utilization_pct"]["value"] <= 100
    assert all(metric["labels"]["scope"] == "host" for metric in sample["metrics"])


def test_workload_scope_measures_the_servers_own_processes(tmp_path):
    sampler, _, _ = _sampler(tmp_path, "workload")
    m = {name: rows[0] for name, rows in _by_name(sampler.sample()).items()}
    assert m["cpu.utilization_pct"]["value"] > 0
    assert "server processes" in m["cpu.utilization_pct"]["labels"]["basis"]
    assert m["container.memory_bytes"]["value"] == (81920 + 8192) * 1024
    assert m["ram.utilization_pct"]["value"] == pytest.approx(90112 / 65843204 * 100, abs=0.001)
    assert m["disk.throughput_mbps"]["value"] == pytest.approx(1_000_000 / 60 / 1e6, abs=0.001)
    assert "system.load" not in m      # the container host's load is not this server's
    assert "disk.iops" not in m


def test_tls_listeners_are_timed_and_non_tls_ports_are_left_alone(tmp_path):
    sampler, clock, _ = _sampler(tmp_path, "host", hsm_probe="127.0.0.1:8443")
    calls = []

    def probe(address, port, timeout):
        calls.append(port)
        return _tls(address, port, timeout)

    sampler.tls_probe = probe
    rows = _by_name(sampler.sample())
    tls = rows["crypto.tls_handshake_ms"]
    assert [r["labels"]["port"] for r in tls] == ["8443"]
    assert tls[0]["value"] == 4.2 and tls[0]["labels"]["algorithm"] == "TLS_AES_256_GCM_SHA384"
    assert rows["crypto.tls_negotiation_failures"][0]["value"] == 0
    assert rows["crypto.hsm_operation_latency_ms"][0]["value"] == 7.5
    assert sorted(calls) == [22, 8443]
    calls.clear()
    clock.advance()
    sampler.sample()
    assert calls == [8443]              # ssh on 22 is not re-tried every minute

    # 8443 spoke TLS before; now it fails → a negotiation failure, not a missing port
    sampler.tls_probe = lambda a, p, t: None
    clock.advance()
    rows = _by_name(sampler.sample())
    assert "crypto.tls_handshake_ms" not in rows
    assert rows["crypto.tls_negotiation_failures"][0]["value"] == 1


def test_unreadable_figures_are_missing_never_zero(tmp_path):
    sampler, _, config = _sampler(tmp_path, "host")
    proc = Path(config["proc"])
    for name in ("stat", "meminfo", "net/dev"):
        (proc / name).unlink()
    sampler.sleep = lambda s: None
    m = {name: rows[0] for name, rows in _by_name(sampler.sample()).items()}
    for name in ("cpu.utilization_pct", "ram.utilization_pct", "network.throughput_mbps"):
        assert m[name]["quality"] == "missing" and "value" not in m[name], name
        assert m[name]["reason"]


def test_scope_detection(tmp_path):
    view = host_view({"root": "/proc/1/root", "proc": "/proc", "sys": "/sys"})
    assert detect_scope({}, view) == "workload"                      # a sidecar
    assert detect_scope({"performance_scope": "host"}, view) == "host"
    fake = fakehost.build(tmp_path / "x")
    assert detect_scope({"performance_scope": "workload"}, host_view(fake)) == "workload"


def test_the_sample_is_signed_over_every_member(tmp_path):
    sampler, _, config = _sampler(tmp_path, "host")
    config["system"] = {"name": "SWIFT Gateway"}
    key = SigningKey.generate()
    identity = {"agent_id": "a1", "name": "mrdn-prod-dc1-swiftgw01", "contributor": "mrdn-prod-dc1-swiftgw01"}
    doc = signed_sample(sampler.sample(), identity, {**config, "fqdn": "swiftgw01.mrdn.bank"}, key)
    assert doc["agent_id"] == "a1" and doc["host"] == "swiftgw01.mrdn.bank" and doc["system"] == "SWIFT Gateway"
    sig = doc["signature"]
    assert sig["key_id"] == key.key_id
    assert verify(key.public_raw, canonical_bytes(doc), base64.b64decode(sig["signature"]))
    doc["metrics"][0]["value"] = 99.0
    assert not verify(key.public_raw, canonical_bytes(doc), base64.b64decode(sig["signature"]))


def test_brief_status_says_whether_live_metrics_flow():
    from cryptava.cli import brief_status

    identity = {"name": "mrdn-sbx-dc1-ibank01", "server": "http://api:8010"}
    last = {"delivered": True, "response": {"authenticity": "VALID"}, "summary": {"observed_at": "t", "planes": []}}
    assert "live metrics: none sent yet" in brief_status(identity, last, None, show_perf=True)
    ok = brief_status(identity, last, {"delivered": True, "accepted": 16, "observed_at": "10:00Z"}, show_perf=True)
    assert "live metrics 16 sent 10:00Z" in ok
    bad = brief_status(identity, last, {"delivered": False, "error": "HTTP 422"}, show_perf=True)
    assert "live metrics NOT DELIVERED (HTTP 422)" in bad
    assert "live metrics" not in brief_status(identity, last, None)
