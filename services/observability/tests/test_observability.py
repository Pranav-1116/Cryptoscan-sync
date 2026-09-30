"""Tests pin the observability engines: metrics exposition, W3C tracing,
SLO math, deterministic self-alerts, capacity forecasting."""

from __future__ import annotations

import sys
from pathlib import Path

SERVICES = Path(__file__).resolve().parents[2]
for d in sorted((SERVICES).iterdir()):
    if d.is_dir():
        sys.path.insert(0, str(d))

from observability.metrics import (  # noqa: E402
    MetricsRegistry,
    TraceStore,
    compute_slo,
    evaluate_self_alerts,
    forecast_quota,
    parse_traceparent,
)


# ---------------------------------------------------------------------------
# metrics
# ---------------------------------------------------------------------------
def test_prometheus_render_counts_and_histograms():
    reg = MetricsRegistry()
    reg.inc("http_requests_total", method="GET", status="200")
    reg.inc("http_requests_total", method="GET", status="200")
    reg.observe_latency("api", "GET", 200, 120.0)
    text = reg.render_prometheus()
    assert 'http_requests_total{method="GET",status="200"} 2' in text
    assert '# TYPE http_request_duration_seconds histogram' in text
    assert 'http_request_duration_seconds_count{class="api",method="GET"} 1' in text
    # 120ms falls in the le="0.250" bucket
    assert 'le="0.250"' in text


def test_window_eviction_keeps_only_recent_events():
    reg = MetricsRegistry(window=3600.0)
    reg.observe_latency("api", "GET", 200, 5.0)
    # age out the single event by faking an old timestamp via internal deque
    ts, pclass, status, dur = reg._events[0]
    reg._events[0] = (ts - 7200, pclass, status, dur)
    assert compute_slo(reg.window_events())["window_requests"] == 0


# ---------------------------------------------------------------------------
# tracing
# ---------------------------------------------------------------------------
def test_traceparent_parse_valid_and_invalid():
    tid, sid = parse_traceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
    assert tid == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert sid == "00f067aa0ba902b7"
    assert parse_traceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01") is None
    assert parse_traceparent("zz-bad") is None
    assert parse_traceparent(None) is None


def test_trace_store_continues_inbound_context(tmp_path):
    store = TraceStore(sink_path=tmp_path / "spans.jsonl")
    span = store.start_span(method="GET", path="/api/v1/x",
                            traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                            seed="seed-1")
    assert span["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert span["parent_span_id"] == "00f067aa0ba902b7"
    store.finish_span(span, 200)
    assert store.spans[0]["duration_ms"] >= 0
    assert (tmp_path / "spans.jsonl").exists()


def test_otlp_endpoint_normalization_and_payload():
    store = TraceStore(otlp_endpoint="http://collector:4318")
    assert store.otlp_endpoint == "http://collector:4318/v1/traces"
    span = store.start_span(method="POST", path="/api/v1/scans", traceparent=None, seed="otlp")
    started = span["started"]
    payload = store._otlp_payload({**span, "status": 503}, started, started + 0.25)
    exported = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert exported["traceId"] == span["trace_id"]
    assert exported["status"]["code"] == 2
    assert exported["attributes"][-1]["value"]["intValue"] == 503


# ---------------------------------------------------------------------------
# SLO math
# ---------------------------------------------------------------------------
def test_slo_healthy_and_breach_paths():
    now = 1_000.0
    ok = [(now, "api", 200, 80.0)] * 100
    slo = compute_slo(ok)
    assert slo["window_requests"] == 100
    assert slo["availability"]["breached"] is False
    assert slo["latency"]["breached"] is False
    bad = ok[:-1] + [(now, "api", 503, 9000.0)]
    slo = compute_slo(bad)
    assert slo["availability"]["breached"] is True
    assert slo["latency"]["p99_ms"] == 9000.0
    assert slo["latency"]["breached"] is True


# ---------------------------------------------------------------------------
# self-alerts
# ---------------------------------------------------------------------------
def test_alert_rules_fire_deterministically():
    reg = MetricsRegistry()
    now = __import__("time").time()
    for _ in range(10):
        reg._events.append((now - 10, "api", 503, 10.0))  # 100% 5xx in window
    alerts = evaluate_self_alerts(
        reg,
        slo={"latency": {"breached": True, "p99_ms": 900, "target_ms": 500},
             "availability": {"breached": False, "achieved": 0.9995, "target": 0.999}},
        bus_lag={"raw-events": 250}, cbom_stale=["core-banking"])
    rules = {a["rule"] for a in alerts}
    assert {"platform_5xx_rate", "platform_p99_latency",
            "bus_consumer_lag", "cbom_stale"} <= rules
    assert all(a["severity"] for a in alerts)
    quiet = evaluate_self_alerts(MetricsRegistry(), slo={
        "latency": {"breached": False}, "availability": {"breached": False}})
    assert quiet == []


# ---------------------------------------------------------------------------
# forecasting
# ---------------------------------------------------------------------------
def test_forecast_quota_projects_exhaustion_from_trend():
    out = forecast_quota([100.0, 150.0, 200.0], 400)
    assert out["trend"] == "+50.0/month"
    assert out["months_to_exhaustion"] == 4.0  # (400-200)/50
    flat = forecast_quota([100.0, 100.0], 400)
    assert flat["months_to_exhaustion"] is None
    single = forecast_quota([50.0], 200)
    assert single["months_to_exhaustion"] == 3.0
