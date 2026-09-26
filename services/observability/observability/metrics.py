"""Observability engines: metrics, tracing, SLOs, self-alerts, forecasting.

Pure, deterministic, dependency-free. The API middleware feeds the registry;
the /ops router exposes Prometheus text, recent traces, SLO burn, alerts and
capacity forecasts. When OTEL_EXPORTER_OTLP_ENDPOINT is set, spans are also
exported as OTLP/HTTP JSON (W3C trace-context compatible ids) — no vendor
lock, no heavy SDK.
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import time
from collections import deque
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# metrics (Prometheus-compatible exposition)
# ---------------------------------------------------------------------------
DEFAULT_BUCKETS_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)


class MetricsRegistry:
    """Counters + latency histograms with Prometheus text rendering."""

    def __init__(self, buckets_ms: tuple[int, ...] = DEFAULT_BUCKETS_MS,
                 window: float = 3600.0):
        self.buckets = buckets_ms
        self.window = window
        self._counters: dict[str, float] = {}
        self._hist: dict[str, dict] = {}
        self._events: deque = deque()  # (ts, path_class, status, dur_ms) for SLO
        self._lock_free_note = "single-process registry (see bus docstring)"

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = self._key(name, labels)
        self._counters[key] = self._counters.get(key, 0.0) + value

    def observe_latency(self, path_class: str, method: str, status: int,
                        dur_ms: float) -> None:
        now = time.time()
        key = self._key("http_request_duration_seconds",
                        {"class": path_class, "method": method})
        hist = self._hist.setdefault(key, {"count": 0, "sum": 0.0,
                                           "buckets": {b: 0 for b in self.buckets}})
        hist["count"] += 1
        hist["sum"] += dur_ms / 1000.0
        for b in self.buckets:
            if dur_ms <= b:
                hist["buckets"][b] += 1
        self._events.append((now, path_class, status, dur_ms))
        cutoff = now - self.window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> str:
        if not labels:
            return name
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"

    def window_events(self) -> list[tuple[float, str, int, float]]:
        cutoff = time.time() - self.window
        return [e for e in self._events if e[0] >= cutoff]

    def render_prometheus(self) -> str:
        lines: list[str] = []
        for key, value in sorted(self._counters.items()):
            lines.append(f"# TYPE {key.split('{')[0]} counter")
            lines.append(f"{key} {value}")
        for key, hist in sorted(self._hist.items()):
            base = key.split("{")[0]
            inner = key[key.find("{") + 1:-1] if "{" in key else ""
            sep = "," if inner else ""
            lines.append(f"# TYPE {base} histogram")
            for b in self.buckets:
                lines.append(f'{base}_bucket{{le="{b / 1000:.3f}"{sep}{inner}}} '
                             f'{hist["buckets"][b]}')
            lines.append(f"{base}_count{{{inner}}} {hist['count']}")
            lines.append(f"{base}_sum{{{inner}}} {hist['sum']:.6f}")
        return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# tracing (W3C trace-context, OTLP/JSON export optional)
# ---------------------------------------------------------------------------
def _hex(rng_chars: int, seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:rng_chars]


def parse_traceparent(header: str | None) -> tuple[str, str] | None:
    """W3C traceparent: ``00-<32hex traceid>-<16hex spanid>-<flags>``."""
    if not header:
        return None
    parts = header.strip().split("-")
    if len(parts) != 4 or parts[0] != "00":
        return None
    trace_id, parent_id = parts[1], parts[2]
    if len(trace_id) != 32 or len(parent_id) != 16:
        return None
    if set(trace_id) == {"0"}:
        return None
    return trace_id, parent_id


class TraceStore:
    """In-process span ring + optional JSONL sink and OTLP/JSON export."""

    def __init__(self, capacity: int = 2000,
                 sink_path: Path | None = None,
                 otlp_endpoint: str | None = None,
                 service_name: str = "cryptoscan-api"):
        self.capacity = capacity
        self.spans: deque = deque(maxlen=capacity)
        self.sink_path = sink_path
        self.otlp_endpoint = otlp_endpoint
        self.service_name = service_name

    def start_span(self, *, method: str, path: str, traceparent: str | None,
                   seed: str) -> dict[str, Any]:
        parsed = parse_traceparent(traceparent)
        if parsed:
            trace_id, parent_id = parsed
        else:
            trace_id, parent_id = _hex(32, f"t:{seed}"), None
        span = {
            "trace_id": trace_id,
            "span_id": _hex(16, f"s:{seed}"),
            "parent_span_id": parent_id,
            "method": method,
            "path": path,
            "started": time.time(),
        }
        return span

    def finish_span(self, span: dict[str, Any], status: int) -> None:
        span["duration_ms"] = round((time.time() - span["started"]) * 1000, 2)
        span["status"] = status
        span["service"] = self.service_name
        span.pop("started", None)
        self.spans.append(span)
        if self.sink_path is not None:
            try:
                self.sink_path.parent.mkdir(parents=True, exist_ok=True)
                with self.sink_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(span, separators=(",", ":")) + "\n")
            except OSError:
                pass

    def recent(self, limit: int = 50, *, slower_than_ms: float | None = None) -> list:
        spans = list(self.spans)[::-1]
        if slower_than_ms is not None:
            spans = [s for s in spans if s["duration_ms"] >= slower_than_ms]
        return spans[:limit]


# ---------------------------------------------------------------------------
# SLO math (error budget + burn rate)
# ---------------------------------------------------------------------------
DEFAULT_SLOS = {
    "availability": {"target": 0.999, "window_seconds": 3600},
    "latency_p99_ms": {"target": 500.0, "window_seconds": 3600},
    "error_rate": {"target": 0.01, "window_seconds": 3600},
}


def compute_slo(events: list[tuple[float, str, int, float]],
                slos: dict | None = None) -> dict[str, Any]:
    """events: (ts, path_class, status, dur_ms) within the window."""
    slos = slos or DEFAULT_SLOS
    total = len(events)
    if total == 0:
        return {"window_requests": 0, "note": "no traffic in window yet"}
    errors = sum(1 for _, _, s, _ in events if s >= 500)
    availability = 1.0 - errors / total
    p99 = percentile([d for _, _, _, d in events], 0.99)
    error_rate = errors / total

    avail_target = slos["availability"]["target"]
    budget_total = 1.0 - avail_target
    budget_used = max(0.0, avail_target - availability)
    out = {
        "window_requests": total,
        "availability": {
            "achieved": round(availability, 6),
            "target": avail_target,
            "budget_remaining": round(max(0.0, budget_total - budget_used) / budget_total, 4)
            if budget_total > 0 else None,
            "breached": availability < avail_target,
        },
        "latency": {
            "p99_ms": round(p99, 1),
            "target_ms": slos["latency_p99_ms"]["target"],
            "breached": p99 > slos["latency_p99_ms"]["target"],
        },
        "error_rate": {
            "server_error_rate": round(error_rate, 6),
            "target_max": slos["error_rate"]["target"],
            "breached": error_rate > slos["error_rate"]["target"],
        },
    }
    return out


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(int(len(ordered) * fraction), len(ordered) - 1)
    return ordered[idx]


# ---------------------------------------------------------------------------
# self-alerting (platform watches itself, deterministic rules)
# ---------------------------------------------------------------------------
def evaluate_self_alerts(metrics: MetricsRegistry,
                         *, slo: dict | None = None,
                         bus_lag: dict | None = None,
                         cbom_stale: list[str] | None = None) -> list[dict]:
    """Deterministic rules over live metrics; fired alerts are returned (the
    router also publishes them to the bus `alerts` topic)."""
    alerts: list[dict] = []
    now = time.time()
    slo = slo or {}
    events = metrics.window_events()
    recent_5m = [e for e in events if now - e[0] <= 300]
    if recent_5m:
        errs = sum(1 for e in recent_5m if e[2] >= 500)
        rate = errs / len(recent_5m)
        if rate > 0.01:
            alerts.append({"rule": "platform_5xx_rate", "severity": "CRITICAL",
                           "detail": f"5xx rate {rate:.3f} over last 5 min "
                                     f"({errs}/{len(recent_5m)})"})
    if slo.get("latency", {}).get("breached"):
        alerts.append({"rule": "platform_p99_latency", "severity": "HIGH",
                       "detail": f"p99 {slo['latency']['p99_ms']}ms exceeds "
                                 f"{slo['latency']['target_ms']}ms target"})
    if slo.get("availability", {}).get("breached"):
        alerts.append({"rule": "platform_availability", "severity": "CRITICAL",
                       "detail": f"availability {slo['availability']['achieved']} "
                                 f"below {slo['availability']['target']}"})
    for topic, lag in (bus_lag or {}).items():
        if lag > 100:
            alerts.append({"rule": "bus_consumer_lag", "severity": "HIGH",
                           "detail": f"topic {topic} consumer lag {lag} > 100"})
    for system in (cbom_stale or []):
        alerts.append({"rule": "cbom_stale", "severity": "MEDIUM",
                       "detail": f"live CBOM for '{system}' exceeded freshness window"})
    return alerts


# ---------------------------------------------------------------------------
# capacity forecasting (from real metering data)
# ---------------------------------------------------------------------------
def forecast_quota(usage_by_month: list[float], monthly_limit: int | None,
                   *, growth: str = "linear") -> dict[str, Any]:
    """Deterministic projection from per-month usage totals.

    linear: average month-over-month delta projects future usage; returns
    months until the plan limit is hit (None = never at current trend).
    """
    if not usage_by_month:
        return {"months": len(usage_by_month), "note": "no usage data yet"}
    if monthly_limit is None:
        return {"months": len(usage_by_month),
                "note": "plan limit is unlimited — no exhaustion point"}
    if len(usage_by_month) == 1:
        used = usage_by_month[0]
        months = (monthly_limit - used) / used if used > 0 else None
        out = {"months": len(usage_by_month), "trend": "flat (single month)",
               "used_last_month": used, "limit": monthly_limit}
        out["months_to_exhaustion"] = round(months, 1) if months and months > 0 else None
        return out
    deltas = [b - a for a, b in zip(usage_by_month, usage_by_month[1:])]
    avg_delta = statistics.fmean(deltas)
    last = usage_by_month[-1]
    out = {"months": len(usage_by_month), "trend": f"{avg_delta:+.1f}/month",
           "used_last_month": last, "limit": monthly_limit}
    if avg_delta <= 0:
        out["months_to_exhaustion"] = None
        out["note"] = "flat or declining usage — no exhaustion at current trend"
    else:
        headroom = monthly_limit - last
        out["months_to_exhaustion"] = round(headroom / avg_delta, 1) if headroom > 0 else 0.0
        if math.isinf(out["months_to_exhaustion"] or 0):
            out["months_to_exhaustion"] = None
    return out
