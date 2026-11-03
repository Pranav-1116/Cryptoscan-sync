"""Prometheus rules that actually match the metrics this product emits.

Three failure modes, all of them silent until an incident:

1. **Dead rules.** An alert expression references a metric nobody reports. It
   never fires, and the dashboard looks calm forever.
2. **Alerts inside the patient.** Every SLO alert evaluated inside the API dies
   with the API. At least one rule must depend on scrape health (`up`), not on
   the application's own telemetry.
3. **Threshold drift.** The API's `DEFAULT_SLOS` says p99 is 500 ms and the
   alert says 2 s, so the product claims an SLO it never pages on.

This file drives the real middleware to produce real metric names, then checks
the rule file against that output.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "infra" / "monitoring" / "prometheus" / "alerts.yml"
PROM_CONFIG = ROOT / "infra" / "monitoring" / "prometheus" / "prometheus.yml"

sys.path.insert(0, str(ROOT / "services" / "api"))
sys.path.insert(0, str(ROOT / "services" / "observability"))


def load_rules() -> list[dict]:
    document = yaml.safe_load(RULES.read_text(encoding="utf-8"))
    return [rule for group in document["groups"] for rule in group["rules"]]


def emitted_metric_families() -> set[str]:
    """Render the registry as the middleware fills it, and read the families."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from api.middleware.observability_middleware import ObservabilityMiddleware

    async def ok(request):
        return PlainTextResponse("ok")

    async def boom(request):
        return PlainTextResponse("nope", status_code=500)

    from observability.metrics import MetricsRegistry, TraceStore

    app = Starlette(routes=[Route("/api/v1/scans", ok), Route("/api/v1/fail", boom)])
    registry = MetricsRegistry()
    wrapped = ObservabilityMiddleware(app, registry=registry, traces=TraceStore(capacity=10))
    with TestClient(wrapped, raise_server_exceptions=False) as client:
        client.get("/api/v1/scans")
        client.get("/api/v1/fail")
    text = registry.render_prometheus()
    names = {line.split("{")[0].split(" ")[0] for line in text.splitlines()
             if line and not line.startswith("#")}
    names |= router_metric_names()
    return names


def router_metric_names() -> set[str]:
    """Series the API emits itself, read from the router that renders them.

    `api/routers/metrics.py` appends gauges as text lines rather than through the
    middleware registry, so a rule about queue depth or collection coverage would
    have looked "dead" to this test even though /metrics emits it. Reading the
    names from the router keeps the check honest: a rule may only reference a
    series that some code in this tree actually writes.
    """
    source = (ROOT / "services" / "api" / "api" / "routers" / "metrics.py").read_text(encoding="utf-8")
    return set(re.findall(r'["\'](cryptoscan_[a-z0-9_]+)["\']', source))


# PromQL identifiers may contain ':' (recording-rule namespace) — tokenising on
# word boundaries splits `cryptoscan:http_error_ratio:rate5m` into fragments and
# reports a missing metric for each one.
REFERENCE = re.compile(
    r"(?<![a-zA-Z0-9_:])([a-zA-Z_:][a-zA-Z0-9_:]*)(?![a-zA-Z0-9_:])(?!\s*[({=])"
)
LABELS = re.compile(r"\{[^{}]*\}")


def metric_references(expr: str) -> set[str]:
    """Metric-like identifiers in an expression, minus functions and keywords."""
    ignored = {
        "sum", "rate", "by", "and", "or", "unless", "on", "ignoring", "group_left",
        "group_right", "clamp_min", "clamp_max", "histogram_quantile", "le", "absent",
        "humanize", "humanizePercentage", "humanizeDuration", "offset", "bool",
        "avg", "min", "max", "count", "increase", "irate", "without", "inf",
    }
    names = set()
    # Label matchers and label lists are not metrics.
    stripped = LABELS.sub(" ", expr)
    for token in REFERENCE.findall(stripped):
        if token in ignored or token.isdigit() or token in {"true", "false"}:
            continue
        names.add(token)
    return names


def test_the_rules_parse_and_every_alert_is_actionable():
    rules = load_rules()
    alerts = [rule for rule in rules if "alert" in rule]
    assert alerts, "no alerts defined"
    for rule in rules:
        assert rule.get("expr"), rule
    for alert in alerts:
        assert alert.get("labels", {}).get("severity") in {"critical", "high", "medium", "low"}, alert["alert"]
        assert alert.get("annotations", {}).get("summary"), alert["alert"]
        runbook = alert["annotations"].get("runbook_url")
        assert runbook, f"{alert['alert']} has no runbook_url"
        assert (ROOT / runbook).is_file(), f"{alert['alert']} points at a missing runbook: {runbook}"


def test_every_referenced_metric_is_actually_emitted():
    emitted = emitted_metric_families()
    assert "http_requests_total" in emitted and "http_server_errors_total" in emitted
    assert any(name.startswith("http_request_duration_seconds") for name in emitted)

    # Strip metric suffixes so a _bucket reference matches its family.
    families = set()
    for name in emitted:
        for suffix in ("_bucket", "_count", "_sum"):
            if name.endswith(suffix):
                families.add(name[: -len(suffix)])
        families.add(name)

    missing: list[str] = []
    for rule in load_rules():
        for name in metric_references(rule["expr"]):
            if name in {"up"} or name.startswith("cryptoscan:"):
                continue  # scrape health, and this file's own recording rules
            if name not in families:
                missing.append(f"{rule.get('alert') or rule.get('record')}: {name}")
    assert not missing, "rules reference metrics the API never emits: " + ", ".join(sorted(missing))


def test_recording_rules_resolve_in_order():
    """A recording rule may only refer to earlier records, never to a later one."""
    seen: set[str] = set()
    for group in yaml.safe_load(RULES.read_text(encoding="utf-8"))["groups"]:
        for rule in group["rules"]:
            references = {name for name in metric_references(rule["expr"]) if name.startswith("cryptoscan:")}
            unknown = references - seen
            assert not unknown, (
                f"{rule['record']} depends on {sorted(unknown)}, which is defined later or not at all"
            )
            if "record" in rule:
                seen.add(rule["record"])


def test_something_pages_when_the_api_itself_is_dead():
    """At least one alert must rest on scrape health rather than on app telemetry."""
    independent = [
        rule for rule in load_rules()
        if "alert" in rule and ("up{" in rule["expr"] or "absent(" in rule["expr"])
    ]
    assert independent, "every alert is evaluated inside the API: nothing pages when it dies"


def test_thresholds_match_the_application_slos():
    from observability.metrics import DEFAULT_SLOS

    availability = DEFAULT_SLOS["availability"]["target"]
    budget = 1.0 - availability
    rules = {rule.get("alert"): rule for rule in load_rules()}
    # Long-window budget burn: 14.4x is the standard multi-window burn-rate
    # multiplier, so the alert threshold must be 14.4 x the error budget.
    burn = rules["CryptoscanAvailabilityBudgetBurnHigh"]["expr"]
    assert f"{14.4 * budget:.4f}".rstrip("0") in burn, (
        f"budget-burn alert disagrees with DEFAULT_SLOS ({availability}): {burn}"
    )

    error_rate = DEFAULT_SLOS["error_rate"]["target"]
    assert str(error_rate) in rules["CryptoscanServerErrorRate"]["expr"]
    p99_seconds = DEFAULT_SLOS["latency_p99_ms"]["target"] / 1000.0
    assert str(p99_seconds) in rules["CryptoscanLatencyP99High"]["expr"]


def test_prometheus_loads_the_rule_file():
    config = yaml.safe_load(PROM_CONFIG.read_text(encoding="utf-8"))
    rule_files = config.get("rule_files") or []
    assert any(path.endswith("alerts.yml") for path in rule_files), (
        "prometheus.yml does not load alerts.yml: the rules would never be evaluated"
    )
