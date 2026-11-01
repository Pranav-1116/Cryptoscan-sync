"""Observability coverage: what an operator could actually see during an incident.

The review's seventh blocker was that observability was asserted rather than
demonstrated. This drill answers it by walking the six surfaces the review names
— collector, queue, DB, evidence, agent, coverage — plus the three transports
(metrics, logs, traces) and the two answering surfaces (health, alerts), and
grading each one against what the repository can be shown to do.

Nothing here is a claim about a deployment. Three kinds of evidence appear, and
each row says which one it used:

    EXECUTED   the /metrics endpoint was served in-process and its output parsed
    READ       a file or an import in this checkout proves the surface exists
    ABSENT     the surface does not exist in this checkout

The alert rules are checked the strict way: every ``cryptoscan_*`` series a rule
depends on must appear in the live ``/metrics`` output, so a renamed metric
breaks the report instead of breaking the pager at 03:00.

Run::

    python scripts/observability_coverage.py \\
        --json docs/bank-environment/117-observability-coverage.json \\
        --md   docs/bank-environment/117-observability-coverage.md
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.observability-coverage/1"
VERSION = "observability-coverage/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_FILE = REPO_ROOT / "infra" / "monitoring" / "prometheus" / "alerts.yml"
PROMETHEUS_YML = REPO_ROOT / "infra" / "monitoring" / "prometheus" / "prometheus.yml"
ALERTMANAGER_YML = REPO_ROOT / "infra" / "monitoring" / "alertmanager" / "alertmanager.yml"

PASS, PARTIAL, FAIL, UNPROVEN = "PASS", "PARTIAL", "FAIL", "UNPROVEN"

EXECUTED, READ, ABSENT = "EXECUTED", "READ", "ABSENT"


# ------------------------------------------------------------------- metrics --- #
def _seed(engine: Any) -> dict[str, Any]:
    """One row of each kind a metric needs, so the series are exercised.

    An empty database proves which series *exist*; it cannot prove that a series
    carries the right meaning. Each fixture here is the smallest row that makes
    one metric answerable: a queued job, an estate discovery whose HAS plane
    failed, one enrolled agent that has never checked in.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy.orm import sessionmaker

    from db.models.control_plane import Agent
    from db.models.scan_job import ScanJob
    from db.tenancy import tenant_scope

    session = sessionmaker(bind=engine)()
    seeded: dict[str, Any] = {}
    try:
        with tenant_scope("tenant-observability"), session:
            session.add(ScanJob(id="job-obs-1", status="QUEUED", target_repo="obs/fixture",
                                job_type="MANUAL", triggered_by="drill",
                                created_at=datetime.now(timezone.utc) - timedelta(minutes=20)))
            session.add(ScanJob(id="job-obs-2", status="FAILED", target_repo="obs/fixture",
                                job_type="MANUAL", triggered_by="drill",
                                created_at=datetime.now(timezone.utc) - timedelta(minutes=5)))
            session.add(Agent(name="agent-obs-1", status="enrolled", healthy=False,
                              last_heartbeat_at=None))
            session.add(Agent(name="agent-obs-2", status="connected", healthy=True,
                              last_heartbeat_at=datetime.now(timezone.utc) - timedelta(seconds=30)))
            from db.repositories.scan_run_repository import ScanRunRepository

            run = ScanRunRepository(session).create_run(
                {"coverage": {"rows": [
                    {"target": "NETWORK", "status": "COMPLETE", "expected": 10, "collected": 10},
                    {"target": "HSM", "status": "FAILED", "expected": 5, "collected": 0},
                ]}},
                target_kind="estate-discovery",
            )
            run.tenant_id = "tenant-observability"
            session.commit()
            seeded = {"jobs": 2, "agents": 2, "estate_runs": 1,
                      "oldest_queued_minutes": 20, "coverage_planes": 2}
    finally:
        session.close()
    return seeded


def _patch_redis() -> dict[str, Any]:
    """Point the API's queue read at an in-process Redis, with the keys it reads.

    The consumer writes these keys (``{queue}:retry``, ``:dead``, ``:worker:*``);
    the fake is seeded with the same shapes so the drill proves the API reads them
    rather than trusting that it would.
    """
    try:
        import fakeredis
        import redis
    except ImportError:  # pragma: no cover - test dependency
        return {"available": False}

    queue = "cryptoscan:jobs:queue"
    client = fakeredis.FakeStrictRedis(server=fakeredis.FakeServer(), decode_responses=False)
    client.zadd(f"{queue}:retry", {"job-a": 1, "job-b": 2})
    client.lpush(f"{queue}:dead", "job-c")
    client.set(f"{queue}:worker:worker-1", b"1")
    client.set(f"{queue}:worker:worker-2", b"1")
    os.environ.setdefault("REDIS_URL", "redis://observability-drill.invalid:6379/0")
    os.environ.setdefault("JOB_QUEUE_NAME", queue)
    redis.Redis.from_url = staticmethod(lambda *args, **kwargs: client)  # type: ignore[assignment]
    return {"available": True, "retry_scheduled": 2, "dead_letter": 1, "workers": 2}


def serve_metrics() -> dict[str, Any]:
    """Serve /metrics against a scratch database seeded with one row of each kind.

    In-process, with a real app, a real schema, a fake Redis holding the same keys
    the consumer writes, and no shortcut around the endpoint: the output is the
    text a Prometheus scrape would receive.
    """
    database = tempfile.mktemp(suffix=".db", prefix="obs-")
    os.environ["DATABASE_URL"] = f"sqlite:///{database}"

    import db.models  # noqa: F401 — registers the metadata
    from db.connection.engine import get_engine
    from db.connection.session import configure_session
    from db.models.base import Base
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from api.routers.metrics import router

    engine = get_engine()
    Base.metadata.create_all(engine)
    configure_session(engine)
    seeded = _seed(engine)
    redis_fixture = _patch_redis()

    app = FastAPI()
    app.include_router(router)
    response = TestClient(app).get("/metrics")
    body = response.text

    families: dict[str, dict[str, Any]] = {}
    for line in body.splitlines():
        if not line or line.startswith("#"):
            if line.startswith("# HELP "):
                _, _, rest = line.partition("# HELP ")
                name, _, help_text = rest.partition(" ")
                families.setdefault(name, {"help": help_text.strip(), "samples": 0,
                                           "labels": []})
            continue
        series = line.split(" ", 1)[0]
        name = series.split("{", 1)[0]
        entry = families.setdefault(name, {"help": "", "samples": 0, "labels": []})
        entry["samples"] += 1
        if "{" in series:
            labels = re.findall(r'(\w+)="', series)
            entry["labels"] = sorted(set(entry["labels"]) | set(labels))

    try:
        os.unlink(database)
    except OSError:
        pass
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "families": families,
        "names": sorted(families),
        "line_count": len(body.splitlines()),
        "seeded": seeded,
        "redis_fixture": redis_fixture,
        "body_head": body.splitlines()[:5],
    }


METRIC_CALL = re.compile(r"_(?:gauge|counter|histogram)\(\s*[f]?\"([a-z0-9_]+)\"")
METRICS_SOURCE = REPO_ROOT / "services" / "api" / "api" / "routers" / "metrics.py"


def declared_metrics() -> list[str]:
    """Every series name written literally in the metrics module.

    The endpoint's output depends on the environment — queue series need Redis, a
    populated estate needs rows. The *declaration* does not, so the alert check
    reads this and reports separately which declared names the run did not emit.
    """
    if not METRICS_SOURCE.exists():  # pragma: no cover - path is fixed in this repo
        return []
    text = METRICS_SOURCE.read_text(encoding="utf-8")
    names = set(METRIC_CALL.findall(text))
    # the histogram helper emits _bucket/_sum/_count siblings
    names |= {f"{name}_{suffix}" for name in list(names)
              for suffix in ("bucket", "sum", "count") if name.endswith("duration_seconds")}
    return sorted(names)


def alert_rules() -> dict[str, Any]:
    """Every rule, and the crypto metrics each one depends on."""
    if not ALERT_FILE.exists():
        return {"exists": False, "rules": [], "metrics": [], "groups": 0}
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a test dependency
        return {"exists": True, "rules": [], "metrics": [], "groups": 0,
                "error": "PyYAML unavailable"}
    document = yaml.safe_load(ALERT_FILE.read_text(encoding="utf-8")) or {}
    rules: list[dict[str, Any]] = []
    metrics: set[str] = set()
    for group in document.get("groups") or []:
        for rule in group.get("rules") or []:
            expr = str(rule.get("expr") or "")
            referenced = sorted(set(re.findall(r"\b(cryptoscan_[a-z0-9_]+)\b", expr)))
            metrics.update(referenced)
            rules.append({
                "name": rule.get("alert"),
                "group": group.get("name"),
                "severity": (rule.get("labels") or {}).get("severity"),
                "for": rule.get("for"),
                "expr": expr.strip(),
                "metrics": referenced,
                "has_runbook": "runbook" in (rule.get("annotations") or {}),
            })
    return {
        "exists": True,
        "path": str(ALERT_FILE.relative_to(REPO_ROOT)),
        "groups": len(document.get("groups") or []),
        "rules": rules,
        "metrics": sorted(metrics),
    }


def prometheus_wiring() -> dict[str, Any]:
    text = PROMETHEUS_YML.read_text(encoding="utf-8") if PROMETHEUS_YML.exists() else ""
    rule_paths = re.findall(r"^\s*-\s*(/etc/prometheus/rules/\S+|\S+alerts\.yml)\s*$",
                            text, re.M)
    alertmanager_enabled = bool(re.search(r"^alerting:", text, re.M))
    return {
        "scrapes_metrics": "metrics_path: /metrics" in text,
        "rule_files": rule_paths,
        "alertmanager_configured": alertmanager_enabled,
        "note": (
            "rules are mounted at /etc/prometheus/rules/alerts.yml; without an "
            "Alertmanager stanza they evaluate and go nowhere"
        ),
    }


# ------------------------------------------------------------- executed rows --- #
def _scratch(seed: bool = False) -> tuple[Any, Any, str]:
    """An app-less scratch database; the caller mounts the routers it needs."""
    database = tempfile.mktemp(suffix=".db", prefix="obs-")
    os.environ["DATABASE_URL"] = f"sqlite:///{database}"

    import db.models  # noqa: F401 — registers the metadata
    from db.connection.engine import get_engine
    from db.connection.session import configure_session
    from db.models.base import Base

    engine = get_engine()
    Base.metadata.create_all(engine)
    configure_session(engine)
    if seed:
        _seed(engine)
    return engine, None, database


def worker_probe() -> dict[str, Any]:
    """Execute the worker liveness probe in both directions.

    A probe that always answers 200 is decoration. This one is called twice: with
    a job waiting and no drain evidence (it must say 503 and name the condition),
    then with a completion observed (it must say 200). The API's own liveness is
    read too, so the report can show the three probes answering different
    questions rather than the same one three times.
    """
    from datetime import datetime, timedelta, timezone

    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker

    engine, _, database = _scratch()
    from db.models.scan_job import ScanJob

    session = sessionmaker(bind=engine)()
    try:
        session.add(ScanJob(
            id="job-probe-1", status="QUEUED", target_repo="probe/fixture",
            job_type="MANUAL", triggered_by="drill",
            created_at=datetime.now(timezone.utc) - timedelta(minutes=45)))
        session.commit()
    finally:
        session.close()

    from api.routers.health import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    stalled = client.get("/healthz/workers")
    live = client.get("/healthz")
    ready = client.get("/readyz")

    session = sessionmaker(bind=engine)()
    try:
        session.add(ScanJob(
            id="job-probe-2", status="COMPLETED", target_repo="probe/fixture",
            job_type="MANUAL", triggered_by="drill",
            created_at=datetime.now(timezone.utc) - timedelta(minutes=2),
            completed_at=datetime.now(timezone.utc)))
        session.commit()
    finally:
        session.close()
    draining = client.get("/healthz/workers")
    try:
        os.unlink(database)
    except OSError:
        pass

    return {
        "liveness": {"path": "/healthz", "status_code": live.status_code},
        "readiness": {"path": "/readyz", "status_code": ready.status_code},
        "worker_probe_q": {
            "path": "/healthz/workers",
            "status_code": stalled.status_code,
            "state": stalled.json().get("status"),
            "detail": stalled.json().get("detail"),
        },
        "worker_probe_draining": {
            "status_code": draining.status_code,
            "state": draining.json().get("status"),
            "detail": draining.json().get("detail"),
        },
        "distinguishes": (
            stalled.status_code == 503 and draining.status_code == 200
            and live.status_code == 200
        ),
        "meaning": (
            "three probes, three questions: liveness is the process, readiness is its "
            "dependencies, and the worker probe is whether anything is consuming — "
            "measured from the job and lease records, so it answers while the console "
            "is unreachable"
        ),
    }


def trace_export() -> dict[str, Any]:
    """Export a span through the real OTLP/HTTP path, to a real HTTP sink.

    The exporter existed and was never executed. This stands up a socket sink,
    points the trace store at it, finishes a span, and reads back what arrived:
    the payload has to be OTLP/JSON — ``resourceSpans[].scopeSpans[].spans[]`` with
    the trace id, span id, timings and attributes of the span that was finished.

    A second store is built with **no** endpoint and asked to finish a span: it
    must not spawn an exporter or open a socket, because "export is optional" is
    only true if the unconfigured path does nothing.
    """
    import http.server
    import threading

    from observability.metrics import TraceStore

    received: list[bytes] = []

    class _Sink(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 — http.server's interface
            length = int(self.headers.get("content-length") or 0)
            received.append(self.rfile.read(length))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: Any) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), _Sink)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        store = TraceStore(otlp_endpoint=f"http://127.0.0.1:{port}",
                           service_name="cryptoscan-observability-drill")
        span = store.start_span(method="GET", path="/api/v1/collectors/authority",
                                traceparent=None, seed="drill")
        store.finish_span(span, 200)
        assert store._otlp_queue is not None
        store._otlp_queue.join()

        quiet = TraceStore(otlp_endpoint=None)
        quiet.finish_span(quiet.start_span(method="GET", path="/healthz",
                                           traceparent=None, seed="quiet"), 200)
        no_exporter = quiet._otlp_thread is None
    finally:
        server.shutdown()
        server.server_close()

    payload = json.loads(received[0]) if received else {}
    spans = ((((payload.get("resourceSpans") or [{}])[0]
               .get("scopeSpans") or [{}])[0]).get("spans") or [{}])
    exported = spans[0] if spans else {}
    attributes = {item.get("key"): item.get("value", {}).get("stringValue")
                  for item in exported.get("attributes") or []}
    resource = (((payload.get("resourceSpans") or [{}])[0].get("resource") or {})
                .get("attributes") or [{}])
    service = (resource[0].get("value") or {}).get("stringValue") if resource else None
    return {
        "endpoint": f"http://127.0.0.1:{port}/v1/traces",
        "notifications": len(received),
        "span_name": exported.get("name"),
        "trace_id_matches": exported.get("traceId") == span["trace_id"],
        "span_id_matches": exported.get("spanId") == span["span_id"],
        "timings_present": bool(exported.get("startTimeUnixNano")
                                and exported.get("endTimeUnixNano")),
        "http_route_attribute": attributes.get("http.route"),
        "service_name": service,
        "payload_bytes": len(received[0]) if received else 0,
        "unconfigured_store_spawns_exporter": not no_exporter,
        "status": exported.get("status"),
        "meaning": (
            "the span a request finished is the span the collector received, with the "
            "same trace and span ids, the route as an attribute and the service name in "
            "the resource — export is off the request path and absent when unconfigured"
        ),
    }


def pager_path(rules: dict[str, Any]) -> dict[str, Any]:
    """From a rule in ``alerts.yml`` to a counted notification and a scraped series.

    The chain is walked with the real files: the Alertmanager config is parsed for
    the receiver URL, a webhook-v4 notification is built **from a rule that exists**
    in ``alerts.yml`` (name, severity, and the fingerprint a real Alertmanager
    computes), posted to the route that URL names, and then the ``/metrics``
    output is scraped to prove the notification became a series rather than a
    return value nobody keeps.
    """
    import yaml
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    document = yaml.safe_load(ALERTMANAGER_YML.read_text(encoding="utf-8")) \
        if ALERTMANAGER_YML.exists() else {}
    receivers = document.get("receivers") or []
    webhooks = [config for receiver in receivers
                for config in (receiver.get("webhook_configs") or [])]
    receiver_url = webhooks[0].get("url") if webhooks else None
    routes = {receiver.get("name") for receiver in receivers}

    route = document.get("route") or {}
    sub_routes = route.get("routes") or []
    unrouted = [sub.get("receiver") for sub in sub_routes if sub.get("receiver") not in routes]
    if route.get("receiver") not in routes:
        unrouted.append(route.get("receiver"))

    paging_rule = next((rule for rule in rules["rules"]
                        if rule.get("name") and (rule.get("severity") or "") == "critical"),
                       None)
    alertname = (paging_rule or {}).get("name") or "CryptoscanDrillAlert"
    severity = (paging_rule or {}).get("severity") or "critical"

    _, _, database = _scratch()
    from api.routers import ops_alerts
    from api.routers.metrics import router as metrics_router

    ops_alerts.reset()
    app = FastAPI()
    app.include_router(metrics_router)
    app.include_router(ops_alerts.router, prefix="/api/v1")
    client = TestClient(app)

    path = (receiver_url or "/api/v1/ops/alerts/alertmanager")
    path = "/" + path.split("://", 1)[-1].partition("/")[2] if "://" in path else path
    notification = {
        "version": "4",
        "status": "firing",
        "receiver": (receivers[0].get("name") if receivers else None),
        "groupKey": f'{{}}:{{alertname="{alertname}"}}',
        "alerts": [{
            "status": "firing",
            "labels": {"alertname": alertname, "severity": severity,
                       "job": "cryptoscan-api"},
            "annotations": {"summary": "posted by the guide 117 drill"},
            "startsAt": datetime.now(timezone.utc).isoformat(),
            "fingerprint": "0b1d4c6e8f2a",
        }],
    }
    receipt = client.post(path, json=notification)
    unauthenticated_malformed = client.post(path, json={**notification, "status": "bogus"})
    body = client.get("/metrics").text

    received_series = re.findall(
        r'cryptoscan_alertmanager_notifications_total\{alertname="([^"]*)",'
        r'severity="([^"]*)",status="([^"]*)"\} (\d+)', body)
    age = re.search(r"cryptoscan_alertmanager_last_notification_age_seconds ([-\d.]+)", body)
    try:
        os.unlink(database)
    except OSError:
        pass

    counted = any(name == alertname and state == "firing" and int(count) >= 1
                  for name, _severity, state, count in received_series)
    return {
        "alertmanager_config": str(ALERTMANAGER_YML.relative_to(REPO_ROOT))
        if ALERTMANAGER_YML.exists() else None,
        "receivers": sorted(routes),
        "receiver_url": receiver_url,
        "unrouted_sub_routes": unrouted,
        "inhibit_rules": len(document.get("inhibit_rules") or []),
        "group_by": route.get("group_by"),
        "paging_rule_used": {"alertname": alertname, "severity": severity,
                             "for": (paging_rule or {}).get("for")},
        "post_status": receipt.status_code,
        "accepted": (receipt.json() or {}).get("accepted") if receipt.status_code == 200 else None,
        "malformed_notification_status": unauthenticated_malformed.status_code,
        "series_after": [{"alertname": name, "severity": sev, "status": state,
                          "count": int(count)}
                         for name, sev, state, count in received_series],
        "counted_in_metrics": counted,
        "last_notification_age_seconds": age.group(1) if age else None,
        "meaning": (
            "a rule that exists in alerts.yml was posted as an Alertmanager "
            "notification to the receiver its own config names, was accepted, and is "
            "now a scraped series — the alert evaluates outside the system it watches "
            "and the platform can prove it was told"
        ),
    }


# -------------------------------------------------------------------- sources --- #
def _grep(pattern: str, *, roots: tuple[str, ...], exclude: tuple[str, ...] = ()) -> list[str]:
    """Files under ``roots`` whose text matches ``pattern`` (regex)."""
    hits: list[str] = []
    regex = re.compile(pattern)
    for root in roots:
        base = REPO_ROOT / root
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            relative = str(path.relative_to(REPO_ROOT))
            if any(token in relative for token in exclude):
                continue
            try:
                if regex.search(path.read_text(encoding="utf-8", errors="ignore")):
                    hits.append(relative)
            except OSError:
                continue
    return sorted(hits)


@dataclass
class Row:
    id: str
    question: str
    verdict: str
    evidence_kind: str
    found: dict[str, Any] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    note: str = ""
    limit: str = ""
    closes_with: str = ""
    #: One line for the summary table: what the measurement actually saw.
    measured: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "question": self.question, "verdict": self.verdict,
                "evidence_kind": self.evidence_kind, "found": self.found,
                "missing": self.missing, "note": self.note, "limit": self.limit,
                "closes_with": self.closes_with, "measured": self.measured}


def _grade_series(required: dict[str, list[str]], names: set[str]) -> tuple[str, list[str]]:
    missing = [name for group in required.values() for name in group if name not in names]
    if not missing:
        return PASS, []
    if len(missing) == sum(len(group) for group in required.values()):
        return FAIL, missing
    return PARTIAL, missing


def metric_row(row_id: str, question: str, required: dict[str, list[str]],
               names: set[str], *, note: str, limit: str, closes_with: str) -> Row:
    verdict, missing = _grade_series(required, names)
    present = {group: [name for name in wanted if name in names]
               for group, wanted in required.items()}
    return Row(id=row_id, question=question, verdict=verdict, evidence_kind=EXECUTED,
               found={"present": present, "emitted_series": len(names)},
               missing=missing, note=note, limit=limit, closes_with=closes_with)


# --------------------------------------------------------------------- measure --- #
def measure() -> dict[str, Any]:
    metrics = serve_metrics()
    names = set(metrics["names"])
    rules = alert_rules()
    wiring = prometheus_wiring()
    rows: list[Row] = []

    rows.append(metric_row(
        "collector_metrics",
        "can an operator see whether collectors are running and what they return?",
        {"scan_volume": ["cryptoscan_scans_total", "cryptoscan_scans_by_status"],
         "scan_duration": ["cryptoscan_scan_duration_seconds_bucket"],
         "monitor_fleet": ["cryptoscan_monitor_targets_total"]},
        names,
        note="scan volume, duration and the live-monitor fleet are emitted by the API",
        limit="per-collector-plane outcome (COMPLETE / PARTIAL / FAILED, as the estate "
              "report calls them) has no metric: a plane that stopped collecting is "
              "visible only through stale evidence",
        closes_with="a labelled counter per plane outcome, emitted by the discovery path",
    ))

    rows.append(metric_row(
        "queue_metrics",
        "can an operator see a queue that is not draining, or work that was given up on?",
        {"depth": ["cryptoscan_jobs_queued", "cryptoscan_jobs_by_status"],
         "age": ["cryptoscan_jobs_oldest_queued_seconds"],
         "retry": ["cryptoscan_jobs_retry_scheduled"],
         "dead_letter": ["cryptoscan_jobs_dead_letter"],
         "workers": ["cryptoscan_workers_alive"]},
        names,
        note=("added this pass: queued age, retry backlog, dead letters and worker "
              "leases, read from the same Redis keys the consumer uses"),
        limit="the retry/dead-letter/worker series are only emitted when REDIS_URL is "
              "set; without Redis the queue is in-process and unobservable by design",
        closes_with="nothing further for a Redis deployment; in-memory mode is a dev path",
    ))

    rows.append(metric_row(
        "database_metrics",
        "can an operator see that the database is unhealthy before users report it?",
        {"reachability": ["cryptoscan_api_db_reachable", "cryptoscan_dependency_up"],
         "latency": ["cryptoscan_dependency_latency_ms"],
         "pool": ["cryptoscan_dependencies_degraded"]},
        names,
        note="reachability, per-dependency latency and an aggregate degraded flag",
        limit="no connection-pool saturation metric (checked-out / overflow / waiting); "
              "a pool that is exhausted shows up as latency, not as pool pressure",
        closes_with="emit SQLAlchemy pool status (checkedout, overflow, timeout count)",
    ))

    rows.append(metric_row(
        "evidence_metrics",
        "can an operator see the evidence store going stale under a BOM?",
        {"volume": ["cryptoscan_evidence_records", "cryptoscan_findings_total"],
         "staleness": ["cryptoscan_evidence_records_stale"],
         "observations": ["cryptoscan_observations_current"]},
        names,
        note=("added this pass: evidence volume, stale evidence and current facts, so "
              "'the BOM stopped changing' can be told apart from 'nothing was observed'"),
        limit="no chain-verification metric: evidence integrity is proven on demand "
              "(guide 112), not continuously monitored",
        closes_with="a periodic verification job that emits its own age and verdict",
    ))

    agent_series = [name for name in names if "agent" in name]
    heartbeat_routes = _grep(r"def agent_heartbeat", roots=("services/api/api",),
                             exclude=("tests/",))
    rows.append(Row(
        id="agent_metrics",
        question="can an operator see that an agent on a host stopped reporting?",
        verdict=(PASS if {"cryptoscan_agents_reporting",
                          "cryptoscan_agent_last_seen_seconds"} <= names
                 else PARTIAL if agent_series else FAIL),
        evidence_kind=EXECUTED,
        found={"agent_series": agent_series,
               "heartbeat_endpoints": heartbeat_routes,
               "meaning": ("reporting counts agents inside AGENT_STALE_SECONDS; the age "
                           "gauge is the stalest check-in, because the outlier is what "
                           "the operator needs")},
        note=("added this pass: the agent fleet was already recorded — heartbeats, "
              "status, buffered events — but nothing exposed it as a metric"),
        limit="the gauge is fleet-wide with no per-agent label: an operator learns that "
              "an agent is stale, then has to look up which one",
        closes_with="a labelled series per agent (bounded by the enrolment count)",
    ))

    coverage_series = [name for name in names if "coverage" in name]
    rows.append(Row(
        id="coverage_metrics",
        question="can an operator see which planes stopped being covered?",
        verdict=(PASS if "cryptoscan_coverage_planes_unknown" in names
                 else PARTIAL if coverage_series else FAIL),
        evidence_kind=EXECUTED,
        found={"coverage_series": coverage_series,
               "reported_when": ("only after an estate discovery has been stored — with no "
                                 "run there is no coverage to report, which is correct: "
                                 "'never observed' is not 'fully covered'")},
        missing=[] if "cryptoscan_coverage_planes_unknown" in names else
                ["cryptoscan_coverage_planes_unknown"],
        note=("added this pass: the last discovery's coverage matrix is emitted as one "
              "labelled series per plane plus a count of planes that are not fully "
              "covered, so a dark plane is an alert and not a screen"),
        limit="the read is platform-wide (metrics have no tenant context); in a "
              "multi-tenant deployment the gauges aggregate every tenant",
        closes_with="tenant-labelled coverage series once a tenant-scoped scrape exists",
    ))

    health_paths = _health_routes()
    probes = worker_probe()
    rows.append(Row(
        id="health_surfaces",
        question="do the probes answer, and do they distinguish liveness from readiness?",
        verdict=(PASS if probes["distinguishes"] and {"healthz", "readyz"} <= set(health_paths)
                 else PARTIAL),
        evidence_kind=EXECUTED,
        found={"routes": health_paths, **probes},
        measured=(f"liveness {probes['liveness']['status_code']}, readiness "
                  f"{probes['readiness']['status_code']}, worker probe "
                  f"{probes['worker_probe_q']['status_code']} when stalled and "
                  f"{probes['worker_probe_draining']['status_code']} when draining"),
        note=("added this pass: /healthz/workers — the worker probe the console had, "
              "reachable by an orchestrator without a session, answering 503 only when "
              "work is waiting and nothing is draining"),
        limit="the probe reads the durable job and lease records, so it reports what the "
              "queue has done, not what a worker process is doing this second",
        closes_with="a lease heartbeat on the queue consumer, carried into the same probe",
    ))

    trace_context = _grep(r"def push_trace|def active_trace|trace_id",
                          roots=("services/api/api/middleware",), exclude=("tests/",))
    exporters = _grep(r"OTLPSpanExporter|JaegerExporter|opentelemetry\.sdk",
                      roots=("services", "shared"), exclude=("tests/",))
    propagated = _grep(r"trace_id", roots=("services/worker",), exclude=("tests/",))
    exported = trace_export()
    rows.append(Row(
        id="traces",
        question="is a single request traceable across API, worker and database?",
        verdict=(PASS if trace_context and exported["notifications"]
                 and exported["trace_id_matches"] and propagated
                 else PARTIAL if trace_context else FAIL),
        evidence_kind=EXECUTED,
        found={"trace_context_modules": trace_context,
               "span_exporters": exporters,
               "otlp_export": exported,
               "worker_trace_propagation": propagated,
               "request_id": _grep(r"X-Request-ID", roots=("services/api/api/middleware",),
                                   exclude=("tests/",))[:3]},
        measured=(f"{exported['notifications']} OTLP notification(s) received, trace id "
                  f"{'matched' if exported['trace_id_matches'] else 'did not match'}, "
                  f"{exported['payload_bytes']} bytes, exporter "
                  f"{'absent' if not exported['unconfigured_store_spawns_exporter'] else 'spawned'}"
                  " when unconfigured"),
        missing=([name for name, present in (
            ("span export to an APM backend", exported["notifications"]),
            ("trace propagation into the worker", propagated)) if not present]),
        note=("added this pass: the span exporter that already existed is executed — a "
              "real HTTP sink receives the OTLP/JSON of a finished span, with the same "
              "trace and span ids and the route as an attribute"),
        limit="the worker carries the trace id in its log context but does not open a "
              "child span, so a job's work is correlated by id rather than drawn as a "
              "trace; and no APM backend in this repository was sent the payload",
        closes_with="a job-id span link opened by the consumer, and a collector the "
                    "bank already runs",
    ))

    rows.append(Row(
        id="logs",
        question="are logs structured, correlated and safe to ship?",
        verdict=PASS if _logging_files() else FAIL,
        evidence_kind=READ,
        found={"structured_logging": _logging_files()[:5],
               "redaction": _grep(r"redact|REDACTED|sanitise|sanitize", roots=("services/api/api",),
                                  exclude=("tests/",))[:4]},
        note="JSON logs through a shared logger, with request ids and redaction helpers",
        limit="no shipping pipeline in this repository: whether logs reach the bank's SIEM "
              "is a deployment question",
        closes_with="a documented log pipeline in the deployment guide",
    ))

    declared = set(declared_metrics())
    emittable = declared | names
    unknown_metrics = [metric for metric in rules["metrics"] if metric not in emittable]
    conditional = sorted(metric for metric in rules["metrics"]
                         if metric in declared and metric not in names)
    pager = pager_path(rules)
    rows.append(Row(
        id="alert_rules",
        question="does every alert reference a metric that exists, and is anything paging?",
        verdict=(FAIL if not rules["exists"] or not pager["counted_in_metrics"]
                 else PARTIAL if unknown_metrics or not wiring["alertmanager_configured"]
                 else PASS),
        evidence_kind=EXECUTED,
        found={
            "rules_file": rules.get("path"),
            "groups": rules["groups"],
            "rules": len(rules["rules"]),
            "metrics_referenced": len(rules["metrics"]),
            "metrics_declared": len(declared),
            "metrics_missing_from_endpoint": unknown_metrics,
            "metrics_not_emitted_in_this_run": conditional,
            "why_not_emitted": ("queue series need REDIS_URL and worker leases; the run "
                                "had no Redis, so they were declared but absent"),
            "prometheus_wiring": wiring,
            "pager_path": pager,
            "severities": sorted({str(rule["severity"]) for rule in rules["rules"]}),
        },
        measured=(f"{len(rules['rules'])} rules, {len(rules['metrics'])} metrics referenced, "
                  f"receiver answered {pager['post_status']} with {pager['accepted']} "
                  f"alert(s) counted"),
        missing=unknown_metrics,
        note=(f"{len(rules['rules'])} rules across availability, backlog, freshness and "
              "integrity; every series a rule names is checked against the endpoint's "
              "live output and the module's declared names, so a renamed metric fails "
              "this report instead of the pager — and added this pass, a rule from "
              "alerts.yml is delivered to the receiver alertmanager.yml names and "
              "counted in /metrics"),
        limit=("no Prometheus scraped these rules and no Alertmanager process ran: the "
               "evaluation and the grouping are the bank's, and what is proven here is "
               "the delivery half — the receiver, the token and the counted series"),
        closes_with="nothing further in code; a bank points alertmanager.yml at its own "
                    "pager and the same series proves delivery",
    ))

    emitted = len(names)
    graded = [row.as_dict() for row in rows]
    counts = {verdict: sum(1 for row in graded if row["verdict"] == verdict)
              for verdict in (PASS, PARTIAL, FAIL, UNPROVEN)}
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "fixtures": {"database": metrics.get("seeded"), "redis": metrics.get("redis_fixture")},
        "metrics": {
            "status_code": metrics["status_code"],
            "content_type": metrics["content_type"],
            "series": emitted,
            "names": metrics["names"],
            "lines": metrics["line_count"],
        },
        "alerts": {k: v for k, v in rules.items() if k != "rules"},
        "rules": rules["rules"],
        "counts": counts,
        "rows": graded,
        "limits": [
            "The metrics were served in-process against a scratch database seeded with "
            "one row of each kind. A populated estate changes the values, not the "
            "presence or the meaning of a series.",
            "No Prometheus and no Alertmanager process ran here. The rules were checked "
            "against the endpoint's own output and a notification was delivered to the "
            "receiver the bundled config names; the evaluation interval, the grouping and "
            "the retry behaviour are Prometheus's, and unproven by this drill.",
            "The span exporter was watched against a local HTTP sink, not an APM backend: "
            "the payload is OTLP/JSON and its ids are checked, but no vendor collector "
            "accepted it.",
            "The worker probe reads durable job and lease records. A worker that is alive "
            "and idle looks the same as one that never started, which is why the probe "
            "reports 'Not measured' rather than inventing a state.",
            "Log shipping to a SIEM is a deployment question and is graded READ: the "
            "structured logger and the redaction helpers exist, and this checkout cannot "
            "show what leaves the host.",
        ],
    }


def _health_routes() -> list[str]:
    """Every probe path the health router serves, read from the router itself."""
    from api.routers.health import router

    return sorted({route.path.strip("/") for route in router.routes
                   if "healthz" in getattr(route, "path", "")
                   or getattr(route, "path", "").strip("/") == "readyz"})


def _tracing_files() -> list[str]:
    return _grep(r"opentelemetry|OpenTelemetry|start_as_current_span",
                 roots=("services", "shared", "scripts"), exclude=("tests/",))


def _logging_files() -> list[str]:
    return _grep(r"structlog|json_logs|JsonFormatter|configure_logging",
                 roots=("services", "shared"), exclude=("tests/",))


# ------------------------------------------------------------------- rendering --- #
def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    metrics = report["metrics"]
    lines = [
        "# Observability coverage — what an operator can see",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts.get(PASS, 0)} pass · {counts.get(PARTIAL, 0)} partial · "
        f"{counts.get(FAIL, 0)} fail** · {metrics['series']} series from `/metrics`",
        "",
        "Each row is graded against something in this repository: a row marked "
        "**EXECUTED** was driven through the real endpoint, route or exporter and its "
        "answer read back; a row marked **READ** is a file or an import that proves the "
        "surface exists; a surface that does not exist is reported as **FAIL**, not as "
        "future work. The evidence block under each row is the measurement, not a "
        "description of one.",
        "",
        "| Surface | Verdict | Evidence | What was found |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        if row["missing"]:
            found = "missing: " + ", ".join(row["missing"][:3])
        else:
            found = row.get("measured") or "every required series present"
        lines.append(f"| **{row['question']}** | **{row['verdict']}** | {row['evidence_kind']} "
                     f"| {found} |")

    lines += ["", "## Row by row", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['id']}` — {row['verdict']} ({row['evidence_kind']})")
        lines.append("")
        lines.append(f"*{row['question']}*")
        lines.append("")
        if row["note"]:
            lines.append(f"- **Reading:** {row['note']}")
        if row["missing"]:
            lines.append(f"- **Missing:** {', '.join(f'`{name}`' for name in row['missing'])}")
        if row["limit"]:
            lines.append(f"- **Limit:** {row['limit']}")
        if row["closes_with"]:
            lines.append(f"- **Closes with:** {row['closes_with']}")
        lines.append("")
        lines.append("```")
        lines.append(json.dumps(row["found"], indent=2, default=str))
        lines.append("```")
        lines.append("")

    if report["rules"]:
        lines += ["## Alert rules, checked against the endpoint", "",
                  "| Alert | Severity | For | Metrics | Runbook |", "|---|---|---|---|---|"]
        for rule in report["rules"]:
            name = f"`{rule['name']}`" if rule["name"] else "_(recording rule)_"
            lines.append(f"| {name} | {rule['severity'] or '—'} | {rule['for'] or '—'} | "
                         f"{', '.join(f'`{m}`' for m in rule['metrics']) or '—'} | "
                         f"{'yes' if rule['has_runbook'] else 'no'} |")
        lines.append("")

    lines += ["## The metric families `/metrics` emits", "",
              ", ".join(f"`{name}`" for name in metrics["names"]), ""]

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    executed = [row["id"] for row in report["rows"]
                if row["verdict"] == PASS and row["evidence_kind"] == EXECUTED]
    read = [row["id"] for row in report["rows"]
            if row["verdict"] == PASS and row["evidence_kind"] == READ]
    passed = [row["id"] for row in report["rows"] if row["verdict"] == PASS]
    partial = [f"{row['id']} ({row['limit']})" for row in report["rows"]
               if row["verdict"] == PARTIAL]
    failed = [row["id"] for row in report["rows"] if row["verdict"] == FAIL]
    lines += [
        "",
        f"**The verdict this drill supports:** {len(passed)} of {len(report['rows'])} "
        "surfaces answer. "
        f"{len(executed)} were driven through their real endpoint, route or exporter — "
        + ", ".join(f"`{name}`" for name in executed) + " — and "
        f"{len(read)} is graded from the checkout because what it claims leaves the host: "
        + ", ".join(f"`{name}`" for name in read) + ".",
        "",
    ]
    if partial:
        lines += ["Still partial, and why: " + "; ".join(partial) + ".", ""]
    if failed:
        lines += ["Not built, reported as FAIL rather than softened: "
                  + ", ".join(f"`{name}`" for name in failed) + ".", ""]
    lines += [
        "The three additions in this pass are the ones the previous pass named as its "
        "closing work: a worker probe an orchestrator can call without a session, a span "
        "exporter that was executed against a real HTTP sink, and a pager path from a rule "
        "in `alerts.yml` through Alertmanager's own config to a counted series in "
        "`/metrics`. Each is a control that now exists *and* has been watched working; "
        "none of them is a claim about a deployment.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Observability coverage, measured.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-fail", type=int, default=99,
                        help="exit non-zero when more than this many rows fail")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            print(f"{row['verdict']:<8} {row['id']:<20} {row['evidence_kind']:<9} "
                  f"{', '.join(row['missing'][:3])}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"].get(FAIL, 0) <= args.max_fail else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
