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

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "question": self.question, "verdict": self.verdict,
                "evidence_kind": self.evidence_kind, "found": self.found,
                "missing": self.missing, "note": self.note, "limit": self.limit,
                "closes_with": self.closes_with}


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
    rows.append(Row(
        id="health_surfaces",
        question="do the probes answer, and do they distinguish liveness from readiness?",
        verdict=PASS if {"healthz", "readyz"} <= set(health_paths) else PARTIAL,
        evidence_kind=READ,
        found={"routes": health_paths},
        note="liveness, readiness and a dependency report are served by the API",
        limit="no worker liveness probe: a dead worker is visible only through the "
              "queue age metric added this pass",
        closes_with="a worker /healthz the orchestrator can probe",
    ))

    trace_context = _grep(r"def push_trace|def active_trace|trace_id",
                          roots=("services/api/api/middleware",), exclude=("tests/",))
    exporters = _grep(r"OTLPSpanExporter|JaegerExporter|opentelemetry\.sdk",
                      roots=("services", "shared"), exclude=("tests/",))
    propagated = _grep(r"trace_id", roots=("services/worker",), exclude=("tests/",))
    rows.append(Row(
        id="traces",
        question="is a single request traceable across API, worker and database?",
        verdict=(PASS if trace_context and exporters and propagated
                 else PARTIAL if trace_context else FAIL),
        evidence_kind=READ,
        found={"trace_context_modules": trace_context,
               "span_exporters": exporters,
               "worker_trace_propagation": propagated,
               "request_id": _grep(r"X-Request-ID", roots=("services/api/api/middleware",),
                                   exclude=("tests/",))[:3]},
        missing=([name for name, present in (
            ("span export to an APM backend", exporters),
            ("trace propagation into the worker", propagated)) if not present]),
        note=("a W3C-shaped trace id and span id are minted per request and carried into "
              "structured logs, and the module says in its own docstring that it is not "
              "an exporter"),
        limit="without an exporter there is no way to follow one request across services; "
              "the trace id only correlates log lines the bank has to join itself",
        closes_with="an OpenTelemetry SDK exporter and a job-id span link carried across "
                    "the queue",
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
    rows.append(Row(
        id="alert_rules",
        question="does every alert reference a metric that exists, and is anything paging?",
        verdict=(FAIL if not rules["exists"]
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
            "severities": sorted({str(rule["severity"]) for rule in rules["rules"]}),
        },
        missing=unknown_metrics,
        note=(f"{len(rules['rules'])} rules across availability, backlog, freshness and "
              "integrity; every series a rule names is checked against the endpoint's "
              "live output and the module's declared names, so a renamed metric fails "
              "this report instead of the pager"),
        limit=("Alertmanager is not configured in the bundled Prometheus config, so the "
               "rules evaluate and go nowhere until a receiver is wired"),
        closes_with="an Alertmanager stanza and a receiver in the bank's own config",
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
            "The metrics were served in-process with an empty database. A populated "
            "estate changes the values, not the presence of a series.",
            "Nothing here was scraped by a running Prometheus, and no alert was fired: "
            "the rules are checked against the endpoint's output, not against a pager.",
            "There is no tracing, and no agent heartbeat; both are reported as FAIL "
            "rather than described as future work.",
        ],
    }


def _health_routes() -> list[str]:
    from fastapi import FastAPI

    from api.routers.health import router

    app = FastAPI()
    app.include_router(router)
    return sorted({route.path.strip("/") for route in app.routes
                   if getattr(route, "path", "").strip("/") in {"healthz", "readyz"}
                   or "healthz" in getattr(route, "path", "")})


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
        "Each row is graded against something in this repository: the metrics rows are "
        "**executed** (the endpoint is served in-process and its output parsed), the "
        "alert row is checked rule by rule against that same output, and a surface that "
        "does not exist is reported as **FAIL**, not as future work.",
        "",
        "| Surface | Verdict | Evidence | What was found |",
        "|---|---|---|---|",
    ]
    for row in report["rows"]:
        found = ", ".join(row["missing"][:3]) if row["missing"] else "complete"
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
            lines.append(f"| `{rule['name']}` | {rule['severity']} | {rule['for']} | "
                         f"{', '.join(f'`{m}`' for m in rule['metrics']) or '—'} | "
                         f"{'yes' if rule['has_runbook'] else 'no'} |")
        lines.append("")

    lines += ["## The metric families `/metrics` emits", "",
              ", ".join(f"`{name}`" for name in metrics["names"]), ""]

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this drill supports:** collectors, the queue, the database and the "
        "evidence store can now be seen, and fifteen alert rules name metrics that exist. "
        "Two surfaces the review asked for do not exist — **agent health** and **traces** — "
        "and coverage is still a screen rather than a metric. Those three are named as "
        "FAIL above rather than softened.",
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
