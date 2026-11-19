"""Cryptava live performance → ZELNX Performance Intelligence.

Every Cryptava agent sends a signed performance sample every minute (see
``services/cryptava/cryptava/performance.py``). This module is the server half:

* :func:`verify_sample` — the sample must be signed by the key the agent registered
  at activation. Anything else is refused: an unsigned or foreign sample is not
  telemetry from that server.
* :func:`metrics_from_sample` — each figure becomes one ``PerformanceMetric`` row.
  The unit and type come from the performance taxonomy, never from the agent; a
  figure the agent could not read is stored ``missing`` with no value (never a zero).
  Every row is linked to the host's node in the live estate (``<agent>::host``) and
  carries the signature fingerprint as its evidence reference.
* :func:`live_systems` — the "Live systems" projection: per server, the newest figures,
  a short trend, and whether the agent is reporting right now.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.cryptava-performance/1"
SOURCE_PREFIX = "cryptava:"
EVIDENCE_PREFIX = "cryptava-signed:"
MAX_METRICS = 64
MAX_CLOCK_AHEAD = timedelta(seconds=120)
MAX_AGE = timedelta(hours=24)
TREND_METRICS = ("cpu.utilization_pct", "ram.utilization_pct", "network.throughput_mbps",
                 "crypto.tls_handshake_ms")
TREND_POINTS = 30
#: labels the server sets itself — a sample cannot overwrite them
RESERVED_LABELS = ("agent", "host", "system", "ip")


class SampleRefused(ValueError):
    """The sample as a whole is not accepted (bad shape, signature, or timestamp)."""

    def __init__(self, error: str, message: str) -> None:
        super().__init__(message)
        self.error = error
        self.message = message


def default_tenant() -> str:
    return (os.environ.get("CRYPTAVA_PERFORMANCE_TENANT") or "default").strip() or "default"


def host_asset_id(agent_name: str) -> str:
    """The host's node in the live estate: contributions are namespaced ``<agent>::<ref>``
    and every Cryptava observation names its host ``host``."""
    from api.estate_contributions import SEPARATOR

    ref = f"{agent_name}{SEPARATOR}host"
    if len(ref) <= 120:   # the performance tables hold 120 characters
        return ref
    return f"{agent_name[:100]}~{hashlib.sha256(agent_name.encode()).hexdigest()[:8]}{SEPARATOR}host"


def source_id(agent_name: str) -> str:
    return f"{SOURCE_PREFIX}{agent_name}"[:120]


def canonical(document: Mapping[str, Any]) -> bytes:
    body = {k: v for k, v in document.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def verify_sample(document: Mapping[str, Any], registered_public_key: str | None) -> dict[str, Any]:
    """VALID only when the agent's registered key signed exactly these bytes."""
    from shared_models import release_signature

    if not registered_public_key:
        raise SampleRefused("agent_not_activated",
                            "this agent has no registered signing key — activate it first")
    if not isinstance(document.get("signature"), Mapping):
        raise SampleRefused("unsigned_sample",
                            "performance samples must be signed with the agent's key")
    verdict = release_signature.verify_document(
        document, trusted_key=release_signature.load_public_key(registered_public_key))
    if verdict.get("status") != release_signature.VALID:
        raise SampleRefused("signature_not_valid",
                            f"signature {verdict.get('status')}: {verdict.get('reason') or 'not valid'}")
    return verdict


def _observed_at(raw: Any, now: datetime) -> datetime:
    try:
        when = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError as exc:
        raise SampleRefused("observed_at_invalid", "observed_at must be an ISO-8601 timestamp") from exc
    if when.tzinfo is None:
        raise SampleRefused("observed_at_invalid", "observed_at must carry its timezone")
    if when > now + MAX_CLOCK_AHEAD:
        raise SampleRefused("clock_ahead",
                            f"observed_at {when.isoformat()} is ahead of the console clock — fix the agent's NTP")
    if when < now - MAX_AGE:
        raise SampleRefused("sample_too_old", "samples older than 24 hours are not accepted")
    return min(when, now)  # a few seconds of skew is tolerated, never stored as the future


def _clean_labels(raw: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(raw, Mapping):
        for key, value in list(raw.items())[:10]:
            key = str(key).strip().lower()
            if key in RESERVED_LABELS or not key:
                continue
            out[key[:32]] = str(value)[:120]
    return out


def metrics_from_sample(document: Mapping[str, Any], *, agent_name: str, tenant_id: str,
                        evidence_id: str, now: datetime | None = None) -> tuple[list[Any], list[dict[str, str]]]:
    """``(PerformanceMetric rows, refused figures)`` for one verified sample."""
    from shared_models.performance_metrics import PerformanceMetric, QualityStatus
    from shared_models.performance_taxonomy import definition_for

    now = now or datetime.now(timezone.utc)
    if document.get("schema") != SCHEMA:
        raise SampleRefused("schema_unknown", f"expected schema {SCHEMA}")
    observed_at = _observed_at(document.get("observed_at"), now)
    figures = document.get("metrics")
    if not isinstance(figures, list) or not figures:
        raise SampleRefused("no_metrics", "the sample carries no metrics")
    if len(figures) > MAX_METRICS:
        raise SampleRefused("too_many_metrics", f"at most {MAX_METRICS} metrics per sample")
    interval = document.get("interval_seconds")
    interval = float(interval) if isinstance(interval, (int, float)) and 0 < interval <= 86400 else None
    asset_id = host_asset_id(agent_name)
    fixed = {"agent": agent_name}
    for key, value in (("host", document.get("host")), ("system", document.get("system")),
                       ("ip", document.get("primary_ip"))):
        if value:
            fixed[key] = str(value)[:120]

    rows: list[Any] = []
    refused: list[dict[str, str]] = []
    for figure in figures:
        if not isinstance(figure, Mapping):
            refused.append({"metric": "?", "reason": "not an object"})
            continue
        name = str(figure.get("name") or "")
        try:
            definition = definition_for(name)
        except KeyError:
            refused.append({"metric": name[:80], "reason": "not in the performance taxonomy"})
            continue
        missing = str(figure.get("quality") or "valid").lower() == "missing"
        labels = {**_clean_labels(figure.get("labels")), **fixed}
        if missing and figure.get("reason"):
            labels["reason"] = str(figure["reason"])[:120]
        value = None if missing else figure.get("value")
        identity = json.dumps([agent_name, observed_at.isoformat(), name, sorted(labels.items())])
        try:
            rows.append(PerformanceMetric(
                metric_id="cv-" + hashlib.sha256(identity.encode()).hexdigest()[:40],
                tenant_id=tenant_id, asset_id=asset_id, metric_name=name,
                metric_type=definition.metric_type,
                metric_value=None if value is None else float(value),
                unit=definition.unit, source_id=source_id(agent_name),
                observed_at=observed_at, interval_seconds=interval, labels=labels,
                evidence_id=evidence_id,
                quality_status=QualityStatus.MISSING if missing else QualityStatus.VALID,
            ))
        except (TypeError, ValueError) as exc:
            refused.append({"metric": name[:80], "reason": str(exc).splitlines()[0][:200]})
    return rows, refused


def evidence_reference(document: Mapping[str, Any], key_id: str | None) -> str:
    return f"{EVIDENCE_PREFIX}{key_id or 'unknown'}:{hashlib.sha256(canonical(document)).hexdigest()[:16]}"


# --------------------------------------------------------------------------- #
# the Live systems projection
# --------------------------------------------------------------------------- #

def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def live_systems(rows: Sequence[Any], agents: Iterable[Mapping[str, Any]], *, now: datetime,
                 window_minutes: int, truncated: bool = False) -> dict[str, Any]:
    """One card per Cryptava-monitored server, newest figures first.

    ``rows`` are PerformanceMetric rows from Cryptava sources inside the window;
    ``agents`` are the activated agents of the tenant (so an agent that has not sent a
    sample yet still shows — as a named gap, never as an idle server).
    """
    by_agent: dict[str, list[Any]] = {}
    for row in rows:
        source = str(row.source_id or "")
        if source.startswith(SOURCE_PREFIX):
            by_agent.setdefault(source[len(SOURCE_PREFIX):], []).append(row)
    known = {str(a.get("name")): a for a in agents if a.get("name")}
    systems: list[dict[str, Any]] = []
    for name in sorted(set(by_agent) | set(known)):
        agent_rows = sorted(by_agent.get(name, []), key=lambda r: _aware(r.observed_at))
        agent = known.get(name) or {}
        card: dict[str, Any] = {
            "agent": name, "agent_id": agent.get("id"), "asset_id": host_asset_id(name),
            "host": agent.get("hostname"), "system": None, "ip": None, "scope": None,
            "state": "no_samples", "last_sample_at": None, "age_seconds": None,
            "interval_seconds": None, "signed": False, "metrics": {}, "tls": [], "missing": [],
            "trend": {}, "samples": len(agent_rows),
        }
        if agent_rows:
            last = agent_rows[-1]
            last_at = _aware(last.observed_at)
            labels = dict(last.labels or {})
            interval = last.interval_seconds or 60
            age = max((now - last_at).total_seconds(), 0.0)
            card.update(
                host=labels.get("host") or card["host"], system=labels.get("system"), ip=labels.get("ip"),
                scope=labels.get("scope"), last_sample_at=last_at.isoformat(), age_seconds=round(age),
                interval_seconds=interval,
                state="live" if age <= max(3 * interval, 180) else "stale",
                signed=str(last.evidence_id or "").startswith(EVIDENCE_PREFIX),
            )
            latest_at = {r.observed_at for r in agent_rows if _aware(r.observed_at) == last_at}
            newest = [r for r in agent_rows if r.observed_at in latest_at]
            for row in newest:
                row_labels = dict(row.labels or {})
                quality = getattr(row.quality_status, "value", row.quality_status)
                if row.metric_name == "crypto.tls_handshake_ms" and row.metric_value is not None:
                    card["tls"].append({"port": row_labels.get("port"), "ms": row.metric_value,
                                        "tls_version": row_labels.get("tls_version"),
                                        "algorithm": row_labels.get("algorithm")})
                    continue
                if row.metric_value is None:
                    card["missing"].append({"metric": row.metric_name,
                                            "reason": row_labels.get("reason") or f"{quality} — unknown, never zero"})
                    continue
                card["metrics"][row.metric_name] = {
                    "value": row.metric_value, "unit": row.unit,
                    "labels": {k: v for k, v in row_labels.items()
                               if k not in RESERVED_LABELS and k != "scope"},
                }
            card["tls"].sort(key=lambda item: str(item.get("port")))
            for metric in TREND_METRICS:
                points: dict[str, list[float]] = {}
                for row in agent_rows:
                    if row.metric_name == metric and row.metric_value is not None:
                        points.setdefault(_aware(row.observed_at).isoformat(), []).append(row.metric_value)
                series = [{"t": t, "v": round(max(v), 3)} for t, v in sorted(points.items())][-TREND_POINTS:]
                if series:
                    card["trend"][metric] = series
        systems.append(card)
    counts = {state: sum(1 for s in systems if s["state"] == state) for state in ("live", "stale", "no_samples")}
    return {
        "generated_at": now.isoformat(), "window_minutes": window_minutes, "systems": systems,
        "counts": {"systems": len(systems), **counts}, "truncated": truncated,
        "note": ("live figures as delivered by each server's Cryptava agent, signed with the agent's "
                 "own key; a figure the agent could not read is shown as unknown, never zero; a server "
                 "with no recent sample is stale — its silence is not an idle server"),
    }
