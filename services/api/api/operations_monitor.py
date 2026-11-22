"""Operations: live monitoring of the agent-fed estate (fleet, hosts, activity, alerts).

Everything here is read from what the platform already stores. Nothing is scanned or
written:

* the agent registry (``cp_agents``): each Cryptava agent's heartbeat, delivery health,
  link and buffered deliveries;
* each agent's slice of the estate graph (planes, the sources behind every plane, the
  host, services, listeners, libraries, certificates and keys it observed);
* the agents' signed performance samples (CPU, memory, load, connections, TLS and HSM
  latency), stored as Performance Intelligence metrics;
* the estate change feed, its correlated threat patterns and the audit log.

The rules are deterministic and their thresholds are shown. A heartbeat proves that an
agent is running, not that it observed everything. A host with no sample is
``NOT_SAMPLED``, never healthy.
"""

from __future__ import annotations

import hashlib
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

FLEET_SCHEMA = "cryptoscan.ops-fleet/1"
HOSTS_SCHEMA = "cryptoscan.ops-hosts/1"
ACTIVITY_SCHEMA = "cryptoscan.ops-activity/1"
MONITOR_SCHEMA = "cryptoscan.ops-monitor/1"

HEARTBEAT_ENV = "CRYPTOSCAN_AGENT_HEARTBEAT_SECONDS"
DEFAULT_HEARTBEAT_SECONDS = 60
LATE_MULTIPLE = 3            # a heartbeat older than 3× its interval is late
CPU_ALERT_PCT = 90.0
RAM_ALERT_PCT = 90.0
DISK_ALERT_PCT = 90.0
COVERAGE_ALERT_PCT = 80.0
PERF_WINDOW_MINUTES = 60

LIVE, LATE, OFFLINE, NEVER, RETIRED = "LIVE", "LATE", "OFFLINE", "NEVER_REPORTED", "RETIRED"
LIVENESS_MEANING = {
    LIVE: "heartbeat inside the expected interval",
    LATE: "heartbeat overdue, but younger than the estate's staleness threshold",
    OFFLINE: "no heartbeat within the staleness threshold: this host's slice is history",
    NEVER: "enrolled, but the agent has never sent a heartbeat",
    RETIRED: "retired: no longer expected to report",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# metric name → short key shown by the UI
HOST_METRICS = {
    "cpu.utilization_pct": "cpu_pct",
    "ram.utilization_pct": "ram_pct",
    "system.load": "load",
    "network.connections": "connections",
    "storage.utilization_pct": "disk_pct",
    "network.throughput_mbps": "net_mbps",
    "network.tcp_retransmissions": "tcp_retrans",
    "crypto.tls_handshake_ms": "tls_handshake_ms",
    "crypto.hsm_operation_latency_ms": "hsm_latency_ms",
    "crypto.tls_negotiation_failures": "tls_failures",
    "disk.latency_ms": "disk_latency_ms",
}
SERIES_METRICS = ("cpu.utilization_pct", "ram.utilization_pct", "network.connections", "crypto.tls_handshake_ms")

LIMITS = [
    "a heartbeat proves the agent process is running and can reach the platform; it does not prove every plane was read",
    "an unchanged observation stores a heartbeat, not a row, so the activity feed lists changes, not every report",
    "performance figures are the agents' signed samples; a host that sent none is NOT_SAMPLED, not idle",
    "alerts are deterministic rules over stored state, with their thresholds shown; they are not incident declarations",
]


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def heartbeat_seconds() -> int:
    try:
        return max(15, int(os.getenv(HEARTBEAT_ENV, str(DEFAULT_HEARTBEAT_SECONDS))))
    except ValueError:
        return DEFAULT_HEARTBEAT_SECONDS


def aware(value: Any) -> datetime | None:
    if isinstance(value, str) and value:
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00").replace(" ", "T", 1))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def iso(value: Any) -> str | None:
    moment = aware(value)
    return moment.isoformat() if moment else None


def _age(moment: Any, now: datetime) -> int | None:
    at = aware(moment)
    return None if at is None else max(0, int((now - at).total_seconds()))


def _bom_of(plane: str | None) -> str:
    head = str(plane or "").split("·")[0].strip().upper()
    return head or "UNKNOWN"


def _sid(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def liveness(agent: Mapping[str, Any], now: datetime, *, heartbeat: int, stale_after: int) -> dict[str, Any]:
    if str(agent.get("status") or "").lower() == "retired":
        state = RETIRED
    elif agent.get("last_heartbeat_at") is None:
        state = NEVER
    else:
        age = _age(agent.get("last_heartbeat_at"), now) or 0
        state = LIVE if age <= heartbeat * LATE_MULTIPLE else LATE if age <= stale_after else OFFLINE
    return {
        "state": state,
        "age_seconds": _age(agent.get("last_heartbeat_at"), now),
        "last_heartbeat_at": iso(agent.get("last_heartbeat_at")),
        "late_after_seconds": heartbeat * LATE_MULTIPLE,
        "offline_after_seconds": stale_after,
        "meaning": LIVENESS_MEANING[state],
    }


# --------------------------------------------------------------------------- #
# what one agent's slice says about its host
# --------------------------------------------------------------------------- #


def _evidence_by_target(slice_: Mapping[str, Any]) -> dict[str, list[Mapping[str, Any]]]:
    out: dict[str, list[Mapping[str, Any]]] = {}
    for ev in slice_.get("evidence") or []:
        out.setdefault(str(ev.get("target") or ""), []).append(ev)
    return out


def host_identity(slice_: Mapping[str, Any]) -> dict[str, Any]:
    host = next((a for a in slice_.get("assets") or [] if a.get("type") == "HOST"), None) or {}
    attrs = host.get("attributes") or {}
    ident = host.get("identity") or {}
    return {
        "name": host.get("name"),
        "fqdn": attrs.get("fqdn") or ident.get("hostname"),
        "ip_addresses": list(attrs.get("ip_addresses") or ([ident["ip_address"]] if ident.get("ip_address") else [])),
        "os": attrs.get("os"),
        "kernel": attrs.get("kernel"),
        "architecture": attrs.get("architecture"),
        "fips_mode": attrs.get("fips_mode"),
    }


def host_system(slice_: Mapping[str, Any]) -> dict[str, Any] | None:
    """The business system the agent's bank-approved config maps this host to."""
    systems = {a.get("ref"): a for a in slice_.get("assets") or [] if a.get("type") == "SYSTEM"}
    for ev in slice_.get("evidence") or []:
        facts = ev.get("facts") or {}
        if ev.get("target") in systems and "part of this business system" in str(facts.get("mapping") or ""):
            return {"name": systems[ev["target"]].get("name"), "owner": facts.get("owner"),
                    "criticality": facts.get("criticality")}
    return None


def planes(slice_: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in slice_.get("collectors") or []:
        sources = [
            {key: item.get(key) for key in ("source", "reads", "state", "found", "note")}
            for item in (row.get("sources") or []) if isinstance(item, Mapping)
        ]
        rows.append({
            "plane": row.get("plane"),
            "bom": _bom_of(row.get("plane")),
            "status": row.get("status") or row.get("state") or "UNKNOWN",
            "reason": row.get("reason"),
            "sources": sources,
            "source_states": dict(Counter(str(s.get("state") or "UNKNOWN") for s in sources)),
        })
    return rows


def _crypto_rows(slice_: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every algorithm fact on this host, classified."""
    from shared_models.quantum_classify import quantum_verdict

    names = {a.get("ref"): (a.get("name"), a.get("type")) for a in slice_.get("assets") or []}
    seen: dict[str, dict[str, Any]] = {}
    for ev in slice_.get("evidence") or []:
        facts = ev.get("facts") or {}
        algos = facts.get("algorithm")
        for raw in ([algos] if isinstance(algos, str) else list(algos or [])):
            if not raw:
                continue
            verdict = quantum_verdict(str(raw))
            row = seen.setdefault(str(raw), {
                "algorithm": str(raw), "verdict": verdict.get("verdict"), "status": verdict.get("status"),
                "runtime": False, "assets": [],
            })
            if ev.get("evidence_type") == "RUNTIME_OBSERVED":
                row["runtime"] = True
            label = (names.get(ev.get("target")) or (ev.get("target"), None))[0]
            if label and label not in row["assets"]:
                row["assets"].append(label)
    return sorted(seen.values(), key=lambda r: (r["verdict"] != "SHOR_VULNERABLE", r["algorithm"]))


def host_inventory(slice_: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    by_target = _evidence_by_target(slice_)

    def runtime(ref: Any) -> bool:
        return any(ev.get("evidence_type") == "RUNTIME_OBSERVED" for ev in by_target.get(str(ref), []))

    names = {a.get("ref"): a.get("name") for a in slice_.get("assets") or []}
    loads: dict[str, set[str]] = {}
    for rel in slice_.get("relationships") or []:
        if str(rel.get("predicate")) == "uses_crypto_library" and str(rel.get("basis")) == "RUNTIME_OBSERVATION":
            loads.setdefault(str(rel.get("object")), set()).add(str(names.get(rel.get("subject")) or rel.get("subject")))
    services, listeners, libraries, certificates, keys = [], [], [], [], []
    for asset in slice_.get("assets") or []:
        kind, attrs, ident = asset.get("type"), asset.get("attributes") or {}, asset.get("identity") or {}
        if kind == "SERVICE":
            facts = {}
            for ev in by_target.get(str(asset.get("ref")), []):
                facts.update(ev.get("facts") or {})
            services.append({"name": asset.get("name"), "executable": attrs.get("executable") or facts.get("executable"),
                             "user": attrs.get("user") or facts.get("user"), "listens_on": facts.get("listens_on"),
                             "running": runtime(asset.get("ref")),
                             "libraries": sorted({str(names.get(r.get("object")) or r.get("object"))
                                                  for r in slice_.get("relationships") or []
                                                  if r.get("subject") == asset.get("ref")
                                                  and str(r.get("predicate")) == "uses_crypto_library"})})
        elif kind == "NETWORK_ENDPOINT":
            facts = {}
            for ev in by_target.get(str(asset.get("ref")), []):
                facts.update(ev.get("facts") or {})
            listeners.append({
                "name": asset.get("name"), "host": ident.get("host"), "port": ident.get("port"),
                "protocol": ident.get("protocol") or attrs.get("transport"), "process": attrs.get("process"),
                "loopback_only": attrs.get("loopback_only"), "tls_version": facts.get("tls_version") or attrs.get("tls_version"),
                "cipher": facts.get("cipher_suite") or attrs.get("cipher_suite"),
            })
        elif kind == "LIBRARY":
            loaded_by = sorted(loads.get(str(asset.get("ref")), set()))
            libraries.append({"name": asset.get("name"), "version": attrs.get("version") or ident.get("version"),
                              "path": attrs.get("path") or ident.get("path"),
                              "loaded": bool(loaded_by) or runtime(asset.get("ref")), "loaded_by": loaded_by})
        elif kind == "CERTIFICATE":
            facts = {}
            for ev in by_target.get(str(asset.get("ref")), []):
                facts.update(ev.get("facts") or {})
            not_after = aware(facts.get("not_after") or attrs.get("not_after"))
            certificates.append({
                "name": asset.get("name"), "subject": facts.get("subject") or attrs.get("subject"),
                "issuer": facts.get("issuer") or attrs.get("issuer"), "algorithm": facts.get("algorithm"),
                "key_size": facts.get("key_size"), "not_after": iso(not_after),
                "days_left": None if not_after is None else int((not_after - now).total_seconds() // 86400),
            })
        elif kind == "KEY_METADATA":
            keys.append({"name": asset.get("name"), "algorithm": attrs.get("algorithm"),
                         "key_size": attrs.get("key_size"), "path": attrs.get("path")})
    evidence_types = Counter(str(ev.get("evidence_type") or "UNKNOWN") for ev in slice_.get("evidence") or [])
    return {
        "services": sorted(services, key=lambda s: str(s["name"])),
        "listeners": sorted(listeners, key=lambda s: (str(s["host"]), int(s["port"]) if str(s["port"] or "").isdigit() else 0)),
        "libraries": sorted(libraries, key=lambda s: (not s["loaded"], str(s["name"]))),
        "certificates": sorted(certificates, key=lambda s: (s["days_left"] is None, s["days_left"] or 0)),
        "keys": keys,
        "algorithms": _crypto_rows(slice_),
        "evidence_types": dict(sorted(evidence_types.items())),
        "runtime_evidence": evidence_types.get("RUNTIME_OBSERVED", 0),
    }


# --------------------------------------------------------------------------- #
# performance: the agents' signed samples
# --------------------------------------------------------------------------- #


def performance_summary(samples: Iterable[Mapping[str, Any]], now: datetime, *, heartbeat: int) -> dict[str, Any]:
    """``samples`` are rows ``{metric_name, value, unit, labels, observed_at}``, any order."""
    rows = sorted((s for s in samples if aware(s.get("observed_at"))), key=lambda s: aware(s["observed_at"]))
    if not rows:
        return {"state": "NOT_SAMPLED", "sampled_at": None, "age_seconds": None, "latest": {}, "series": {},
                "meaning": "no signed performance sample from this host in the last "
                           f"{PERF_WINDOW_MINUTES} minutes: its load is unknown, not low"}
    latest: dict[str, dict[str, Any]] = {}
    series: dict[str, list[list[Any]]] = {}
    for s in rows:
        name = str(s.get("metric_name"))
        key = HOST_METRICS.get(name)
        if key is None or s.get("value") is None:
            continue
        labels = dict(s.get("labels") or {})
        target = labels.get("target") or labels.get("port") or labels.get("endpoint")
        if name.startswith("crypto.tls_handshake") and target:
            latest.setdefault(key + "_by_target", {})[str(target)] = round(float(s["value"]), 2)
        latest[key] = {"value": round(float(s["value"]), 2), "unit": s.get("unit"), "at": iso(s["observed_at"])}
        if name in SERIES_METRICS:
            series.setdefault(key, []).append([iso(s["observed_at"]), round(float(s["value"]), 2)])
    sampled_at = aware(rows[-1]["observed_at"])
    age = _age(sampled_at, now)
    fresh = age is not None and age <= heartbeat * LATE_MULTIPLE * 2
    return {"state": "SAMPLED" if fresh else "SAMPLE_STALE", "sampled_at": iso(sampled_at), "age_seconds": age,
            "latest": latest, "series": {k: v[-120:] for k, v in series.items()},
            "meaning": "latest signed sample per metric" if fresh else "the newest sample is old: figures are history"}


# --------------------------------------------------------------------------- #
# fleet
# --------------------------------------------------------------------------- #


def fleet(
    agents: list[Mapping[str, Any]],
    slices: Mapping[str, Mapping[str, Any]],
    perf: Mapping[str, Mapping[str, Any]],
    now: datetime,
    *,
    heartbeat: int,
    stale_after: int,
) -> dict[str, Any]:
    registry = {str(a.get("name")): a for a in agents}
    names = sorted(set(registry) | set(slices))
    rows = []
    for name in names:
        agent = registry.get(name) or {}
        slice_ = slices.get(name) or {}
        meta = slice_.get("meta") or {}
        registered = bool(agent)
        live = liveness(agent, now, heartbeat=heartbeat, stale_after=stale_after) if registered else {
            "state": "UNREGISTERED", "age_seconds": None, "last_heartbeat_at": None,
            "late_after_seconds": heartbeat * LATE_MULTIPLE, "offline_after_seconds": stale_after,
            "meaning": "a slice of the estate names this agent, but the registry has no such agent",
        }
        plane_rows = planes(slice_)
        perf_row = perf.get(name) or performance_summary([], now, heartbeat=heartbeat)
        issues = []
        if registered and agent.get("last_heartbeat_at") is not None and not agent.get("healthy"):
            issues.append("the agent reported its last delivery as failed")
        if int(agent.get("offline_events_buffered") or 0) > 0:
            issues.append(f"{agent.get('offline_events_buffered')} observation(s) buffered on the host, not delivered")
        if registered and str(agent.get("link") or "") not in ("encrypted", ""):
            issues.append(f"link is {agent.get('link')}, not encrypted")
        for p in plane_rows:
            if p["status"] in ("FAILED", "UNKNOWN", "NOT_ATTEMPTED"):
                issues.append(f"{p['plane']} is {p['status']}")
        if slice_ and meta.get("authenticity") not in (None, "VALID"):
            issues.append(f"its slice is {meta.get('authenticity')}, not signed by a registered agent key")
        if registered and not slice_ and live["state"] in (LIVE, LATE):
            issues.append("heartbeats arrive, but no observation from this agent is in the estate")
        rows.append({
            "name": name,
            "agent_id": agent.get("id") or meta.get("agent_id"),
            "registered": registered,
            "registry_status": agent.get("status"),
            "liveness": live,
            "healthy": agent.get("healthy") if registered else None,
            "link": agent.get("link"),
            "version": agent.get("version") or meta.get("agent_version"),
            "target_version": agent.get("target_version"),
            "buffered": int(agent.get("offline_events_buffered") or 0),
            "platform": agent.get("platform"),
            "environment": agent.get("environment"),
            "last_seen_ip": agent.get("last_seen_ip"),
            "enrolled_at": iso(agent.get("created_at")),
            "host": host_identity(slice_),
            "system": host_system(slice_),
            "slice": {
                "assets": len(slice_.get("assets") or []),
                "evidence": len(slice_.get("evidence") or []),
                "relationships": len(slice_.get("relationships") or []),
                "asset_types": dict(sorted(Counter(str(a.get("type")) for a in slice_.get("assets") or []).items())),
                "observed_at": iso(meta.get("observed_at")),
                "last_changed_at": iso(meta.get("received_at")),
                "authenticity": meta.get("authenticity"),
                "key_id": meta.get("key_id"),
            } if slice_ else None,
            "planes": plane_rows,
            "plane_states": dict(Counter(p["status"] for p in plane_rows)),
            "source_states": dict(sum((Counter(p["source_states"]) for p in plane_rows), Counter())),
            "performance": {k: perf_row.get(k) for k in ("state", "sampled_at", "age_seconds", "latest", "series")},
            "issues": issues,
        })
    states = Counter(r["liveness"]["state"] for r in rows)
    return {
        "schema": FLEET_SCHEMA,
        "at": now.isoformat(),
        "heartbeat_seconds": heartbeat,
        "late_after_seconds": heartbeat * LATE_MULTIPLE,
        "offline_after_seconds": stale_after,
        "totals": {
            "agents": len(rows),
            "by_liveness": dict(states),
            "live": states.get(LIVE, 0),
            "reporting": states.get(LIVE, 0) + states.get(LATE, 0),
            "with_issues": sum(1 for r in rows if r["issues"]),
            "buffered": sum(r["buffered"] for r in rows),
            "plane_states": dict(sum((Counter(r["plane_states"]) for r in rows), Counter())),
            "source_states": dict(sum((Counter(r["source_states"]) for r in rows), Counter())),
            "systems": sorted({r["system"]["name"] for r in rows if r.get("system") and r["system"].get("name")}),
        },
        "agents": rows,
        "limits": LIMITS,
    }


def hosts(
    fleet_view: Mapping[str, Any],
    slices: Mapping[str, Mapping[str, Any]],
    perf: Mapping[str, Mapping[str, Any]],
    now: datetime,
    *,
    heartbeat: int,
) -> dict[str, Any]:
    rows = []
    for agent in fleet_view.get("agents") or []:
        slice_ = slices.get(agent["name"])
        if not slice_:
            continue
        inv = host_inventory(slice_, now)
        perf_row = perf.get(agent["name"]) or performance_summary([], now, heartbeat=heartbeat)
        algos = inv["algorithms"]
        rows.append({
            "agent": agent["name"],
            "host": agent["host"],
            "system": agent["system"],
            "liveness": agent["liveness"],
            "performance": perf_row,
            **inv,
            "counts": {
                "services": len(inv["services"]),
                "running_services": sum(1 for s in inv["services"] if s["running"]),
                "listeners": len(inv["listeners"]),
                "exposed_listeners": sum(1 for l in inv["listeners"] if l.get("loopback_only") is False),
                "libraries": len(inv["libraries"]),
                "loaded_libraries": sum(1 for l in inv["libraries"] if l["loaded"]),
                "certificates": len(inv["certificates"]),
                "expiring_certificates": sum(1 for c in inv["certificates"] if c["days_left"] is not None and c["days_left"] <= 30),
                "keys": len(inv["keys"]),
                "algorithms": len(algos),
                "quantum_vulnerable": sum(1 for a in algos if a["verdict"] == "SHOR_VULNERABLE"),
                "runtime_evidence": inv["runtime_evidence"],
            },
        })
    return {
        "schema": HOSTS_SCHEMA,
        "at": now.isoformat(),
        "hosts": rows,
        "totals": {
            "hosts": len(rows),
            "sampled": sum(1 for r in rows if r["performance"]["state"] == "SAMPLED"),
            "running_services": sum(r["counts"]["running_services"] for r in rows),
            "loaded_libraries": sum(r["counts"]["loaded_libraries"] for r in rows),
            "quantum_vulnerable": sum(r["counts"]["quantum_vulnerable"] for r in rows),
            "runtime_evidence": sum(r["counts"]["runtime_evidence"] for r in rows),
        },
        "thresholds": {"cpu_pct": CPU_ALERT_PCT, "ram_pct": RAM_ALERT_PCT, "disk_pct": DISK_ALERT_PCT},
        "limits": LIMITS,
    }


# --------------------------------------------------------------------------- #
# alerts and overall status
# --------------------------------------------------------------------------- #


def _alert(rule: str, severity: str, subject: str, title: str, detail: str, next_action: str, *,
           since: Any = None, agent: str | None = None, system: str | None = None, link: str | None = None) -> dict[str, Any]:
    return {"id": f"{rule}:{_sid(rule, subject)}", "rule": rule, "severity": severity, "subject": subject,
            "title": title, "detail": detail, "next_action": next_action, "since": iso(since),
            "agent": agent, "system": system, "link": link}


def alerts(
    fleet_view: Mapping[str, Any],
    *,
    connection: Mapping[str, Any] | None,
    coverage: Mapping[str, Any] | None,
    changes: Iterable[Mapping[str, Any]],
    patterns: Iterable[Mapping[str, Any]],
    trust_findings: Iterable[str] = (),
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    stale_after = int(fleet_view.get("offline_after_seconds") or 600)
    conn_state = (connection or {}).get("state")
    if conn_state in ("STALE", "NEVER_CONNECTED"):
        out.append(_alert(
            "ESTATE_STALE", "CRITICAL", "estate",
            "The estate is not live" if conn_state == "STALE" else "No agent has ever reported",
            str((connection or {}).get("meaning") or ""),
            "check the agents below and their link to the platform",
            since=(connection or {}).get("last_observation"), link="/live"))
    for agent in fleet_view.get("agents") or []:
        name = agent["name"]
        system = (agent.get("system") or {}).get("name")
        tier0 = str((agent.get("system") or {}).get("criticality") or "").lower() in ("tier-0", "critical")
        state = agent["liveness"]["state"]
        last = aware(agent["liveness"].get("last_heartbeat_at"))
        if state == OFFLINE:
            out.append(_alert(
                "AGENT_OFFLINE", "CRITICAL" if tier0 else "HIGH", name, f"{name} stopped reporting",
                f"last heartbeat {agent['liveness']['age_seconds']}s ago, past the {stale_after}s threshold"
                + (f"; it is the agent for {system}" if system else ""),
                "check the agent service on the host (`cryptava status`) and its network path to the platform",
                since=(last + timedelta(seconds=stale_after)) if last else None, agent=name, system=system,
                link="/live-scanners"))
        elif state == LATE:
            out.append(_alert(
                "AGENT_LATE", "MEDIUM", name, f"{name} is late",
                f"last heartbeat {agent['liveness']['age_seconds']}s ago; expected every {fleet_view.get('heartbeat_seconds')}s",
                "watch it: it turns offline at the staleness threshold", since=last, agent=name, system=system,
                link="/live-scanners"))
        elif state == NEVER:
            out.append(_alert(
                "AGENT_NEVER_REPORTED", "MEDIUM", name, f"{name} has never reported",
                "enrolled in the registry, but no heartbeat has arrived",
                "activate the agent on its host (`cryptava enroll`), then start it",
                since=agent.get("enrolled_at"), agent=name, system=system, link="/live-scanners"))
        elif state == "UNREGISTERED":
            out.append(_alert(
                "SLICE_WITHOUT_AGENT", "LOW", name, f"{name} has a slice but no registered agent",
                "the estate still holds this host's observations, but the registry has no agent by that name",
                "re-enrol the host, or remove its slice if it was decommissioned", agent=name, system=system,
                link="/live-scanners"))
        if state in (LIVE, LATE):
            if agent.get("healthy") is False:
                out.append(_alert(
                    "DELIVERY_FAILING", "HIGH", name, f"{name} cannot deliver observations",
                    "the agent's last heartbeat reported a failed delivery; the platform keeps its previous slice",
                    "read the agent log on the host; the next successful run replaces the slice",
                    since=last, agent=name, system=system, link="/live-scanners"))
            if agent.get("buffered"):
                out.append(_alert(
                    "DELIVERY_BUFFERED", "MEDIUM", name, f"{name} has {agent['buffered']} undelivered observation(s)",
                    "observations are spooled on the host until the platform accepts them",
                    "check the platform's ingestion responses in the agent log", since=last, agent=name,
                    system=system, link="/live-scanners"))
        for plane in agent.get("planes") or []:
            if plane["status"] in ("FAILED",):
                out.append(_alert(
                    "PLANE_FAILED", "HIGH", f"{name} · {plane['plane']}", f"{plane['plane']} failed on {name}",
                    str(plane.get("reason") or ""), "fix the source it could not read; its BOM rows are unknown, not empty",
                    agent=name, system=system, link="/live-scanners"))
            elif plane["status"] in ("UNKNOWN", "NOT_ATTEMPTED"):
                out.append(_alert(
                    "PLANE_UNKNOWN", "LOW", f"{name} · {plane['plane']}", f"{plane['plane']} not observed on {name}",
                    str(plane.get("reason") or ""), "enable the plane's sources in the agent configuration",
                    agent=name, system=system, link="/live-scanners"))
            for source in plane.get("sources") or []:
                if str(source.get("state") or "").upper() in ("ERROR", "FAILED", "DENIED", "TIMEOUT"):
                    out.append(_alert(
                        "SOURCE_ERROR", "MEDIUM", f"{name} · {source.get('source')}",
                        f"{source.get('source')} could not be read on {name}",
                        str(source.get("note") or source.get("reads") or ""),
                        "check the agent's permissions for this source", agent=name, system=system,
                        link="/live-scanners"))
        latest = (agent.get("performance") or {}).get("latest") or {}
        for key, limit, rule, label in (("cpu_pct", CPU_ALERT_PCT, "HOST_CPU_HIGH", "CPU"),
                                        ("ram_pct", RAM_ALERT_PCT, "HOST_MEMORY_HIGH", "memory"),
                                        ("disk_pct", DISK_ALERT_PCT, "HOST_DISK_HIGH", "disk")):
            value = (latest.get(key) or {}).get("value")
            if value is not None and value >= limit:
                out.append(_alert(
                    rule, "MEDIUM", f"{name} · {label}", f"{label} at {value:g}% on {name}",
                    f"latest signed sample is at or above the {limit:g}% threshold",
                    "check the host's workload before the agent's own collection is affected",
                    since=(latest.get(key) or {}).get("at"), agent=name, system=system, link="/runtime"))
        if (agent.get("slice") or {}).get("authenticity") not in (None, "VALID"):
            out.append(_alert(
                "UNSIGNED_SLICE", "MEDIUM", name, f"{name}'s observations are not signed",
                f"authenticity {agent['slice']['authenticity']}", "activate the agent so its key signs each observation",
                agent=name, system=system, link="/live-scanners"))
    pct = (coverage or {}).get("coverage_percent")
    if isinstance(pct, (int, float)) and pct < COVERAGE_ALERT_PCT:
        out.append(_alert(
            "COVERAGE_LOW", "MEDIUM", "estate coverage", f"Collection coverage is {pct:g}%",
            f"{(coverage or {}).get('collected')} of {(coverage or {}).get('expected')} expected targets collected; "
            f"threshold {COVERAGE_ALERT_PCT:g}%",
            "open the planes that are PARTIAL or UNKNOWN on Live scanners", link="/live-scanners"))
    unacked = [c for c in changes if not c.get("acknowledged") and c.get("severity") in ("CRITICAL", "WARNING")]
    critical = [c for c in unacked if c.get("severity") == "CRITICAL"]
    if critical:
        out.append(_alert(
            "CRITICAL_CHANGE_UNREVIEWED", "HIGH", "change feed",
            f"{len(critical)} critical estate change(s) not reviewed", str(critical[0].get("headline") or ""),
            "review and acknowledge them in Activity", since=critical[-1].get("first_detected_at"),
            link="/live-stream"))
    elif unacked:
        out.append(_alert(
            "CHANGES_UNREVIEWED", "LOW", "change feed", f"{len(unacked)} estate change(s) not reviewed",
            str(unacked[0].get("headline") or ""), "review and acknowledge them in Activity",
            since=unacked[-1].get("first_detected_at"), link="/live-stream"))
    for pattern in patterns:
        level = int(pattern.get("level") or 0)
        if level >= 3:
            out.append(_alert(
                "THREAT_PATTERN", "HIGH" if level >= 4 else "MEDIUM", str(pattern.get("pattern_id")),
                str(pattern.get("name") or "pattern").replace("_", " ").lower().capitalize(),
                str(pattern.get("headline") or pattern.get("why") or ""),
                "review the correlated changes; a pattern is a priority for review, not proof of compromise",
                since=(pattern.get("window") or {}).get("to") or pattern.get("last_seen"), link="/live-stream"))
    for finding in trust_findings:
        out.append(_alert("NO_TRUSTED_COLLECTOR_KEY", "LOW", "ingestion trust", "Collector trust keys are not configured",
                          str(finding), "set CRYPTOSCAN_COLLECTOR_TRUST_KEYS so unsigned observations are refused",
                          link="/live"))
    out.sort(key=lambda a: (SEVERITY_ORDER.get(a["severity"], 9), a["rule"], a["subject"]))
    return out


def overall(fleet_view: Mapping[str, Any], alert_rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    totals = fleet_view.get("totals") or {}
    if not totals.get("agents"):
        return {"state": "NOT_CONNECTED", "headline": "No agent is enrolled or reporting",
                "meaning": "nothing is being monitored; enrol an agent on each bank server"}
    if not totals.get("reporting"):
        return {"state": "DOWN", "headline": "No agent is reporting",
                "meaning": "every agent is offline or has never reported: the estate shown is history"}
    worst = min((SEVERITY_ORDER.get(a["severity"], 9) for a in alert_rows), default=9)
    if worst <= SEVERITY_ORDER["HIGH"]:
        n = sum(1 for a in alert_rows if SEVERITY_ORDER.get(a["severity"], 9) <= 1)
        return {"state": "DEGRADED", "headline": f"{n} critical or high alert(s) need attention",
                "meaning": "agents are reporting, but part of the estate is not observed as expected"}
    return {"state": "OPERATIONAL",
            "headline": f"{totals.get('live')} of {totals.get('agents')} agents live",
            "meaning": "agents are reporting inside their interval; this is not a claim that the estate is safe"}


# --------------------------------------------------------------------------- #
# activity: one timeline
# --------------------------------------------------------------------------- #

CHANGE_SEVERITY = {"CRITICAL": "CRITICAL", "WARNING": "MEDIUM", "INFO": "INFO", "BASELINE": "INFO"}
AUDIT_TITLES = {
    "control.agent_enrolled": ("agent", "INFO", "Agent enrolled"),
    "control.agent_activated": ("agent", "INFO", "Agent activated"),
    "control.agent_activation_denied": ("agent", "HIGH", "Agent activation refused"),
    "control.agent_upgrade": ("agent", "INFO", "Agent upgrade requested"),
    "control.agent_configured": ("agent", "INFO", "Agent configuration changed"),
    "control.agent_cert_rotated": ("agent", "INFO", "Agent certificate rotated"),
    "control.agent_token_reissued": ("agent", "LOW", "Agent enrollment token reissued"),
    "control.agent_heartbeat_denied": ("agent", "HIGH", "Agent heartbeat refused"),
    "control.agent_performance_denied": ("agent", "HIGH", "Agent performance sample refused"),
    "control.emergency_stop": ("agent", "CRITICAL", "Safe-scan emergency stop"),
    "remediation.task_created": ("task", "INFO", "Remediation task opened"),
    "remediation.task_accept": ("task", "INFO", "Remediation task accepted"),
    "remediation.task_accepted": ("task", "INFO", "Remediation task accepted"),
    "remediation.task_complete": ("task", "INFO", "Remediation task marked complete"),
    "remediation.task_completed": ("task", "INFO", "Remediation task marked complete"),
    "remediation.task_verified": ("task", "INFO", "Remediation task verified"),
}


def audit_detail(raw: str) -> str:
    """An audit row's JSON detail as one readable line; unknown shapes pass through."""
    import json

    try:
        data = json.loads(raw) if raw.strip().startswith("{") else None
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return raw[:300]
    parts = []
    for change in data.get("changes") or []:
        if isinstance(change, dict) and change.get("field") and change.get("field") != "notes":
            parts.append(f"{change['field']}: {change.get('before') or '—'} → {change.get('after') or '—'}")
    for key in ("name", "result", "reason", "owner", "rule_id", "hostname", "key_id", "target_version"):
        if data.get(key) not in (None, "", []):
            parts.append(f"{key.replace('_', ' ')} {data[key]}")
    return " · ".join(parts)[:300] or raw[:300]


def _match_agents(text: str, needles: Mapping[str, str]) -> list[str]:
    low = text.lower()
    return sorted({agent for needle, agent in needles.items() if needle and needle.lower() in low})


def activity(
    *,
    changes: Iterable[Mapping[str, Any]],
    patterns: Iterable[Mapping[str, Any]],
    audit: Iterable[Mapping[str, Any]],
    fleet_view: Mapping[str, Any],
    now: datetime,
) -> dict[str, Any]:
    needles: dict[str, str] = {}
    systems: dict[str, str | None] = {}
    for agent in fleet_view.get("agents") or []:
        needles[agent["name"]] = agent["name"]
        if agent.get("agent_id"):
            needles[str(agent["agent_id"])] = agent["name"]
        for alias in (agent["host"].get("name"), agent["host"].get("fqdn")):
            if alias and len(alias) > 3:
                needles[alias] = agent["name"]
        systems[agent["name"]] = (agent.get("system") or {}).get("name")
    events: list[dict[str, Any]] = []
    for change in changes:
        items = change.get("changes") or []
        text = " ".join(str(i.get("subject") or "") + " " + str(i.get("detail") or "") for i in items)
        agents = _match_agents(text, needles)
        events.append({
            "id": f"change:{change.get('event_id')}", "kind": "change",
            "at": change.get("first_detected_at") or change.get("last_detected_at"),
            "severity": CHANGE_SEVERITY.get(str(change.get("severity")), "INFO"),
            "title": str(change.get("verdict") or "CHANGE").replace("_", " ").lower().capitalize(),
            "detail": change.get("headline"), "next_action": change.get("next_action"),
            "agents": agents, "systems": sorted({s for a in agents if (s := systems.get(a))}),
            "acknowledged": bool(change.get("acknowledged")), "ref": change.get("event_id"),
            "counts": change.get("counts") or {},
            "items": [{k: i.get(k) for k in ("kind", "severity", "subject", "before", "after", "detail")} for i in items[:60]],
            "item_total": len(items), "link": "/live",
        })
    for pattern in patterns:
        level = int(pattern.get("level") or 0)
        text = " ".join(str(s) for s in pattern.get("subjects") or [])
        agents = _match_agents(text + " " + str(pattern.get("headline") or ""), needles)
        events.append({
            "id": f"pattern:{pattern.get('pattern_id')}", "kind": "pattern",
            "at": (pattern.get("window") or {}).get("to") or pattern.get("last_seen") or pattern.get("first_seen"),
            "severity": "HIGH" if level >= 4 else "MEDIUM" if level >= 3 else "LOW",
            "title": str(pattern.get("name") or "pattern").replace("_", " ").lower().capitalize(),
            "detail": pattern.get("headline"), "next_action": pattern.get("level_meaning"),
            "agents": agents, "systems": sorted({s for a in agents if (s := systems.get(a))}),
            "acknowledged": None, "ref": pattern.get("pattern_id"), "counts": {},
            "items": [{"kind": "WHY", "severity": None, "subject": pattern.get("why"), "before": None, "after": None,
                       "detail": None}] if pattern.get("why") else [],
            "item_total": 1 if pattern.get("why") else 0, "link": "/live",
        })
    for row in audit:
        kind, severity, title = AUDIT_TITLES.get(str(row.get("action")), (None, None, None))
        if kind is None:
            continue
        if str(row.get("outcome") or "SUCCESS") != "SUCCESS":
            severity = "HIGH"
        raw = str(row.get("detail") or "")
        detail = audit_detail(raw)
        agents = _match_agents(f"{row.get('target_id')} {raw}", needles)
        events.append({
            "id": f"audit:{row.get('id')}", "kind": kind, "at": row.get("created_at"), "severity": severity,
            "title": title, "detail": detail or f"{row.get('target_type') or ''} {row.get('target_id') or ''}".strip(),
            "next_action": None, "agents": agents, "systems": sorted({s for a in agents if (s := systems.get(a))}),
            "acknowledged": None, "ref": row.get("target_id"), "actor": row.get("actor"), "counts": {},
            "items": [], "item_total": 0, "link": "/remediation" if kind == "task" else "/live-scanners",
        })
    stale_after = int(fleet_view.get("offline_after_seconds") or 600)
    for agent in fleet_view.get("agents") or []:
        if agent["liveness"]["state"] != OFFLINE:
            continue
        last = aware(agent["liveness"].get("last_heartbeat_at"))
        events.append({
            "id": f"silent:{agent['name']}:{iso(last)}", "kind": "agent",
            "at": iso(last + timedelta(seconds=stale_after)) if last else None, "severity": "HIGH",
            "title": "Agent went silent", "detail": f"{agent['name']} sent no heartbeat for {stale_after}s",
            "next_action": "check the agent service on the host", "agents": [agent["name"]],
            "systems": [s] if (s := systems.get(agent["name"])) else [], "acknowledged": None,
            "ref": agent["name"], "counts": {}, "items": [], "item_total": 0, "link": "/live-scanners",
        })
    for e in events:
        e["at"] = iso(e.get("at"))
    events = [e for e in events if e["at"]]
    events.sort(key=lambda e: e["at"], reverse=True)
    day_ago = now - timedelta(hours=24)
    hourly = [0] * 24
    for e in events:
        at = aware(e["at"])
        if at and at >= day_ago:
            hourly[min(23, int((at - day_ago).total_seconds() // 3600))] += 1
    return {
        "schema": ACTIVITY_SCHEMA,
        "at": now.isoformat(),
        "events": events,
        "totals": {
            "events": len(events),
            "last_24h": sum(hourly),
            "by_kind": dict(Counter(e["kind"] for e in events)),
            "by_severity": dict(Counter(e["severity"] for e in events)),
            "unacknowledged_changes": sum(1 for e in events if e["kind"] == "change" and e["acknowledged"] is False),
        },
        "hourly": {"from": day_ago.isoformat(), "to": now.isoformat(), "counts": hourly},
        "limits": LIMITS,
    }


__all__ = [
    "ACTIVITY_SCHEMA", "FLEET_SCHEMA", "HOSTS_SCHEMA", "MONITOR_SCHEMA", "LIMITS",
    "activity", "alerts", "aware", "fleet", "heartbeat_seconds", "host_identity", "host_inventory",
    "host_system", "hosts", "iso", "liveness", "overall", "performance_summary", "planes",
]
