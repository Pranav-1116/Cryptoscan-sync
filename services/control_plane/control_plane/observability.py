"""Platform observability — health of ZELNX itself.

Aggregates the health signals operators need to distinguish "customer
environment is quiet" from "a scanner/agent/queue stopped working":
queue depth & dead-letter rate, agent fleet health, credential health, and
the components' own status. Deterministic given inputs; the API layer supplies
live counts from repositories and (where present) Redis.
"""

from __future__ import annotations

from datetime import datetime, timezone


def _stale(last_seen_iso: str | None, *, now: datetime, seconds: int) -> bool:
    if not last_seen_iso:
        return True
    try:
        dt = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (now - dt).total_seconds() > seconds
    except ValueError:
        return True


def fleet_health(agents: list[dict], *, now: datetime | None = None,
                 stale_after_seconds: int = 300) -> dict:
    """Summarize the agent fleet: connected, stale/offline, versions."""
    now = now or datetime.now(timezone.utc)
    total = len(agents)
    connected = sum(1 for a in agents if a.get("status") == "connected"
                    and not _stale(a.get("last_heartbeat_at") or a.get("last_seen"),
                                   now=now, seconds=stale_after_seconds))
    stale = sum(1 for a in agents if a.get("status") == "connected"
                and _stale(a.get("last_heartbeat_at") or a.get("last_seen"),
                           now=now, seconds=stale_after_seconds))
    offline = total - connected - stale
    versions = {}
    for a in agents:
        v = a.get("version") or "unknown"
        versions[v] = versions.get(v, 0) + 1
    buffered = sum(int(a.get("offline_events_buffered", 0) or 0) for a in agents)
    return {
        "total": total, "connected": connected, "stale": stale, "offline": offline,
        "versions": versions, "buffered_offline_events": buffered,
        "healthy": total == 0 or connected > 0,
    }


def queue_health(events: list[dict]) -> dict:
    """Queue depth, dead-letter rate and processing backlog."""
    total = len(events)
    by_status: dict[str, int] = {}
    priority_depth: dict[str, int] = {}
    for e in events:
        by_status[e.get("status", "?")] = by_status.get(e.get("status", "?"), 0) + 1
        if e.get("status") == "queued":
            p = e.get("priority", "normal")
            priority_depth[p] = priority_depth.get(p, 0) + 1
    dead = by_status.get("dead", 0)
    queued = by_status.get("queued", 0)
    leased = by_status.get("leased", 0)
    dead_rate = round(dead / total, 4) if total else 0.0
    return {
        "total": total, "queued": queued, "leased": leased,
        "completed": by_status.get("completed", 0), "dead": dead,
        "dead_letter_rate": dead_rate,
        "priority_depth": priority_depth,
        "healthy": dead_rate < 0.1,
    }


def credential_health(credentials: list[dict]) -> dict:
    """How many credentials are active vs expiring/expired/unverified."""
    active = sum(1 for c in credentials if c.get("health", {}).get("status") == "active"
                 and c.get("health", {}).get("healthy"))
    expiring = sum(1 for c in credentials if c.get("health", {}).get("rotation_due"))
    expired = sum(1 for c in credentials if c.get("health", {}).get("status") in {"expired", "revoked", "error"})
    pending = sum(1 for c in credentials if c.get("health", {}).get("status") == "pending")
    total = len(credentials)
    return {"total": total, "active": active, "rotation_due": expiring,
            "expired_or_revoked": expired, "unverified": pending,
            "healthy": expired == 0}


def overall_status(*, queue: dict, fleet: dict, credentials: dict,
                   api_up: bool = True, db_up: bool = True) -> dict:
    components = {"api": api_up, "database": db_up,
                  "queue": queue.get("healthy", False),
                  "agents": fleet.get("healthy", False),
                  "credentials": credentials.get("healthy", False)}
    if not api_up or not db_up:
        status = "critical"
    elif not all(components.values()):
        status = "degraded"
    else:
        status = "ok"
    return {"status": status, "components": components,
            "queue": queue, "fleet": fleet, "credentials": credentials}
