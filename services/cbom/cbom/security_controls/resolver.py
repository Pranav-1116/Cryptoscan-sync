"""Correlation resolvers: the hop-by-hop path, sourced from the estate and bounded by time.

Guide 181 could answer *what crypto did this alert touch* only if the caller handed it five
lists. That is a demonstration, not an answer. This module supplies the lists from the platform
— tenant-scoped, read-only, from the tables that already hold them — and adds the dimension the
first version was missing: **time**.

Why time is not a detail
------------------------

An inventory is a statement about a moment. An IDS alert at 09:14 correlated against a process
list captured at 06:00 is not a fact: the process may have restarted, the library may have been
upgraded, the key may have rotated. So every hop carries the moment its evidence was captured,
and the resolver reports one of

* ``IN_WINDOW`` — captured inside the window the caller requires, so the hop may be stated;
* ``STALE`` — captured before the window opened: the hop is returned for the human reading the
  finding, and **excluded from the answer** rather than silently trusted;
* ``AFTER_EVENT`` — captured after the event but inside tolerance: recorded, marked, and not
  treated as evidence of what ran at the moment of the alert.

A caller who only wants strict answers sets ``max_age_seconds`` and gets ``STALE`` hops named in
``unresolved`` with code ``STALE_EVIDENCE``. That is the difference between "we could not prove
this" and "we assumed it".

Table choices (each one the closest thing the platform already stores)
----------------------------------------------------------------------

======================================  =====================================================
hop                                      source
======================================  =====================================================
source IP → host                         ``RuntimeFinding.hostname`` plus an endpoint row whose
                                         address matches, else a ``HardwareAsset`` by id
host → process                           ``RuntimeFinding`` (hostname, process_name, pid)
process → API                            ``RuntimeFinding.extra['api']`` when a collector
                                         recorded it, else the application inventory link
API → crypto library                     ``RuntimeFinding.kind == 'tls-library-risk'``
library → HSM/KMS key                    ``PaymentKey`` by HSM device, then the KMS surface
======================================  =====================================================

Where a table cannot answer, the resolver says so: a hop nobody collected stays unresolved with
the reason, exactly as in guide 181.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Protocol

from .base import ControlRefused, _norm

IN_WINDOW = "IN_WINDOW"
STALE = "STALE"
AFTER_EVENT = "AFTER_EVENT"
UNKNOWN_TIME = "UNKNOWN_TIME"

#: how close to the event an observation must be to describe it, unless the caller says
DEFAULT_MAX_AGE_SECONDS = 24 * 3600
#: an observation captured after the event is still useful, but never as "what was running"
DEFAULT_AFTER_TOLERANCE_SECONDS = 900


def _moment(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class Window:
    """The interval an answer is allowed to speak about."""

    event_at: datetime | None = None
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    after_tolerance_seconds: int = DEFAULT_AFTER_TOLERANCE_SECONDS

    def classify(self, captured_at: Any) -> str:
        moment = _moment(captured_at)
        if moment is None:
            return UNKNOWN_TIME
        if self.event_at is None:
            return IN_WINDOW
        if moment > self.event_at + timedelta(seconds=self.after_tolerance_seconds):
            return AFTER_EVENT
        if moment < self.event_at - timedelta(seconds=self.max_age_seconds):
            return STALE
        return IN_WINDOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_at": self.event_at.isoformat() if self.event_at else None,
            "max_age_seconds": self.max_age_seconds,
            "after_tolerance_seconds": self.after_tolerance_seconds,
            "opens_at": (self.event_at - timedelta(seconds=self.max_age_seconds)).isoformat()
            if self.event_at else None,
        }


class InventoryResolver(Protocol):
    """Five lookups. A resolver that cannot answer one says so instead of guessing."""

    def host_for_address(self, address: str) -> list[dict[str, Any]]: ...

    def process_for_host(self, host: str) -> list[dict[str, Any]]: ...

    def api_for_process(self, process: str) -> list[dict[str, Any]]: ...

    def library_for_api(self, api: str, process: str = "") -> list[dict[str, Any]]: ...

    def key_for_library(self, library: str) -> list[dict[str, Any]]: ...


@dataclass
class StaticResolver:
    """A resolver over rows already in memory — the shape tests and fixtures use."""

    rows: Mapping[str, Iterable[Mapping[str, Any]]] = field(default_factory=dict)
    captured_at: str | None = None

    def _find(self, kind: str, key: str, value: str) -> list[dict[str, Any]]:
        return [{**dict(row), "captured_at": row.get("captured_at") or self.captured_at}
                for row in self.rows.get(kind) or ()
                if isinstance(row, Mapping) and _norm(row.get(key)) == _norm(value)]

    def host_for_address(self, address: str) -> list[dict[str, Any]]:
        return self._find("hosts", "ip", address)

    def process_for_host(self, host: str) -> list[dict[str, Any]]:
        return self._find("processes", "host", host)

    def api_for_process(self, process: str) -> list[dict[str, Any]]:
        return self._find("apis", "process", process)

    def library_for_api(self, api: str, process: str = "") -> list[dict[str, Any]]:
        rows = self._find("libraries", "api", api)
        return rows or self._find("libraries", "process", process)

    def key_for_library(self, library: str) -> list[dict[str, Any]]:
        return self._find("keys", "library", library)


@dataclass
class SqlResolver:
    """The tenant-scoped SQL resolver over the tables the platform already holds.

    It reads five tables and computes nothing: a hop is a row that names both ends. A session
    is injected rather than opened here, so tenancy is the caller's (already enforced) context
    and this class cannot widen it.
    """

    session: Any
    tenant: str | None = None
    limit: int = 200

    def _rows(self, model: Any, *criteria: Any) -> list[Any]:
        query = self.session.query(model)
        for criterion in criteria:
            query = query.filter(criterion)
        return query.limit(self.limit).all()

    # -- hops --------------------------------------------------------------- #
    def host_for_address(self, address: str) -> list[dict[str, Any]]:
        from db.models.runtime_finding import RuntimeFinding

        value = _norm(address)
        rows: list[dict[str, Any]] = []
        for row in self._rows(RuntimeFinding, RuntimeFinding.hostname == value):
            rows.append({"ip": address, "host": row.hostname,
                         "evidence_id": f"runtime:{row.id}",
                         "captured_at": _iso(getattr(row, "last_seen_at", None)),
                         "basis": "agent-inventory"})
        if rows:
            return rows
        # an address is not an identity: a host that names it in its attributes is a candidate,
        # and two candidates stay two candidates (the correlate step reports AMBIGUOUS)
        from db.models.hardware_live import HardwareAsset

        for row in self._rows(HardwareAsset, HardwareAsset.asset_id == value):
            rows.append({"ip": address, "host": row.asset_id,
                         "evidence_id": f"hardware:{row.asset_id}",
                         "captured_at": _iso(getattr(row, "last_seen", None)),
                         "basis": "agent-inventory"})
        return rows

    def process_for_host(self, host: str) -> list[dict[str, Any]]:
        from db.models.runtime_finding import RuntimeFinding

        rows: list[dict[str, Any]] = []
        for row in self._rows(RuntimeFinding, RuntimeFinding.hostname == _norm(host)):
            name = _norm(getattr(row, "process_name", ""))
            if not name:
                continue
            rows.append({"host": host, "process": name,
                         "evidence_id": f"runtime:{row.id}",
                         "captured_at": _iso(getattr(row, "last_seen_at", None)),
                         "basis": "process-trace"})
        return rows

    def api_for_process(self, process: str) -> list[dict[str, Any]]:
        from db.models.runtime_finding import RuntimeFinding

        rows: list[dict[str, Any]] = []
        for row in self._rows(RuntimeFinding, RuntimeFinding.process_name == _norm(process)):
            extra = getattr(row, "extra", None) or {}
            api = _norm(extra.get("api") or extra.get("api_id") or extra.get("route"))
            if not api:
                continue
            rows.append({"process": process, "api": api,
                         "evidence_id": f"runtime:{row.id}",
                         "captured_at": _iso(getattr(row, "last_seen_at", None)),
                         "basis": "agent-inventory"})
        return rows

    def library_for_api(self, api: str, process: str = "") -> list[dict[str, Any]]:
        """A library loaded by a process, from the runtime collector's own rows.

        The platform records *process → library* (``runtime_findings.extra.library``), and it
        records an API on the process when a collector could name one
        (``extra.api``). It does not record *API → library* as a first-class edge, so this
        lookup uses the process as the join when the API is unknown — and says so in the row,
        rather than inventing an edge the estate does not hold.
        """
        from db.models.runtime_finding import RuntimeFinding

        rows: list[dict[str, Any]] = []
        for row in self._rows(RuntimeFinding):
            extra = getattr(row, "extra", None) or {}
            if not isinstance(extra, Mapping):
                continue
            api_match = _norm(extra.get("api") or extra.get("api_id")) == _norm(api)
            process_match = bool(process) and _norm(row.process_name) == _norm(process)
            if not api_match and not process_match:
                continue
            name = _norm(extra.get("library") or extra.get("library_name"))
            if not name:
                continue
            rows.append({"api": api or _norm(row.process_name), "library": name,
                         "version": _norm(extra.get("library_version")) or None,
                         "joined_on": "api" if api_match else "process",
                         "evidence_id": f"runtime:{row.id}",
                         "captured_at": _iso(getattr(row, "last_seen_at", None)),
                         "basis": "agent-inventory"})
        return rows

    def key_for_library(self, library: str) -> list[dict[str, Any]]:
        from db.models.payment_crypto import PaymentKey

        rows: list[dict[str, Any]] = []
        for row in self._rows(PaymentKey):
            note = _norm(getattr(row, "notes", ""))
            if _norm(library) not in note.lower() and _norm(library).lower() != \
                    _norm(getattr(row, "hsm_device", "")).lower():
                continue
            rows.append({"library": library, "hsm": _norm(getattr(row, "hsm_device", "")) or None,
                         "key_label": _norm(getattr(row, "name", "")) or None,
                         "evidence_id": f"key:{getattr(row, 'key_id', '')}",
                         "captured_at": _iso(getattr(row, "updated_at", None)),
                         "basis": "api-poll"})
        return rows


def _iso(value: Any) -> str | None:
    moment = _moment(value)
    return moment.isoformat() if moment else None


def resolve_with(resolver: InventoryResolver, *, window: Window | None = None,
                 address: str, strict: bool = False) -> dict[str, Any]:
    """Run the five lookups, classify each hop in time, and return the rows to correlate.

    ``strict`` drops every hop that is not ``IN_WINDOW`` and names it in ``dropped``; a caller
    that wants the path *as it was at the event* sets it and accepts a shorter answer. Without
    ``strict`` a stale hop is kept for the narrative and reported in ``stale``, which the
    correlation output flags so a reader is never told a 06:00 inventory describes 09:14.
    """
    window = window or Window()
    dropped: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    seen = {"hosts": [], "processes": [], "apis": [], "libraries": [], "keys": []}

    def keep(bucket: str, rows: list[dict[str, Any]], hop: str) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        for row in rows:
            state = window.classify(row.get("captured_at"))
            row = {**row, "window_state": state}
            if state != IN_WINDOW:
                (stale if state in {STALE, UNKNOWN_TIME} else dropped).append(
                    {"hop": hop, "state": state, "subject": row.get(hop_key(hop)),
                     "captured_at": row.get("captured_at")})
                if strict:
                    continue
            kept.append(row)
        seen[bucket].extend(kept)
        return kept

    hosts = keep("hosts", list(resolver.host_for_address(address)), "hosts")
    host = _single(hosts, "host")
    processes = keep("processes", list(resolver.process_for_host(host)), "processes") if host else []
    process = _single(processes, "process")
    apis = keep("apis", list(resolver.api_for_process(process)), "apis") if process else []
    api = _single(apis, "api")
    libraries = keep("libraries", list(resolver.library_for_api(api, process)), "libraries") \
        if api else []
    library = _single(libraries, "library")
    # the key hop is collected (and counted in ``seen``) for the answer's narrative; the
    # correlation itself reads it from ``rows``
    keep("keys", list(resolver.key_for_library(library)), "keys") if library else []
    return {
        "resolved": any(seen.values()),
        "rows": seen,
        "window": window.as_dict(),
        "stale": stale,
        "dropped_after_event": dropped,
        "strict": strict,
        "note": ("a hop outside the window is named: an inventory is a statement about a "
                 "moment, and correlating a 09:14 alert to a 06:00 process list is an "
                 "assumption, not a fact"),
    }


def _single(rows: list[dict[str, Any]], key: str) -> str:
    values = {_norm(row.get(key)) for row in rows if _norm(row.get(key))}
    return values.pop() if len(values) == 1 else ""


def hop_key(hop: str) -> str:
    return {"hosts": "host", "processes": "process", "apis": "api",
            "libraries": "library", "keys": "hsm"}.get(hop, hop)


def correlate_from_inventory(event: Mapping[str, Any], resolver: InventoryResolver, *,
                             window: Window | None = None, strict: bool = False) -> dict[str, Any]:
    """``correlate_event`` over a resolver, with the window carried into the answer."""
    from .correlate import correlate_event

    address = _norm(event.get("src") or event.get("source"))
    if not address:
        raise ControlRefused("NO_SOURCE_ADDRESS",
                             "an event with no source address has no path to resolve")
    resolved = resolve_with(resolver, window=window, address=address, strict=strict)
    rows = resolved["rows"]
    result = correlate_event(
        event,
        hosts=rows["hosts"], processes=rows["processes"], apis=rows["apis"],
        libraries=rows["libraries"], hsms=rows["keys"],
    )
    result["inventory"] = {
        "source": "resolver" if resolved["resolved"] else "empty",
        "window": resolved["window"],
        "stale": resolved["stale"],
        "dropped_after_event": resolved["dropped_after_event"],
        "strict": strict,
        "note": resolved["note"],
    }
    if resolved["stale"]:
        result["unresolved"] = list(result["unresolved"]) + [{
            "hop": row["hop"], "code": "STALE_EVIDENCE", "subject": row["subject"],
            "captured_at": row["captured_at"],
            "reason": (f"the evidence for this hop was captured at {row['captured_at']}, "
                       f"outside the {resolved['window']['max_age_seconds']}s window that "
                       "opens at the event; it is reported, not used as proof"),
        } for row in resolved["stale"]]
    result["trustworthy"] = (result["answerable"] and not resolved["stale"]
                            and bool(result["resolved_hops"]))
    return result
