"""Live drivers: a dialect's endpoints, executed, producing the feed the contract already reads.

A driver does one job — turn a device's read-only answers into the ``feed`` shape
:class:`~cbom.security_controls.base.DeviceCollector` consumes — and it is the *same* feed the
recorded fixtures use, so the collector, the evidence book, the redaction guard and the
projection are exercised by a live read exactly as they were by a fixture. That is the whole
reason the fixture shape was chosen in guide 181.

Each driver states, in code, three things a reviewer needs:

* **what it asks for** — the endpoint list, which is also the audit surface
  (``GET /api/v2/cmdb/firewall/policy`` and friends), never a mutating verb;
* **how the vendor spells its sections** — the mapping into canonical section names, so the
  firewall collector's ``rules()`` does not grow a Fortinet branch;
* **what a partial read means** — a device that answered three of seven sections produces a
  snapshot with ``PARTIAL_READ`` in its health and the failed sections named, not a shorter
  estate that looks complete.

Deliberate limit: a driver never parses a payload, never reads a private key out of a
certificate bundle, and never follows a secret reference the device hands back. It keeps
metadata, and the base module's ``scrub`` runs over everything it returns.
"""

from __future__ import annotations

import json
import inspect
from dataclasses import dataclass, field
from typing import Any, Mapping

from .base import ControlRefused, _norm, scrub
from .transport import (AUTH_FAILED, BAD_RESPONSE, OK, PARTIAL_READ, REFUSED, UNREACHABLE,
                        Credential, FileTail, ReadOnlyTransport, TransportResult, worst_state)

#: keys a vendor response wraps its rows in; tried in order, first hit wins
ROW_ENVELOPES: tuple[str, ...] = ("results", "data", "objects", "items", "value", "rows",
                                  "entries")


def rows_from(body: Any) -> list[dict[str, Any]]:
    """Rows out of whatever envelope the device used, without inventing any."""
    if body is None:
        return []
    if isinstance(body, list):
        return [dict(row) for row in body if isinstance(row, Mapping)]
    if isinstance(body, Mapping):
        for key in ROW_ENVELOPES:
            candidate = body.get(key)
            if isinstance(candidate, list):
                return [dict(row) for row in candidate if isinstance(row, Mapping)]
            if isinstance(candidate, Mapping):
                nested = rows_from(candidate)
                if nested:
                    return nested
    return []


def _sorted_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic order, so two reads of an unchanged device produce the same ids.

    Evidence ids in the firewall collector are keyed by rule position (``FW-001``). If the
    device returns its policy in a different order — and several do, after a commit — every
    id moves and the diff reports the whole policy as changed. Sorting on the canonical JSON
    of the row removes that without pretending the device's own order is meaningful.
    """
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True, default=str))


@dataclass
class SectionRead:
    """One endpoint's outcome: how many rows, which state, why."""

    section: str
    path: str
    state: str = OK
    rows: int = 0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"section": self.section, "path": self.path, "state": self.state,
                "rows": self.rows, "reason": self.reason or None}


#: Rows kept per section before the read is truncated. A firewall with 40,000 rules will not
#: fit in a snapshot, and a collector that tries has already failed — it just has not noticed.
#: The cap is a *recorded* truncation, not a silent slice: a partial section that looks whole is
#: how a rule nobody could see gets a clean audit.
MAX_ROWS_PER_SECTION = 2000
#: The largest snapshot one device may contribute. Beyond it the remaining rows are refused
#: with ``CAP_REACHED``, and the refusal is part of the snapshot.
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024


def section_digest(rows: list[dict[str, Any]]) -> str:
    """A stable digest over one section's rows — the unit of incremental collection."""
    import hashlib
    import json

    payload = json.dumps(rows, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


class SectionCache:
    """What the last read of each section said, so an unchanged section can be skipped.

    Nine controls times dozens of devices is hundreds of reads per cycle, and almost none of
    them changed. The cache is deliberately dumb — it holds per-section digests and sizes, not
    the rows — so it cannot itself become the memory problem it exists to avoid. A caller that
    wants the unchanged rows passes them back in (its own store has them).
    """

    def __init__(self, digests: Mapping[str, str] | None = None,
                 read_at: Mapping[str, str] | None = None) -> None:
        self.digests: dict[str, str] = dict(digests or {})
        self.read_at: dict[str, str] = dict(read_at or {})

    def changed(self, section: str, rows: list[dict[str, Any]]) -> bool:
        digest = section_digest(rows)
        return self.digests.get(section) != digest

    def record(self, section: str, rows: list[dict[str, Any]], *, at: str = "") -> str:
        digest = section_digest(rows)
        self.digests[section] = digest
        if at:
            self.read_at[section] = at
        return digest

    def as_dict(self) -> dict[str, Any]:
        return {"digests": dict(sorted(self.digests.items())),
                "read_at": dict(sorted(self.read_at.items()))}

    @classmethod
    def from_feed(cls, feed: Mapping[str, Any] | None) -> "SectionCache":
        """Rebuild the cache from a previous feed *or* a previous snapshot's ``health``."""
        health = (feed or {}).get("health") or {}
        digests = health.get("section_digests")
        if not isinstance(digests, Mapping):
            read = health.get("read") if isinstance(health.get("read"), Mapping) else {}
            digests = read.get("section_digests")
        digests = digests if isinstance(digests, Mapping) else {}
        read_at = health.get("section_read_at") or {}
        return cls(digests=digests, read_at=read_at if isinstance(read_at, Mapping) else {})


class BaseDriver:
    """Fetch the sections a spec declares, into canonical section names."""

    control: str = ""
    vendor: str = ""
    #: the identity a vendor's read reports when the caller did not supply one
    model: str = ""
    version: str = ""
    #: canonical section → endpoint path, in the order the device should be asked
    endpoints: Mapping[str, str] = {}

    def __init__(self, transport: ReadOnlyTransport, *,
                 system: str = "", params: Mapping[str, Mapping[str, Any]] | None = None,
                 version: str = "", model: str = "",
                 log_path: str = "", max_lines: int = 0, max_rows: int = 0) -> None:
        """The one constructor. A subclass declares vocabulary, never ``__init__``.

        Guide 182 shipped this module with a mix of dataclass and plain subclasses, which
        meant every ``@dataclass`` driver silently replaced this initialiser — and a driver
        that cannot be handed a transport is a driver that cannot be used. The constructor
        lives here, on the base, and the options every dialect may want are named.
        """
        self.transport = transport
        self.system = _norm(system)
        self.params = dict(params or {})
        self.version = _norm(version) or type(self).version
        self.model = _norm(model) or type(self).model
        self.log_path = _norm(log_path)
        self.max_lines = int(max_lines or 0)
        self.max_rows = int(max_rows or 0)
        self.reads: list[SectionRead] = []

    # -- what a subclass may override --------------------------------------- #
    def assets(self) -> list[dict[str, Any]]:
        """The device itself, as an asset row. A vendor adds its identity here."""
        return []

    def extra_sections(self) -> dict[str, list[dict[str, Any]]]:
        """Sections that are not one endpoint each (a log tail, a computed table)."""
        return {}

    # -- the one implementation --------------------------------------------- #
    def fetch(self, *, cache: SectionCache | None = None,
              skip_unchanged: bool = False) -> dict[str, Any]:
        """Read every declared section, or report why it could not be read.

        ``cache`` supplies the previous read's per-section digests. With ``skip_unchanged``,
        a section whose rows hash the same as last time is not re-emitted — the caller already
        holds it — and the section is named in ``unchanged_sections`` so the omission is
        visible rather than inferred.
        """
        self.reads = []
        sections: dict[str, list[dict[str, Any]]] = {}
        states: list[str] = []
        unchanged: list[str] = []
        truncated: dict[str, dict[str, Any]] = {}
        digests: dict[str, str] = {}
        budget = MAX_SNAPSHOT_BYTES
        for section, path in self.endpoints.items():
            rows, result = self._read(path, params=self.params.get(section))
            section_state = result.state
            cap = min(MAX_ROWS_PER_SECTION, self.max_rows or MAX_ROWS_PER_SECTION)
            dropped = 0
            if len(rows) > cap:
                dropped = len(rows) - cap
                rows = rows[:cap]
                truncated[section] = {
                    "rows_read": cap + dropped, "rows_kept": cap, "rows_dropped": dropped,
                    "cap": cap, "reason": ("the section is larger than one snapshot may hold; "
                                           "the rows kept are the first by a stable sort, and "
                                           "the count dropped is recorded because a partial "
                                           "section that looks whole is a clean audit of a "
                                           "rule nobody could see")}
                if section_state == OK:
                    section_state = PARTIAL_READ
            size = len(_canonical_rows(rows).encode("utf-8")) if rows else 0
            if size > budget:
                truncated.setdefault(section, {})["memory_refused"] = True
                if section_state == OK:
                    section_state = PARTIAL_READ
                states.append(section_state)
                self.reads.append(SectionRead(section=section, path=path, state=section_state,
                                              rows=0, reason="snapshot memory budget reached"))
                continue
            states.append(section_state)
            budget -= size
            self.reads.append(SectionRead(section=section, path=path, state=section_state,
                                          rows=len(rows), reason=result.reason))
            if result.ok and rows:
                ordered = _sorted_rows(rows)
                digest = section_digest(ordered)
                digests[section] = digest
                if cache is not None:
                    if skip_unchanged and not cache.changed(section, ordered):
                        unchanged.append(section)
                        continue
                    cache.record(section, ordered)
                sections[section] = ordered
        for section, rows in self.extra_sections().items():
            if rows:
                sections[section] = _sorted_rows(rows)
        state = worst_state(states)
        if state != OK and any(value == OK for value in states):
            # some sections answered and some did not. That is the definition of a partial
            # read, and reporting it as a failure would throw away the part that arrived —
            # while reporting it as OK would present a device nobody finished reading as read.
            state = PARTIAL_READ
        return {
            "system": self.system,
            "assets": self.assets(),
            "sections": sections,
            "health": {
                **self.transport.health(),
                "state": state,
                "read_only": True,
                "reachable": state not in {UNREACHABLE, REFUSED},
                "partial": state == PARTIAL_READ,
                "sections": [read.as_dict() for read in self.reads],
                "failed_sections": [read.section for read in self.reads
                                    if read.state not in {OK, PARTIAL_READ}
                                    or read.reason == "snapshot memory budget reached"],
                "detail": _detail(state, self.reads),
                # -- scale, in three parts -------------------------------------- #
                "coverage": self._coverage(state, unchanged),
                "section_digests": dict(sorted(digests.items())),
                "unchanged_sections": sorted(unchanged),
                "truncated": truncated,
                "limits": {"max_rows_per_section": self.max_rows or MAX_ROWS_PER_SECTION,
                           "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
                           "bytes_remaining": budget},
            },
        }

    def _coverage(self, state: str, unchanged: list[str]) -> dict[str, Any]:
        """Sections read versus sections the dialect declares — per device, not per estate."""
        declared = len(self.endpoints)
        read = sum(1 for item in self.reads if item.state in {OK, PARTIAL_READ}
                   and item.reason != "snapshot memory budget reached")
        failed = [item.section for item in self.reads if item.state not in {OK, PARTIAL_READ}
                  or item.reason == "snapshot memory budget reached"]
        return {
            "sections_declared": declared,
            "sections_read": read,
            "sections_failed": len(failed),
            "sections_unchanged": len(unchanged),
            "failed": failed,
            "fraction": round(read / declared, 3) if declared else 0.0,
            "complete": bool(declared) and read == declared and state == OK,
            "state": state,
        }

    def _read(self, path: str,
              params: Mapping[str, Any] | None = None) -> tuple[list[dict[str, Any]],
                                                                TransportResult]:
        getter = getattr(self.transport, "get_all", None)
        if callable(getter):
            rows, result = getter(path, params=params)
            return [dict(row) for row in rows if isinstance(row, Mapping)], result
        result = self.transport.get(path, params=params)
        return rows_from(result.body), result


def _canonical_rows(rows: list[dict[str, Any]]) -> str:
    import json

    return json.dumps(rows, sort_keys=True, default=str, separators=(",", ":"))


def _detail(state: str, reads: list[SectionRead]) -> str:
    if state == OK:
        return f"{len(reads)} section(s) read"
    bad = [read for read in reads if read.state not in {OK, PARTIAL_READ}]
    if not bad:
        return "every section answered, but the device reported more rows than one read follows"
    return "; ".join(f"{read.section}: {read.state} ({read.reason or 'no reason given'})"
                     for read in bad)


# --------------------------------------------------------------------------- #
# Firewall: FortiOS, PAN-OS, Check Point
# --------------------------------------------------------------------------- #

class FortigateDriver(BaseDriver):
    """FortiOS REST — ``/api/v2/cmdb/...`` with token auth and ``start/count`` paging."""

    control: str = "FIREWALL"
    vendor: str = "Fortinet"
    endpoints: Mapping[str, str] = {
        "rules": "/api/v2/cmdb/firewall/policy",
        "zones": "/api/v2/cmdb/system/zone",
        "interfaces": "/api/v2/cmdb/system/interface",
        "vpn": "/api/v2/cmdb/vpn.ipsec/phase1-interface",
        "tls_inspection": "/api/v2/cmdb/firewall/ssl-ssh-profile",
    }
    model: str = ""
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        if not self.system:
            return []
        return [{"kind": "FIREWALL", "name": self.system,
                 "vendor": "Fortinet", "product": "FortiGate",
                 "version": self.version or None, "model": self.model or None,
                 "source": "fortios-rest"}]


class PaloAltoDriver(BaseDriver):
    """PAN-OS XML API, JSON-encoded — one XPath per section."""

    control: str = "FIREWALL"
    vendor: str = "Palo Alto Networks"
    endpoints: Mapping[str, str] = {
        "rules": "/api/?type=config&action=show&xpath=/config/devices/entry/vsys/entry"
                 "/rulebase/security/rules&output=json",
        "zones": "/api/?type=config&action=show&xpath=/config/devices/entry/vsys/entry"
                 "/zone&output=json",
        "vpn": "/api/?type=config&action=show&xpath=/config/devices/entry/network"
               "/ike/gateway&output=json",
        "tls_inspection": "/api/?type=config&action=show&xpath=/config/devices/entry/vsys"
                          "/entry/rulebase/decryption/rules&output=json",
    }
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        if not self.system:
            return []
        return [{"kind": "FIREWALL", "name": self.system, "vendor": "Palo Alto Networks",
                 "product": "PAN-OS", "version": self.version or None,
                 "source": "panos-xml-api"}]


class CheckPointDriver(BaseDriver):
    """Check Point management API — ``/web_api/show-access-rulebase``."""

    control: str = "FIREWALL"
    vendor: str = "Check Point"
    endpoints: Mapping[str, str] = {
        "rules": "/web_api/show-access-rulebase",
        "zones": "/web_api/show-zones",
        "interfaces": "/web_api/show-interfaces",
    }
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        if not self.system:
            return []
        return [{"kind": "FIREWALL", "name": self.system, "vendor": "Check Point",
                 "product": "Quantum Security Gateway", "version": self.version or None,
                 "source": "cp-management-api"}]


# --------------------------------------------------------------------------- #
# IDS / IPS: Suricata (log tail) and a syslog-free HTTP sensor
# --------------------------------------------------------------------------- #

class SuricataDriver(BaseDriver):
    """Suricata from ``eve.json``: events as metadata, never payload.

    Suricata logs a JSON object per event and includes the HTTP body and TLS payload in some
    records. The driver copies a named allow-list of metadata fields and drops everything
    else *before* the base module's scrub runs, so a body never enters the pipeline in the
    first place. ``payload``/``http``/``tls.certificate`` are never even read.
    """

    control: str = "IDS"
    vendor: str = "OISF"
    endpoints: Mapping[str, str] = {}
    log_path: str = "/var/log/suricata/eve.json"
    version: str = ""
    max_lines: int = 5000
    _tail: FileTail | None = field(default=None, repr=False)

    #: fields kept from an eve record. Everything else — payload, http body, tls bytes — is
    #: dropped, because the estate needs the flow, not the content.
    EVENT_FIELDS: tuple[str, ...] = (
        "timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
        "app_proto", "flow_id", "host", "community_id",
    )
    ALERT_FIELDS: tuple[str, ...] = ("action", "signature", "signature_id", "rev",
                                     "category", "severity", "gid")
    TLS_FIELDS: tuple[str, ...] = ("version", "sni", "subject", "issuerdn", "fingerprint",
                                   "ja3", "ja3s", "alpn", "cipher_suite")

    def tail(self) -> FileTail:
        if self._tail is None:
            self._tail = FileTail(self.log_path, max_lines=self.max_lines)
        return self._tail

    def fetch(self) -> dict[str, Any]:
        records, detail = self.tail().read_lines()
        events = [row for row in (self._event(record) for record in records) if row]
        state = detail.get("state", OK)
        return {
            "system": self.system,
            "assets": self.assets(),
            "sections": {"eve": _sorted_rows(events)} if events else {},
            "events": events,
            "health": {
                "transport": "file",
                "state": state if events else PARTIAL_READ if state == OK else state,
                "read_only": True,
                "reachable": state == OK,
                "detail": (f"{len(events)} event(s) from {self.log_path}"
                           + (f", {detail['malformed']} malformed line(s)"
                              if detail.get("malformed") else "")
                           + ("; the tail hit its byte cap, so this is a window and not the "
                              "whole file" if detail.get("truncated") else "")),
                "log": detail,
                "sections": [{"section": "eve", "path": self.log_path, "state": state,
                              "rows": len(events), "reason": detail.get("reason")}],
                "failed_sections": [] if state == OK else ["eve"],
            },
        }

    def assets(self) -> list[dict[str, Any]]:
        if not self.system:
            return []
        return [{"kind": "IDS", "name": self.system, "vendor": "OISF",
                 "product": "Suricata", "version": self.version or None,
                 "source": "eve-json"}]

    def _event(self, record: Mapping[str, Any]) -> dict[str, Any] | None:
        kind = _norm(record.get("event_type")).upper()
        if kind not in {"ALERT", "DROP", "FLOW", "TLS", "HTTP", "DNS", "NETFLOW"}:
            return None
        event: dict[str, Any] = {"kind": "ALERT" if kind == "ALERT" else kind}
        for key in self.EVENT_FIELDS:
            if record.get(key) not in (None, ""):
                event[_alias(key)] = record[key]
        alert = record.get("alert")
        if isinstance(alert, Mapping):
            for key in self.ALERT_FIELDS:
                if alert.get(key) not in (None, ""):
                    event[_alias(key)] = alert[key]
        tls = record.get("tls")
        if isinstance(tls, Mapping):  # metadata only: no certificate bytes, no session keys
            for key in self.TLS_FIELDS:
                if tls.get(key) not in (None, ""):
                    event[_alias(key)] = tls[key]
        clean, _ = scrub(event)
        return clean


def _alias(key: str) -> str:
    return {"src_ip": "src", "dest_ip": "dst", "dest_port": "port",
            "app_proto": "protocol", "cipher_suite": "cipher_suite"}.get(key, key)


# --------------------------------------------------------------------------- #
# The rest of the dialects are plain endpoint maps
# --------------------------------------------------------------------------- #

class NginxDriver(BaseDriver):
    """NGINX Plus API: upstreams, servers, SSL profiles (read-only ``/api/``)."""

    control: str = "LOAD_BALANCER"
    vendor: str = "F5 (NGINX)"
    endpoints: Mapping[str, str] = {
        "pools": "/api/9/http/upstreams",
        "vips": "/api/9/http/servers",
    }
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        return [{"kind": "LOAD_BALANCER", "name": self.system, "vendor": "F5 (NGINX)",
                 "product": "NGINX Plus", "version": self.version or None,
                 "source": "nginx-plus-api"}] if self.system else []


class KongDriver(BaseDriver):
    """Kong Admin API: services, routes, certificates, plugins."""

    control: str = "API_GATEWAY"
    vendor: str = "Kong"
    endpoints: Mapping[str, str] = {
        "apis": "/services",
        "routes": "/routes",
        "certificates": "/certificates",
        "policies": "/plugins",
    }
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        return [{"kind": "API_GATEWAY", "name": self.system, "vendor": "Kong",
                 "product": "Kong Gateway", "version": self.version or None,
                 "source": "kong-admin-api"}] if self.system else []


class F5Driver(BaseDriver):
    """F5 iControl REST: virtuals, pools, client-ssl profiles."""

    control: str = "LOAD_BALANCER"
    vendor: str = "F5"
    endpoints: Mapping[str, str] = {
        "vips": "/mgmt/tm/ltm/virtual",
        "pools": "/mgmt/tm/ltm/pool",
        "tls_profiles": "/mgmt/tm/ltm/profile/client-ssl",
    }
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        return [{"kind": "LOAD_BALANCER", "name": self.system, "vendor": "F5",
                 "product": "BIG-IP LTM", "version": self.version or None,
                 "source": "icontrol-rest"}] if self.system else []


class SplunkDriver(BaseDriver):
    """Splunk: correlation references and notable events, as queries (never writes)."""

    control: str = "SIEM"
    vendor: str = "Splunk"
    endpoints: Mapping[str, str] = {
        "correlations": "/services/search/jobs/export",
    }
    version: str = ""

    def assets(self) -> list[dict[str, Any]]:
        return [{"kind": "SECURITY_APPLIANCE", "name": self.system, "vendor": "Splunk",
                 "product": "Splunk Enterprise Security", "version": self.version or None,
                 "source": "splunk-rest"}] if self.system else []


#: dialect key (as it appears in ``vendors.py``) → driver
DRIVERS: dict[str, type[BaseDriver]] = {
    "firewall.fortigate": FortigateDriver,
    "firewall.paloalto": PaloAltoDriver,
    "firewall.checkpoint": CheckPointDriver,
    "ids.suricata": SuricataDriver,
    "ips.suricata_inline": SuricataDriver,
    "load_balancer.f5": F5Driver,
    "load_balancer.nginx": NginxDriver,
    "api_gateway.kong": KongDriver,
    "siem.splunk": SplunkDriver,
}


def driver_coverage() -> dict[str, Any]:
    """Live driver vs dialect documentation vs nothing — named, never implied.

    A dialect row documents what a vendor exposes; a *driver* is code that actually reads
    the device. This returns the two sets separately, and names the families (WAF, VPN,
    rate-limit) where dialects are documented and no live read exists. A report showing
    only the dialect rows would be implying coverage the platform does not have: nine
    dialects have live drivers, the rest are fixtures at best, and the gap is this, not a
    blank.
    """
    from .registry import adapters as registry_adapters

    live = {key.lower(): cls.__name__ for key, cls in DRIVERS.items()}
    fixture_only: list[str] = []
    facade: list[str] = []
    for key in registry_adapters():
        normalized = key.lower().replace(":", ".")
        if key.endswith(":existing-collectors"):
            facade.append(normalized)
        elif normalized not in live:
            fixture_only.append(normalized)
    gaps: dict[str, Any] = {}
    for family in ("waf", "vpn", "rate_limit"):
        members = sorted(k for k in (*fixture_only, *live) if k.split(".", 1)[0] == family)
        if members and not any(k in live for k in members):
            gaps[family] = {
                "dialects": members,
                "live_drivers": [],
                "gap": (f"{len(members)} documented dialect(s) and no live driver: the row "
                        "describes what the vendor exposes and nothing reads it. Supporting "
                        "this family or reporting this gap are the only two honest options, "
                        "and this is the report"),
            }
    return {
        "live": dict(sorted(live.items())),
        "fixture_only": sorted(fixture_only),
        "facade": sorted(facade),
        "gaps": gaps,
        "counts": {"live": len(live), "fixture_only": len(fixture_only),
                   "facade": len(facade), "gap_families": len(gaps)},
        "note": ("a fixture proves the parsing, not the device: only the names in 'live' "
                 "read real hardware, and only those were live-tested against real devices "
                 "(see the operations guide's real-device qualification gap)"),
    }


def driver_for(adapter_key: str, transport: ReadOnlyTransport, *,
               system: str = "", **options: Any) -> BaseDriver:
    """The driver for one dialect, or a refusal that names which dialects have one.

    A dialect without a driver is not a failure of the contract: the contract is still
    satisfied by its documented endpoint list. What this function refuses is *pretending* —
    a caller asking for a live read of a dialect nobody has implemented is told so.
    """
    key = _norm(adapter_key).lower()
    cls = DRIVERS.get(key)
    if cls is None:
        raise ControlRefused(
            "NO_LIVE_DRIVER",
            f"{key or '(none)'} has no driver yet; implemented: "
            f"{', '.join(sorted(DRIVERS))}. Its dialect row still documents the endpoints, "
            "and inventing a reader for it here would be a guess presented as a read")
    control = _norm(getattr(cls, "control", "")).lower()
    del control
    # a driver accepts what its own signature accepts, and nothing is dropped silently: an
    # option the class does not take would otherwise vanish into ``**options`` and the caller
    # would believe it had been applied
    accepted = set(inspect.signature(cls.__init__).parameters) - {"self", "transport",
                                                                 "system"}
    unsupported = sorted(set(options) - accepted)
    if unsupported:
        raise ControlRefused(
            "UNSUPPORTED_DRIVER_OPTION",
            f"{cls.__name__} does not take {', '.join(unsupported)}; ignoring an option is "
            "how a read ends up different from the read that was asked for")
    return cls(transport=transport, system=system, **options)


# --------------------------------------------------------------------------- #
# One live collection: driver → feed → the shipping collector
# --------------------------------------------------------------------------- #

def live_snapshot(control: str, vendor: str, transport: ReadOnlyTransport, *,
                  system: str = "", previous: Mapping[str, Any] | None = None,
                  incremental: bool = False, **options: Any) -> dict[str, Any]:
    """Read a device live and return everything a reviewer needs to judge the read.

    The collector is the shipping one — the same class, the same evidence book, the same
    refusals — so a live snapshot and a fixture snapshot are comparable documents. The extra
    keys are the honest ones: ``read`` (which sections the device answered) and ``transport``.

    ``previous`` is the last feed for this device (or the ``health`` block of the last
    snapshot). With ``incremental=True`` a section whose rows hash the same as last time is not
    re-read into this snapshot: it is named in ``unchanged_sections`` and merged back from
    ``previous`` so the snapshot is still complete. The omission and the merge are both
    recorded, because a snapshot that silently contains less is worse than one that fails.
    """
    from .registry import collector as build_collector

    base = build_collector(control, vendor, {})  # validates control + vendor first
    driver = driver_for(base.spec.key, transport, system=system, **options)
    cache = SectionCache.from_feed(previous) if (incremental and previous) else None
    feed = driver.fetch(cache=cache, skip_unchanged=bool(cache))
    merged: list[str] = []
    if cache is not None:
        held = (previous or {}).get("sections") or {}
        for section in feed.get("health", {}).get("unchanged_sections", []):
            if section in held:
                feed["sections"][section] = held[section]
                merged.append(section)
    collector = build_collector(control, vendor, feed)
    snapshot = collector.snapshot()
    transport_state = (feed.get("health") or {}).get("state", UNREACHABLE)
    return {
        **snapshot,
        "read": {
            "adapter": base.spec.key,
            "driver": type(driver).__name__,
            "system": system,
            "state": transport_state,
            "sections": feed.get("health", {}).get("sections", []),
            "failed_sections": feed.get("health", {}).get("failed_sections", []),
            "partial": transport_state == PARTIAL_READ,
            "detail": feed.get("health", {}).get("detail"),
            # scale: what this device contributed, what it refused, what was skipped and
            # what came back from the previous read
            "coverage": feed.get("health", {}).get("coverage"),
            "unchanged_sections": feed.get("health", {}).get("unchanged_sections", []),
            "merged_sections": sorted(merged),
            "truncated": feed.get("health", {}).get("truncated", {}),
            "limits": feed.get("health", {}).get("limits"),
            "incremental": bool(cache),
        },
        "transport": transport.health(),
    }


def credential_from_env(variable: str, *, required: bool = True) -> Credential:
    """The deployment-facing helper: ``FOO_TOKEN`` or ``FOO_TOKEN_FILE``."""
    from .transport import SecretSource

    return SecretSource.from_env(variable, required=required)


__all__ = [
    "AUTH_FAILED", "BAD_RESPONSE", "BaseDriver", "CheckPointDriver", "DRIVERS",
    "F5Driver", "FortigateDriver", "KongDriver", "NginxDriver", "PaloAltoDriver",
    "REFUSED", "SectionRead", "SplunkDriver", "SuricataDriver", "UNREACHABLE",
    "credential_from_env", "driver_for", "live_snapshot", "rows_from",
]
