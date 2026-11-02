"""Which application used the primitive — or an honest "nobody can say".

A session proves that RSA-2048 was exercised on `10.0.0.5:443`. It does not
prove that *Payments API* did it, and the difference is the one a payment
scheme auditor asks about. This module joins observed peers to a bank-supplied
endpoint register and returns one of four answers:

``ATTRIBUTED``
    one endpoint record, one application: the session belongs to it.
``PARTIAL``
    the endpoint is known but names no application, so the asset is identified
    and the workload is not.
``AMBIGUOUS``
    the endpoint is known and hosts four applications. All four are returned and
    none is chosen, because picking the first is how a report becomes wrong in a
    way nobody notices.
``UNATTRIBUTED``
    no record names the peer. It is not assigned to the nearest appliance, the
    busiest host or a default, and the sessions stay counted under "unknown
    workload" until somebody registers the endpoint.

The result carries a ``ledger`` of the partial and ambiguous answers in the
shape :func:`vendor_intel.vendor_evidence.partial_ledger` consumes, so an
attribution run cannot quietly lose the half-answers it produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

SCHEMA = "cryptoscan.usage-attribution/1"

ATTRIBUTION_STATES: tuple[str, ...] = ("ATTRIBUTED", "PARTIAL", "AMBIGUOUS", "UNATTRIBUTED")


@dataclass(frozen=True)
class Endpoint:
    """One registered address, and the workloads behind it.

    ``address`` is a hostname or an IP; ``port`` narrows it when one appliance
    runs several listeners with different owners. ``evidence`` is the record
    that says this address belongs to this application — a CMDB entry, a service
    register row — because an attribution with no citation is a guess with a
    provenance field.
    """

    address: str
    asset_id: str | None = None
    applications: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    port: int | None = None
    evidence: Any = None

    def __post_init__(self) -> None:
        if not str(self.address or "").strip():
            raise ValueError("an endpoint needs an address")
        object.__setattr__(self, "address", str(self.address).strip())
        object.__setattr__(self, "applications", tuple(self.applications))
        object.__setattr__(self, "services", tuple(self.services))

    def matches(self, host: str, port: int | None) -> bool:
        if _norm(host) != _norm(self.address):
            return False
        if self.port is None:
            return True
        return port is not None and int(port) == int(self.port)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def split_peer(peer: Any) -> tuple[str, int | None]:
    """``"10.0.0.5:443"`` -> ``("10.0.0.5", 443)``; a bare host keeps ``None``."""
    text = str(peer or "").strip()
    if not text:
        return "", None
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            return host.strip(), int(port)
    return text, None


def _peers(records: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    peers: dict[str, dict[str, Any]] = {}
    for record in records:
        peer = str(record.get("peer") or "").strip()
        if not peer:
            continue
        host, port = split_peer(peer)
        entry = peers.setdefault(peer, {"peer": peer, "host": host, "port": port,
                                        "sessions": 0})
        entry["sessions"] += 1
    return peers


def attribute_sessions(records: Iterable[Mapping[str, Any]],
                       endpoints: Iterable[Endpoint], *,
                       default_asset_id: str | None = None) -> dict[str, Any]:
    """Join peers to workloads and refuse to fill the blanks.

    ``default_asset_id`` is the asset the sessions were collected *from* (the
    appliance), not the workload that used it: an unknown peer keeps that asset
    and gains no application, which is ``UNATTRIBUTED`` rather than a guess.
    """
    endpoint_list = list(endpoints)
    peers = _peers(list(records))
    rows: list[dict[str, Any]] = []
    ledger: list[dict[str, Any]] = []
    totals: dict[str, int] = {state: 0 for state in ATTRIBUTION_STATES}
    for peer, entry in sorted(peers.items()):
        matched = [endpoint for endpoint in endpoint_list
                   if endpoint.matches(entry["host"], entry["port"])]
        applications = sorted({name for endpoint in matched for name in endpoint.applications})
        services = sorted({name for endpoint in matched for name in endpoint.services})
        assets = sorted({endpoint.asset_id for endpoint in matched if endpoint.asset_id})
        if not matched:
            state = "UNATTRIBUTED"
            reason = ("no endpoint record names this peer; the session stays counted under an "
                      "unknown workload rather than being assigned to the nearest appliance")
        elif len(matched) > 1:
            state = "AMBIGUOUS"
            reason = (f"{len(matched)} endpoint records claim this peer "
                      f"({', '.join(sorted(endpoint.address for endpoint in matched))})")
        elif not applications:
            state = "PARTIAL"
            reason = ("the endpoint is known and names no application, so the asset is "
                      "identified and the workload is not")
        elif len(applications) > 1:
            state = "AMBIGUOUS"
            reason = (f"the endpoint hosts {len(applications)} applications; a session on a "
                      "shared appliance cannot say which one used the primitive")
        else:
            state = "ATTRIBUTED"
            reason = f"one endpoint record and one application: {applications[0]}"
        if not assets and default_asset_id:
            assets = [default_asset_id]
        totals[state] += 1
        rows.append({
            "peer": peer,
            "state": state,
            "sessions": entry["sessions"],
            "asset_ids": assets,
            "applications": applications,
            "services": services,
            "endpoint_evidence": [endpoint.evidence.evidence_id
                                  for endpoint in matched if endpoint.evidence is not None],
            "reason": reason,
        })
        if state in {"PARTIAL", "AMBIGUOUS", "UNATTRIBUTED"}:
            ledger.append({"state": "PARTIAL" if state == "PARTIAL" else state,
                           "subject": peer, "reasons": [reason]})
    attributed_sessions = sum(row["sessions"] for row in rows if row["state"] == "ATTRIBUTED")
    total_sessions = sum(row["sessions"] for row in rows)
    return {
        "schema": SCHEMA,
        "peers": len(rows),
        "sessions": total_sessions,
        "attributed_sessions": attributed_sessions,
        "counts": totals,
        "rows": rows,
        "ledger": ledger,
        "applications": sorted({name for row in rows if row["state"] == "ATTRIBUTED"
                                for name in row["applications"]}),
        "statement": (
            f"{attributed_sessions} of {total_sessions} session(s) are attributed to a single "
            f"application; {totals['AMBIGUOUS']} peer(s) are ambiguous, "
            f"{totals['PARTIAL']} name an asset but no application and "
            f"{totals['UNATTRIBUTED']} are unknown workloads"),
    }


def workload_summary(attribution: Mapping[str, Any]) -> dict[str, Any]:
    """Per-application session counts, with the unattributed remainder kept.

    The remainder is a line in the output, not a rounding difference: a
    workload table that adds up to 100% while a third of the sessions are
    unattributed is the most comfortable lie a VBOM can tell.
    """
    per_application: dict[str, int] = {}
    for row in attribution.get("rows") or ():
        if row["state"] != "ATTRIBUTED":
            continue
        for application in row["applications"]:
            per_application[application] = per_application.get(application, 0) + row["sessions"]
    remainder = sum(row["sessions"] for row in attribution.get("rows") or ()
                    if row["state"] != "ATTRIBUTED")
    total = attribution.get("sessions", 0) or 0
    return {
        "applications": dict(sorted(per_application.items())),
        "unattributed_sessions": remainder,
        "total_sessions": total,
        "coverage": round(100.0 * (total - remainder) / total, 1) if total else 0.0,
        "statement": (
            f"{total - remainder} of {total} session(s) map to a named application"
            + (f"; {remainder} do not, and are reported as an unknown workload rather than "
               "spread across the applications that were identified" if remainder else "")),
    }


def endpoints_from_inventory(rows: Sequence[Mapping[str, Any]]) -> list[Endpoint]:
    """Build endpoints from a register export: address, asset, applications, evidence."""
    endpoints: list[Endpoint] = []
    for row in rows:
        address = row.get("address") or row.get("host") or row.get("ip")
        if not address:
            raise ValueError("an endpoint row needs an address")
        endpoints.append(Endpoint(
            address=str(address),
            asset_id=row.get("asset_id"),
            applications=tuple(row.get("applications") or ()),
            services=tuple(row.get("services") or ()),
            port=int(row["port"]) if row.get("port") not in (None, "") else None,
            evidence=row.get("evidence"),
        ))
    return endpoints
