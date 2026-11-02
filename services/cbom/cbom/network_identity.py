"""Network asset identity: an address is an attribute, not a name.

Review item 20 is one sentence long and entirely right: *not* `IP:port`, because IPs
change. `10.20.1.10:443` is not an asset. It is where an asset answered on one
afternoon, and a scanner that keys its network inventory on it rebuilds the estate
every time a load balancer fails over — losing history, inventing assets, and
orphaning findings.

The identity here is derived from what survives an address change, in this order:

    asset_id (CMDB) → device_id → hostname + environment + location
                    → certificate fingerprint → SNI / service identity

An observation that carries **only** an address and a port is refused rather than
given a synthetic identity, because an identity invented by the collector is exactly
the `IP:port` inventory the review rejects. IP churn becomes *history on the asset*
(`IP_ADDED` / `IP_REMOVED` with first/last seen), never a retirement plus an arrival.

What this module deliberately will not do is name the application. `link()` reads a
declared mapping with an evidence id and returns `NOT_PROVEN` for everything else,
so a load balancer's certificate never becomes *Payments API uses AES-256-GCM*.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping

SCHEMA = "cryptoscan.cbom-network-identity/1"

#: Device classes an identity may carry. `UNKNOWN` is recorded, never guessed.
ASSET_TYPES: tuple[str, ...] = (
    "LOAD_BALANCER", "ADC", "REVERSE_PROXY", "API_GATEWAY", "WAF", "FIREWALL",
    "VPN", "MAIL_GATEWAY", "HSM", "KMS", "SERVER", "APPLIANCE", "UNKNOWN",
)

#: The order in which an identity is taken. Earlier beats later.
IDENTIFIERS: tuple[str, ...] = (
    "asset_id", "device_id", "hostname", "certificate_fingerprint_sha256",
    "service_identity", "sni",
)

#: Attributes that describe an asset and are allowed to change under it.
ATTRIBUTES: tuple[str, ...] = (
    "ips", "environment", "location", "zone", "type", "hostname", "certificates",
    "collector_sources", "sni",
)

CHURN_KINDS: tuple[str, ...] = (
    "IP_ADDED", "IP_REMOVED", "HOSTNAME_CHANGED", "CERTIFICATE_CHANGED",
    "ENVIRONMENT_CHANGED", "LOCATION_CHANGED", "TYPE_CHANGED",
    "ASSET_ADDED", "ASSET_RETIRED",
)

#: Only these identifiers may *create* an asset. The rest may describe one.
CREATING = ("asset_id", "device_id", "hostname", "certificate_fingerprint_sha256")

NOT_PROVEN = (
    "that a hostname is an application: a name is an entry point until a mapping says "
    "otherwise, and a load balancer's name is not the system behind it",
    "that an asset with a new address is a new asset, or that an asset with no "
    "observation was retired — a discovery gap and a decommission look identical here",
    "that two collectors reporting the same hostname are reporting the same device: "
    "they may be two devices behind one name",
    "that the cryptography an asset terminates is used by the application behind it",
)


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _values(value: Any) -> list[str]:
    """A scalar or a list, as a sorted de-duplicated list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        items: Iterable[Any] = [value]
    elif isinstance(value, Mapping):
        items = [value]
    else:
        items = value
    out: list[str] = []
    for item in items:
        text = _text(item)
        if text and text not in out:
            out.append(text)
    return sorted(out)


def _basis(row: Mapping[str, Any]) -> list[str]:
    """Which identifiers this observation actually carries, strongest first."""
    present: list[str] = []
    for name in IDENTIFIERS:
        if name == "certificate_fingerprint_sha256":
            carried = bool(_text(row.get(name))
                           or _text((row.get("certificate") or {}).get(name))
                           or _fingerprint(row))
        else:
            carried = bool(_text(row.get(name)))
        if carried:
            present.append(name)
    return present


def _fingerprint(row: Mapping[str, Any]) -> str | None:
    certificate = row.get("certificate")
    if isinstance(certificate, Mapping):
        return _text(certificate.get("fingerprint_sha256"))
    return None


def derive_id(row: Mapping[str, Any]) -> str:
    """A deterministic asset id from the stable identifiers, never from an address.

    Two collectors that see the same device produce the same id; the same device on a
    new address produces the same id; nothing about an address takes part.
    """
    basis = [name for name in _basis(row) if name != "asset_id"]
    if not basis:
        raise ValueError(
            "an IP:port is not an identity: this observation carries no asset id, "
            "device id, hostname, certificate or service name, and an address changes")
    environment = _text(row.get("environment")) or "UNKNOWN"
    location = _text(row.get("location")) or _text(row.get("zone")) or "UNKNOWN"
    parts: list[str] = []
    for name in basis:
        value = _fingerprint(row) if name == "certificate_fingerprint_sha256" else None
        parts.append(f"{name}={value or _text(row.get(name))}")
    material = "|".join([environment, location, *parts])
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:10].upper()
    return f"NET-{digest}"


def identity(row: Mapping[str, Any]) -> dict[str, Any]:
    """One observation -> the stable identity it belongs to, with its attributes."""
    if not isinstance(row, Mapping):
        raise ValueError("an observation must be an object")
    basis = _basis(row)
    if not [name for name in basis if name in CREATING]:
        raise ValueError(
            "an IP:port is not an identity: this observation carries no asset id, "
            "device id, hostname or certificate, and an address changes")
    explicit = _text(row.get("asset_id"))
    asset_id = explicit or derive_id(row)
    asset_type = (_text(row.get("type")) or _text(row.get("device_type"))
                  or "UNKNOWN").upper()
    if asset_type not in ASSET_TYPES:
        raise ValueError(f"{asset_type} is not an asset type this model records")
    ips = _values(row.get("ips") if row.get("ips") is not None else row.get("ip"))
    certificates = _values(row.get("certificates"))
    fingerprint = _fingerprint(row) or _text(row.get("certificate_fingerprint_sha256"))
    if fingerprint and fingerprint not in certificates:
        certificates = sorted([*certificates, fingerprint])
    services = _values(row.get("services"))
    return {
        "asset_id": asset_id,
        "asset_id_source": "EXPLICIT" if explicit else "DERIVED",
        "identity_basis": basis if explicit else [name for name in basis
                                                  if name in CREATING],
        "identity_confidence": "STRONG" if explicit or "hostname" in basis else "WEAK",
        "type": asset_type,
        "hostnames": _values(row.get("hostname")),
        "ips": [ip for ip in ips if ":" not in ip],
        "ipv6": [ip for ip in ips if ":" in ip],
        "environment": _text(row.get("environment")),
        "location": _text(row.get("location")),
        "zone": _text(row.get("zone")),
        "collector_sources": _values(row.get("collector_source")
                                     or row.get("collector_sources")),
        "certificates": certificates,
        "sni": _values(row.get("sni")),
        "service_identity": _values(row.get("service_identity")),
        "services": services,
        "evidence_ids": _values(row.get("evidence_id") or row.get("evidence_ids")),
        "observed_at": _text(row.get("observed_at")),
        "private_material": "NOT_STORED",
    }


def merge(observations: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Many observations, possibly from several collectors -> one record per asset."""
    merged: dict[str, dict[str, Any]] = {}
    refused: list[dict[str, Any]] = []
    observations_seen = 0
    for row in observations or ():
        if not isinstance(row, Mapping):
            refused.append({"observation": row, "reason": "an observation must be an object"})
            continue
        try:
            record = identity(row)
        except ValueError as exc:
            refused.append({"observation": dict(row), "reason": str(exc)})
            continue
        observations_seen += 1
        current = merged.get(record["asset_id"])
        if current is None:
            record["ip_history"] = [
                {"ip": ip, "first_seen": record["observed_at"], "last_seen":
                 record["observed_at"],
                 "collector_sources": list(record["collector_sources"])}
                for ip in [*record["ips"], *record["ipv6"]]]
            record["observation_count"] = 1
            record["conflicts"] = []
            merged[record["asset_id"]] = record
            continue
        current["observation_count"] += 1
        for ip in [*record["ips"], *record["ipv6"]]:
            entry = next((item for item in current["ip_history"] if item["ip"] == ip), None)
            if entry is None:
                current["ip_history"].append(
                    {"ip": ip, "first_seen": record["observed_at"],
                     "last_seen": record["observed_at"],
                     "collector_sources": list(record["collector_sources"])})
                continue
            sources = set(entry["collector_sources"]) | set(record["collector_sources"])
            entry["collector_sources"] = sorted(sources)
            for edge, keep in (("first_seen", min), ("last_seen", max)):
                if record["observed_at"] is None:
                    continue
                entry[edge] = (record["observed_at"] if entry[edge] is None
                               else keep(entry[edge], record["observed_at"]))
        for name in ("ips", "ipv6", "hostnames", "certificates", "sni",
                     "service_identity", "services", "evidence_ids",
                     "collector_sources"):
            current[name] = sorted(set(current[name]) | set(record[name]))
        if record["environment"] and current["environment"] not in (None,
                                                                    record["environment"]):
            current["conflicts"].append({"field": "environment",
                                         "values": sorted({current["environment"],
                                                           record["environment"]})})
        elif record["environment"] and current["environment"] is None:
            current["environment"] = record["environment"]
        if record["type"] != "UNKNOWN" and current["type"] not in ("UNKNOWN",
                                                                   record["type"]):
            current["conflicts"].append({"field": "type",
                                         "values": sorted({current["type"],
                                                           record["type"]})})
        elif current["type"] == "UNKNOWN":
            current["type"] = record["type"]
    records = sorted(merged.values(), key=lambda record: record["asset_id"])
    for record in records:
        record["ip_history"] = sorted(record["ip_history"], key=lambda item: item["ip"])
        record["ip_count"] = len(record["ip_history"])
        record["multiple_addresses"] = record["ip_count"] > 1
        record["statement"] = (
            f"{record['asset_id']} ({record['type']}"
            + (f", {record['environment']}" if record["environment"] else "")
            + (f", {record['location']}" if record["location"] else "")
            + f") seen {record['observation_count']} time(s) with "
            + (f"{record['ip_count']} address(es) {', '.join(i['ip'] for i in record['ip_history'])}"
               if record["ip_count"] else "no recorded address")
            + "; the addresses are attributes of this asset, not its identity")
    return {
        "schema": SCHEMA,
        "assets": records,
        "refused": refused,
        "observations": observations_seen,
        "collectors": sorted({source for record in records
                              for source in record["collector_sources"]}),
        "untyped": [record["asset_id"] for record in records if record["type"] == "UNKNOWN"],
        "statement": (
            f"{len(records)} network asset(s) from {observations_seen} observation(s) "
            f"across {len({source for record in records for source in record['collector_sources']})} "
            "collector source(s)"
            + (f"; {len(refused)} observation(s) refused for having no stable identity"
               if refused else "")
            + (f"; {len([r for r in records if r['multiple_addresses']])} asset(s) "
               "answered on more than one address" if any(r["multiple_addresses"]
                                                          for r in records) else "")),
    }


def _attribute(record: Mapping[str, Any], name: str) -> set[str]:
    if name == "ips":
        return set(record.get("ips") or []) | set(record.get("ipv6") or [])
    values = record.get(name)
    if values is None:
        return set()
    if isinstance(values, str):
        return {values}
    if isinstance(values, Mapping):
        return set()
    return {str(value) for value in values}


def churn(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Two merged inventories -> what changed *under one identity*, not what is new."""
    for name, body in (("before", before), ("after", after)):
        if not isinstance(body, Mapping) or body.get("schema") != SCHEMA:
            raise ValueError(f"the {name} inventory is not a {SCHEMA} document")
    old = {record["asset_id"]: record for record in before.get("assets") or []}
    new = {record["asset_id"]: record for record in after.get("assets") or []}
    changes: list[dict[str, Any]] = []
    for asset_id in sorted(old.keys() | new.keys()):
        if asset_id not in old:
            changes.append({"kind": "ASSET_ADDED", "asset_id": asset_id,
                            "detail": "an asset appeared; the review's point is that this "
                                      "is asserted by identity, not by an address"})
            continue
        if asset_id not in new:
            changes.append({
                "kind": "ASSET_RETIRED", "asset_id": asset_id,
                "detail": ("no observation in the later inventory: retired and not "
                           "answering are indistinguishable, so this is a question for "
                           "the owner, not a deletion")})
            continue
        was, now = old[asset_id], new[asset_id]
        for added_kind, removed_kind, name in (
                ("IP_ADDED", "IP_REMOVED", "ips"),
                ("HOSTNAME_CHANGED", "HOSTNAME_CHANGED", "hostnames"),
                ("CERTIFICATE_CHANGED", "CERTIFICATE_CHANGED", "certificates")):
            added = _attribute(now, name) - _attribute(was, name)
            removed = _attribute(was, name) - _attribute(now, name)
            for value in sorted(added):
                changes.append({"kind": added_kind, "asset_id": asset_id, "field": name,
                                "change": "ADDED", "value": value,
                                "detail": f"{name} gained {value}"})
            for value in sorted(removed):
                changes.append({"kind": removed_kind, "asset_id": asset_id, "field": name,
                                "change": "REMOVED", "value": value,
                                "detail": f"{name} lost {value}"})
        for name, kind in (("environment", "ENVIRONMENT_CHANGED"),
                           ("location", "LOCATION_CHANGED"),
                           ("type", "TYPE_CHANGED")):
            if was.get(name) != now.get(name):
                changes.append({"kind": kind, "asset_id": asset_id, "field": name,
                                "before": was.get(name), "after": now.get(name),
                                "detail": f"{name} went from {was.get(name)} to "
                                          f"{now.get(name)}"})
    for change in changes:
        change.setdefault("evidence_before",
                          sorted({value for record in [old.get(change["asset_id"]) or {}]
                                  for value in record.get("evidence_ids") or []}))
        change.setdefault("evidence_after",
                          sorted({value for record in [new.get(change["asset_id"]) or {}]
                                  for value in record.get("evidence_ids") or []}))
    counts: dict[str, int] = {}
    for change in changes:
        counts[change["kind"]] = counts.get(change["kind"], 0) + 1
    address_changes = counts.get("IP_ADDED", 0) + counts.get("IP_REMOVED", 0)
    return {
        "schema": SCHEMA,
        "changes": changes,
        "counts": dict(sorted(counts.items())),
        "identity_stable": not counts.get("ASSET_ADDED", 0)
                           and not counts.get("ASSET_RETIRED", 0),
        "statement": (
            f"{len(changes)} change(s) across {len(old.keys() | new.keys())} identity(ies)"
            + (f"; {address_changes} address change(s), which moved under the same asset "
               "id rather than renaming it" if address_changes else
               "; no address moved")
            + (f"; {counts.get('ASSET_ADDED', 0)} arrival(s) and "
               f"{counts.get('ASSET_RETIRED', 0)} disappearance(s) to reconcile with the "
               "CMDB" if counts.get("ASSET_ADDED") or counts.get("ASSET_RETIRED") else "")),
    }


def link(records: Iterable[Mapping[str, Any]],
         declared: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Asset -> application, only where a declared mapping says so.

    ``declared`` maps asset id (or hostname) to
    ``{"applications": [...], "evidence_id": "...", "source": "CMDB"}``. A mapping
    without an evidence id is not evidence, and a hostname that merely *looks* like an
    application is not a mapping.
    """
    rows: list[dict[str, Any]] = []
    for record in records or ():
        asset_id = record.get("asset_id")
        entry = None
        if isinstance(declared, Mapping):
            entry = declared.get(asset_id) or next(
                (declared.get(host) for host in record.get("hostnames") or []
                 if declared.get(host)), None)
        applications = _values((entry or {}).get("applications")) if entry else []
        evidence_id = _text((entry or {}).get("evidence_id")) if entry else None
        proven = bool(applications and evidence_id)
        rows.append({
            "asset_id": asset_id,
            "applications": applications if proven else [],
            "inference": "PROVEN" if proven else "NOT_PROVEN",
            "evidence_id": evidence_id,
            "source": _text((entry or {}).get("source")) if entry else None,
            "reason": (None if proven else
                       ("the mapping carries no evidence id, so it is a claim and not "
                        "evidence" if applications else
                        "no declared mapping names an application for this asset")),
            "statement": (f"{asset_id} is declared to serve "
                          + ", ".join(applications) + f" ({evidence_id})"
                          if proven else
                          f"{asset_id} is an interface fact: no application is named, "
                          "because inferring one from a hostname is how a load balancer "
                          "becomes an application"),
        })
    proven_rows = [row for row in rows if row["inference"] == "PROVEN"]
    return {
        "schema": SCHEMA,
        "links": rows,
        "proven": len(proven_rows),
        "unproven": len(rows) - len(proven_rows),
        "statement": (
            f"{len(rows)} asset(s): {len(proven_rows)} linked to an application by a "
            f"declared mapping, {len(rows) - len(proven_rows)} left as interface facts"),
    }


def summary(inventory: Mapping[str, Any]) -> dict[str, Any]:
    """One screen: how many assets, how many addresses under them, what is untyped."""
    assets = inventory.get("assets") or []
    return {
        "schema": SCHEMA,
        "assets": len(assets),
        "observations": inventory.get("observations"),
        "collectors": inventory.get("collectors"),
        "addresses": sum(len(record.get("ip_history") or []) for record in assets),
        "multi_address": [record["asset_id"] for record in assets
                          if record.get("multiple_addresses")],
        "untyped": inventory.get("untyped") or [],
        "refused": len(inventory.get("refused") or []),
        "statement": inventory.get("statement", ""),
        "not_proven": list(NOT_PROVEN),
    }


def resolve(assets: Iterable[Mapping[str, Any]],
            records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Attach guide 148's hop assets to an identity: which device is that interface?

    ``cbom.network_assets`` answers *which interface terminated the hop* and refuses to
    call it an application. This function answers the next question only when the
    inventory can: the interface named in ``observed_on`` is matched to an asset's
    hostname, SNI or service identity. An interface with no matching record stays
    `UNRESOLVED` — the alternative is inventing an asset from a name.
    """
    from cbom import network_assets as na  # noqa: PLC0415

    index: dict[str, str] = {}
    for record in records or ():
        asset_id = str(record.get("asset_id") or "")
        if not asset_id:
            continue
        for name in [*(record.get("hostnames") or []), *(record.get("sni") or []),
                     *(record.get("service_identity") or [])]:
            index.setdefault(str(name).strip().lower(), asset_id)
    rows: list[dict[str, Any]] = []
    for asset in assets or ():
        observed_on = str(asset.get("observed_on") or "").strip()
        role = asset.get("interface_role") or na.hop_role(observed_on)
        asset_id = index.get(observed_on.lower()) if observed_on else None
        rows.append({
            "endpoint": asset.get("endpoint"),
            "algorithm": asset.get("algorithm"),
            "observed_on": observed_on,
            "interface_role": role,
            "asset_id": asset_id,
            "resolution": "RESOLVED" if asset_id else "UNRESOLVED",
            "reason": (None if asset_id else
                       f"no inventory record carries {observed_on or 'that interface'} as "
                       "a hostname, SNI or service identity"),
        })
    resolved = [row for row in rows if row["resolution"] == "RESOLVED"]
    return {
        "schema": SCHEMA,
        "rows": rows,
        "resolved": len(resolved),
        "unresolved": len(rows) - len(resolved),
        "statement": (
            f"{len(rows)} network crypto asset row(s): {len(resolved)} attached to an "
            f"asset identity, {len(rows) - len(resolved)} left unresolved rather than "
            "given a name"),
    }
