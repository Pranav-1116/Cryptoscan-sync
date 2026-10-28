"""Read-only ServiceNow CMDB discovery plane (spec 67 §4; spec 93 §13).

The fourth discovery source in spec 67 §4 was "live CMDB", and it was open: a bank
knows what it owns from its CMDB, but only the CMDB knows. This module reads the
ServiceNow Table API and turns configuration items into estate assets — the
inventory *spine* the other planes attach to, not a crypto claim.

Two things it is careful about:

* **CMDB data is declared, not observed.** Every record it emits is ``IMPORTED``
  evidence with LOW confidence, and the relationship it creates uses the
  ``IMPORTED`` basis — which is in ``USAGE_BASES``' complement on purpose, so an
  edge like "app A depends on service B" drawn from a CMDB row can never be read
  as "A uses B's crypto". Whether A actually calls B's TLS endpoint is a network
  observation, and stays a separate layer.
* **A refusal is not an empty CMDB.** 401/403 becomes ``blocked[]`` with the table
  named and the plane reports ``PARTIAL``; a table that does not exist is recorded
  the same way. A limit reached is reported as ``truncated`` so a 5000-row cap
  cannot pass as "that is the whole estate".

Reads (Table API, GET only):

``cmdb_ci_server``      → HOST         (name, ip_address, os, install_status)
``cmdb_ci_service``     → SERVICE      (business services)
``cmdb_ci_appl``        → APPLICATION
``cmdb_rel_ci``         → relationships between the above

Auth: ``SERVICENOW_INSTANCE_URL`` plus either ``SERVICENOW_USERNAME`` +
``SERVICENOW_PASSWORD`` (basic, the usual service-account setup) or
``SERVICENOW_TOKEN`` (OAuth bearer). ``CMDB_MAX_ROWS`` bounds every table, and
``CMDB_QUERY`` optionally narrows the whole read (e.g. ``install_status=1``).
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping

from api.estate_planes import PlaneNotConfigured
from shared_models.estate_graph import make_evidence, normalize_asset

SCHEMA = "cryptoscan.estate-cmdb/1"
PLANE = "CMDB"
SOURCE = "servicenow"

#: table → asset type. `sys_class_name` is reported as an attribute, never used to
#: invent a type: a Windows server CI is still a HOST for the estate graph.
TABLES: dict[str, str] = {
    "cmdb_ci_server": "HOST",
    "cmdb_ci_service": "SERVICE",
    "cmdb_ci_appl": "APPLICATION",
}

FIELDS: dict[str, tuple[str, ...]] = {
    "cmdb_ci_server": ("sys_id", "name", "sys_class_name", "ip_address", "os", "os_version",
                       "install_status", "operational_status", "owned_by", "location",
                       "manufacturer", "serial_number", "environment", "comments"),
    "cmdb_ci_service": ("sys_id", "name", "sys_class_name", "operational_status", "owned_by",
                        "business_unit", "environment", "description", "service_classification"),
    "cmdb_ci_appl": ("sys_id", "name", "sys_class_name", "version", "install_status",
                     "operational_status", "owned_by", "environment", "manufacturer", "comments"),
    "cmdb_rel_ci": ("sys_id", "parent", "child", "type"),
}

#: ServiceNow relationship type names → graph predicates. Anything unmapped is
#: reported as an unmapped type rather than coerced into a predicate.
RELATIONSHIP_TYPES: dict[str, str] = {
    "depends on": "depends_on",
    "used by": "depends_on",          # child uses parent; direction is corrected below
    "runs on": "runs_on",
    "contains": "contains",
    "contained by": "contains",        # direction corrected below
    "hosted on": "hosted_on",
    "owned by": "owned_by",
    "manages": "manages",
}

#: relationship types whose ServiceNow direction is the reverse of the predicate
REVERSED_TYPES = frozenset({"used by", "contained by"})


def relationship_mapping(type_name: str) -> tuple[str | None, bool]:
    """ServiceNow names relationships ``"Parent side::Child side"``.

    Returns ``(predicate, reversed)`` — ``None`` when the type has no agreed
    mapping, so the caller can count it instead of inventing an edge.
    """
    raw = str(type_name or "").strip()
    if not raw:
        return None, False
    parent_side, _, child_side = raw.partition("::")
    for side in (parent_side, child_side):
        key = side.strip().lower()
        if key in RELATIONSHIP_TYPES:
            return RELATIONSHIP_TYPES[key], key in REVERSED_TYPES
        for known, predicate in RELATIONSHIP_TYPES.items():
            if known in key:
                return predicate, known in REVERSED_TYPES
    return None, False

Transport = Callable[[str, Mapping[str, str], float], tuple[int, bytes, Mapping[str, str]]]


class CmdbReadError(RuntimeError):
    """The instance answered, but not with data we can use."""


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def cmdb_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve instance URL + credentials, or raise :class:`PlaneNotConfigured`."""
    env = dict(os.environ if environ is None else environ)
    url = str(env.get("SERVICENOW_INSTANCE_URL") or "").strip().rstrip("/")
    if not url:
        raise PlaneNotConfigured(
            "no CMDB is configured: set SERVICENOW_INSTANCE_URL (plus SERVICENOW_USERNAME/"
            "SERVICENOW_PASSWORD or SERVICENOW_TOKEN) to read the configuration management database"
        )
    if not url.startswith("https://"):
        raise PlaneNotConfigured(
            "SERVICENOW_INSTANCE_URL must be https:// — CMDB data is bank-confidential and is never read over "
            "plaintext"
        )
    token = str(env.get("SERVICENOW_TOKEN") or "").strip()
    user = str(env.get("SERVICENOW_USERNAME") or "").strip()
    password = str(env.get("SERVICENOW_PASSWORD") or "")
    if not token and not (user and password):
        raise PlaneNotConfigured(
            "SERVICENOW_INSTANCE_URL is set but no credential is: set SERVICENOW_TOKEN, or "
            "SERVICENOW_USERNAME + SERVICENOW_PASSWORD"
        )
    return {
        "instance_url": url,
        "token": token or None,
        "username": user or None,
        "password": password or None,
        "ca_file": str(env.get("SERVICENOW_CA_FILE") or "").strip() or None,
        "max_rows": int(env.get("CMDB_MAX_ROWS") or 2000),
        "query": str(env.get("CMDB_QUERY") or "").strip() or None,
        "source": "ENVIRONMENT",
    }


def _default_transport(url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes, Mapping[str, str]]:
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read(), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read() or b"", dict(exc.headers)


def _auth_headers(config: Mapping[str, Any]) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": "CryptoScan-CMDB/1"}
    if config.get("token"):
        headers["Authorization"] = f"Bearer {config['token']}"
    else:
        raw = f"{config['username']}:{config['password']}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return headers


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _reference(value: Any) -> dict[str, str] | None:
    """ServiceNow reference fields are ``{value, link}``; plain strings also occur."""
    if isinstance(value, dict):
        identifier = str(value.get("value") or "").strip()
        display = str(value.get("display_value") or "").strip()
        if not identifier and not display:
            return None
        return {"id": identifier or display, "display": display or identifier}
    text = str(value or "").strip()
    return {"id": text, "display": text} if text else None


def _text(value: Any) -> str | None:
    if isinstance(value, dict):
        return str(value.get("display_value") or value.get("value") or "").strip() or None
    text = str(value or "").strip()
    return text or None


def _identity(table: str, record: Mapping[str, Any], name: str) -> dict[str, Any]:
    """A stable identity per table: sys_id is the CMDB's own key and never reused."""
    sys_id = _text(record.get("sys_id"))
    if table == "cmdb_ci_server":
        return {"hostname": name, "sys_id": sys_id}
    return {"name": name, "sys_id": sys_id}


# --------------------------------------------------------------------------- #
# collector
# --------------------------------------------------------------------------- #
def collect_cmdb(
    _db: Any = None,
    *,
    transport: Transport | None = None,
    config: Mapping[str, Any] | None = None,
    timeout: float = 20.0,
    max_rows: int | None = None,
) -> dict[str, Any]:
    """Read the CMDB into estate assets, evidence and imported relationships."""
    resolved = dict(config) if config else cmdb_config()
    resolved.setdefault("source", "INJECTED")
    sender = transport or _default_transport
    limit = int(max_rows or resolved.get("max_rows") or 2000)

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    blocked: list[str] = []
    limitations: list[str] = [
        "CMDB records are declared data (IMPORTED, LOW confidence): they say an asset exists and who owns it, "
        "never which cryptography it uses",
        "relationship edges carry the IMPORTED basis, so they can never be read as evidence that one asset "
        "uses another's crypto",
    ]
    answered: set[str] = set()
    by_sys_id: dict[str, str] = {}
    unmapped_relationship_types: set[str] = set()

    def fetch(table: str) -> list[dict[str, Any]]:
        params: list[tuple[str, str]] = [
            ("sysparm_fields", ",".join(FIELDS[table])),
            ("sysparm_limit", str(limit)),
            ("sysparm_display_value", "true"),
        ]
        query = str(resolved.get("query") or "").strip()
        if query:
            params.append(("sysparm_query", query))
        url = f"{resolved['instance_url']}/api/now/table/{table}?{urllib.parse.urlencode(params)}"
        status, payload, headers = sender(url, _auth_headers(resolved), timeout)
        label = f"servicenow:table/{table}"
        if status in {401, 403}:
            raise PermissionError(f"{label}: HTTP {status}")
        if status == 404:
            raise LookupError(f"{label}: table not present on this instance")
        if status >= 300:
            raise CmdbReadError(f"{label}: HTTP {status} {payload[:200].decode('utf-8', 'replace')}")
        try:
            document = json.loads(payload or b"{}")
        except ValueError as exc:
            raise CmdbReadError(f"{label}: unparseable JSON") from exc
        rows = document.get("result")
        if not isinstance(rows, list):
            raise CmdbReadError(f"{label}: response has no result list")
        if len(rows) >= limit:
            limitations.append(
                f"{table}: the {limit}-row limit was reached — more records exist and were NOT read "
                f"(truncated, not complete)"
            )
        total = headers.get("X-Total-Count") or headers.get("x-total-count")
        if total and str(total).isdigit() and int(total) > len(rows):
            limitations.append(
                f"{table}: {int(total) - len(rows)} of {total} records were not read — this table is PARTIAL"
            )
        return rows

    def add_asset(table: str, record: Mapping[str, Any]) -> str | None:
        name = _text(record.get("name"))
        if not name:
            return None
        kind = TABLES[table]
        asset = normalize_asset(
            kind,
            name,
            identity=_identity(table, record, name),
            environment=_text(record.get("environment")),
            owner=_text(record.get("owned_by")),
            location=_text(record.get("location")),
            source=SOURCE,
            attributes={
                "sys_id": _text(record.get("sys_id")),
                "sys_class_name": _text(record.get("sys_class_name")),
                "operational_status": _text(record.get("operational_status")),
                "install_status": _text(record.get("install_status")),
                "business_unit": _text(record.get("business_unit")),
                "version": _text(record.get("version")),
                "vendor": _text(record.get("manufacturer")),
                "os": _text(record.get("os")),
                "os_version": _text(record.get("os_version")),
                "ip_address": _text(record.get("ip_address")),
                "serial_number": _text(record.get("serial_number")),
                "cmdb_table": table,
            },
        )
        sys_id = _text(record.get("sys_id"))
        if sys_id:
            by_sys_id[sys_id] = asset["asset_id"]
        assets.append(asset)
        evidence.append(make_evidence(
            source="servicenow",
            evidence_type="IMPORTED",
            target=asset["asset_id"],
            layer="PLATFORM",
            collector=f"servicenow:{table}",
            facts={
                "cmdb_table": table,
                "sys_class_name": _text(record.get("sys_class_name")),
                "operational_status": _text(record.get("operational_status")),
                "claim": "IMPORTED — a CMDB record is a declaration of existence and ownership, not an "
                         "observation of cryptography",
            },
        ))
        return asset["asset_id"]

    # ---- configuration items ---------------------------------------------- #
    for table in TABLES:
        try:
            rows = fetch(table)
            answered.add(table)
        except PermissionError as exc:
            blocked.append(str(exc))
            limitations.append(f"{table}: {exc} — NOT_OBSERVED, not an empty table")
            continue
        except LookupError as exc:
            blocked.append(str(exc))
            limitations.append(f"{table}: {exc} — this CMDB does not model it, which is not an empty estate")
            continue
        except CmdbReadError as exc:
            blocked.append(str(exc))
            limitations.append(f"{table}: {exc}")
            continue
        for record in rows:
            add_asset(table, record)

    # ---- relationship CIs ------------------------------------------------- #
    unmapped = 0
    try:
        rows = fetch("cmdb_rel_ci")
        answered.add("cmdb_rel_ci")
    except (PermissionError, LookupError, CmdbReadError) as exc:
        blocked.append(str(exc))
        limitations.append(
            f"cmdb_rel_ci: {exc} — relationships between CIs are NOT_OBSERVED; the assets stand alone"
        )
        rows = []

    for record in rows:
        parent = _reference(record.get("parent"))
        child = _reference(record.get("child"))
        type_name = _text(record.get("type")) or ""
        predicate, reversed_direction = relationship_mapping(type_name)
        if not parent or not child:
            continue
        if predicate is None:
            unmapped += 1
            if type_name:
                unmapped_relationship_types.add(type_name)
            continue
        subject_id, object_id = parent["id"], child["id"]
        if reversed_direction:
            subject_id, object_id = object_id, subject_id
        subject = by_sys_id.get(subject_id)
        obj = by_sys_id.get(object_id)
        if not subject or not obj:
            # one end was not read (other table refused, or outside the limit)
            continue
        relationships.append({
            "subject": subject,
            "predicate": predicate,
            "object": obj,
            "basis": "IMPORTED",
            "evidence_ids": [],
            "attributes": {
                "claim": "IMPORTED",
                "observed": False,
                "servicenow_type": type_name,
                "note": "a CMDB relationship says the bank records a dependency; it is not proof of a "
                        "crypto call path",
            },
        })

    if unmapped:
        limitations.append(
            f"{unmapped} relationship CI(s) used types with no agreed mapping "
            f"({', '.join(sorted(unmapped_relationship_types)) or 'unnamed'}) — recorded as unmapped, not guessed"
        )

    return {
        "schema": SCHEMA,
        "plane": PLANE,
        "provider": SOURCE,
        "instance_url": resolved.get("instance_url"),
        "credential_source": resolved.get("source"),
        "expected": len(TABLES) + 1,
        "collected": len(answered),
        "answered": sorted(answered),
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "blocked": blocked,
        "unmapped_relationships": unmapped,
        "note": (
            "the CMDB is the inventory spine: it tells the other planes what exists and who owns it, and never "
            "what cryptography is in use"
        ),
        "limitations": limitations,
    }
