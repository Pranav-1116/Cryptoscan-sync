"""Telecom target & carrier registry (pure) — international carrier estates.

A telecom operator group is a set of carriers across countries; each carrier
runs 3GPP network functions (NFs) whose crypto surface is what this scanner
watches: TLS on the 5G service-based interfaces, NDS/IP (IPsec) on backhaul
and roaming edges, TLS on signaling (SIGTRAN/Diameter/SIP).

Shapes follow the platform conventions:

* carriers — {code, name, country, plmn, legal_entity} where ``plmn`` is an
  ITU-T E.212 "MCC-MNC" string and ``legal_entity`` optionally ties the
  carrier into the group registry (cbom.group) for the international view.
* targets — {nf_id, nf_type, endpoint, carrier_code, environment} where
  ``nf_type`` comes from the catalog below and ``endpoint`` is host:port.

Persistence is file-backed and operator-managed: ``CRYPTOSCAN_TELECOM_REGISTRY``
overrides the path; the default is ``<CRYPTOSCAN_ROOT|cwd>/config/telecom_registry.json``
with a writable fallback — the same pattern as the group entity registry.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

_NF_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,62}$")
_CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,23}$")
_MCC_RE = re.compile(r"^\d{3}$")
_MNC_RE = re.compile(r"^\d{2,3}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_ENVS = ("production", "staging", "development", "lab")

# ---------------------------------------------------------------- NF catalog
# Crypto-relevant network-function classes. ``transport`` is what the
# classifier expects on the signaling/SBI port: ``tls`` (direct TLS — the
# overwhelmingly common deployment for SBA/signaling), ``ipsec`` (NDS/IP
# gateways — IKE is classified from operator-side ingest, not probed here).
NF_CATALOG: dict[str, dict[str, Any]] = {
    # 5G service-based architecture (TS 23.501) — SBI is TLS on HTTPS/2
    "amf": {"name": "Access & Mobility Management Function", "transport": "tls", "plane": "5gc"},
    "smf": {"name": "Session Management Function", "transport": "tls", "plane": "5gc"},
    "upf": {"name": "User Plane Function", "transport": "tls", "plane": "5gc"},
    "udm": {"name": "Unified Data Management", "transport": "tls", "plane": "5gc"},
    "udr": {"name": "Unified Data Repository", "transport": "tls", "plane": "5gc"},
    "ausf": {"name": "Authentication Server Function", "transport": "tls", "plane": "5gc"},
    "pcf": {"name": "Policy Control Function", "transport": "tls", "plane": "5gc"},
    "nrf": {"name": "NF Repository Function", "transport": "tls", "plane": "5gc"},
    "nssf": {"name": "Network Slice Selection Function", "transport": "tls", "plane": "5gc"},
    "nef": {"name": "Network Exposure Function", "transport": "tls", "plane": "5gc"},
    "bsf": {"name": "Binding Support Function", "transport": "tls", "plane": "5gc"},
    "smsf": {"name": "SMS Function", "transport": "tls", "plane": "5gc"},
    # roaming edge — inter-PLMN SBI goes through SEPP (TS 33.501 §13)
    "sepp": {"name": "SEPP — roaming edge proxy", "transport": "tls", "plane": "roaming"},
    # 4G EPC (Diameter-based; deployed over TLS/IPsec per NDS/IP)
    "mme": {"name": "Mobility Management Entity", "transport": "tls", "plane": "epc"},
    "sgw": {"name": "Serving Gateway", "transport": "tls", "plane": "epc"},
    "pgw": {"name": "PDN Gateway", "transport": "tls", "plane": "epc"},
    "hss": {"name": "Home Subscriber Server", "transport": "tls", "plane": "epc"},
    "pcrf": {"name": "Policy & Charging Rules Function", "transport": "tls", "plane": "epc"},
    # IMS
    "pcscf": {"name": "Proxy CSCF (IMS SIP)", "transport": "tls", "plane": "ims"},
    "scscf": {"name": "Serving CSCF (IMS SIP)", "transport": "tls", "plane": "ims"},
    # transport / edge
    "ipsecgw": {"name": "NDS/IP security gateway (Za/Zb)", "transport": "ipsec", "plane": "transport"},
    "sbc": {"name": "Session Border Controller", "transport": "tls", "plane": "transport"},
    "siggw": {"name": "Signaling gateway (SIGTRAN/Diameter)", "transport": "tls", "plane": "transport"},
    "gnbcu": {"name": "gNB Centralized Unit (F1/backhaul)", "transport": "tls", "plane": "ran"},
}

PLANE_ORDER = ("5gc", "roaming", "epc", "ims", "ran", "transport")


def validate_plmn(plmn: str) -> dict[str, str]:
    """``"262-01"`` / ``"405874"`` → {mcc, mnc} — ITU-T E.212 shape.

    Accepts ``MCC-MNC`` (dash or colon separated) or a bare 5–6 digit string
    (MCC is always 3 digits, MNC is the 2–3 digit tail).
    """
    text = str(plmn or "").strip().upper().replace(":", "-")
    if "-" in text:
        mcc, _, mnc = text.partition("-")
    else:
        if not text.isdigit() or not (5 <= len(text) <= 6):
            raise ValueError(f"PLMN must be 'MCC-MNC' (e.g. 262-01) or 5-6 digits: {plmn!r}")
        mcc, mnc = text[:3], text[3:]
    if not _MCC_RE.match(mcc):
        raise ValueError(f"PLMN MCC must be 3 digits: {mcc!r}")
    if not _MNC_RE.match(mnc):
        raise ValueError(f"PLMN MNC must be 2-3 digits: {mnc!r}")
    return {"mcc": mcc, "mnc": mnc}


def normalize_carrier(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one carrier record — raises ValueError on any bad field."""
    code = str(record.get("code") or "").strip().lower()
    if not _CODE_RE.match(code):
        raise ValueError(f"carrier code must match {_CODE_RE.pattern}: {record.get('code')!r}")
    name = str(record.get("name") or "").strip()
    if not (2 <= len(name) <= 120):
        raise ValueError("carrier name must be 2-120 characters")
    country = str(record.get("country") or "").strip().lower()
    if not re.match(r"^[a-z]{2}$", country):
        raise ValueError(f"carrier country must be ISO 3166-1 alpha-2: {record.get('country')!r}")
    plmn = validate_plmn(record.get("plmn") or "")
    legal_entity = str(record.get("legal_entity") or "").strip().lower()
    if legal_entity and not _CODE_RE.match(legal_entity):
        raise ValueError(f"legal_entity must match {_CODE_RE.pattern}: {record.get('legal_entity')!r}")
    return {
        "code": code, "name": name, "country": country,
        "plmn": f"{plmn['mcc']}-{plmn['mnc']}", "legal_entity": legal_entity,
    }


def normalize_target(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one NF target record — raises ValueError on any bad field."""
    nf_id = str(record.get("nf_id") or "").strip().lower()
    if not _NF_ID_RE.match(nf_id):
        raise ValueError(f"nf_id must match {_NF_ID_RE.pattern}: {record.get('nf_id')!r}")
    nf_type = str(record.get("nf_type") or "").strip().lower()
    if nf_type not in NF_CATALOG:
        raise ValueError(
            f"nf_type must be one of the catalog: {', '.join(sorted(NF_CATALOG))} (got {nf_type!r})"
        )
    endpoint = str(record.get("endpoint") or "").strip()
    host, _, port_text = endpoint.rpartition(":")
    if not host or not port_text or not port_text.isdigit() or not (1 <= int(port_text) <= 65535):
        raise ValueError(f"endpoint must be host:port: {endpoint!r}")
    if not _HOST_RE.match(host):
        raise ValueError(f"endpoint host has invalid characters: {host!r}")
    carrier_code = str(record.get("carrier_code") or "").strip().lower()
    if carrier_code and not _CODE_RE.match(carrier_code):
        raise ValueError(f"carrier_code must match {_CODE_RE.pattern}: {record.get('carrier_code')!r}")
    environment = str(record.get("environment") or "production").strip().lower()
    if environment not in _ENVS:
        raise ValueError(f"environment must be one of {', '.join(_ENVS)}: {environment!r}")
    return {
        "nf_id": nf_id, "nf_type": nf_type, "endpoint": f"{host}:{int(port_text)}",
        "carrier_code": carrier_code, "environment": environment,
    }


# ------------------------------------------------------------------ registry
def default_registry_path(base: str | Path | None = None) -> Path:
    """Registry file path: CRYPTOSCAN_TELECOM_REGISTRY > config/ > writable fallback."""
    override = os.environ.get("CRYPTOSCAN_TELECOM_REGISTRY")
    if override:
        return Path(override)
    if base is not None:
        return Path(base)
    root = Path(os.environ.get("CRYPTOSCAN_ROOT") or os.getcwd())
    candidate = root / "config" / "telecom_registry.json"
    if candidate.parent.is_dir() and os.access(candidate.parent, os.W_OK):
        return candidate
    home = os.environ.get("CRYPTOSCAN_HOME")
    return Path(home) / "telecom_registry.json" if home else Path(tempfile.gettempdir()) / "telecom_registry.json"


def load_registry(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    """Carriers, targets and roaming partners from the registry file."""
    file = Path(path) if path else default_registry_path()
    empty = {"carriers": {}, "targets": {}, "roaming_partners": {}}
    if not file.is_file():
        return empty
    try:
        raw = json.loads(file.read_text())
    except (OSError, json.JSONDecodeError):
        return empty
    # partner validation lives in roaming (avoids a circular import)
    from telecom_scanner.roaming import normalize_partner

    carriers: dict[str, dict[str, Any]] = {}
    for record in raw.get("carriers") or []:
        try:
            carrier = normalize_carrier(record)
        except ValueError:
            continue
        carriers[carrier["code"]] = carrier
    targets: dict[str, dict[str, Any]] = {}
    for record in raw.get("targets") or []:
        try:
            target = normalize_target(record)
        except ValueError:
            continue
        targets[target["nf_id"]] = target
    partners: dict[str, dict[str, Any]] = {}
    for record in raw.get("roaming_partners") or []:
        try:
            partner = normalize_partner(record)
        except ValueError:
            continue
        partners[partner["id"]] = partner
    return {"carriers": carriers, "targets": targets, "roaming_partners": partners}


def save_registry(
    carriers: Iterable[Mapping[str, Any]],
    targets: Iterable[Mapping[str, Any]],
    path: str | Path | None = None,
    *,
    partners: Iterable[Mapping[str, Any]] = (),
) -> int:
    """Persist the registry (validated); returns the total record count."""
    from telecom_scanner.roaming import normalize_partner

    file = Path(path) if path else default_registry_path()
    file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "carriers": [normalize_carrier(c) for c in carriers],
        "targets": [normalize_target(t) for t in targets],
        "roaming_partners": [normalize_partner(p) for p in partners],
    }
    file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return len(payload["carriers"]) + len(payload["targets"]) + len(payload["roaming_partners"])
