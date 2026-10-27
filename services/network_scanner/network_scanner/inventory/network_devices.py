"""Network device crypto surface — read-only, declared or observed (spec 67 §14).

Routers, switches, firewalls, load balancers, ADC/WAF, VPN gateways and SD-WAN
edges carry crypto nobody points a TLS scanner at: the **management plane**
(Telnet, SNMP v1/v2c, HTTP admin, SSH, HTTPS admin) and the **control plane**
(routing authentication, trustpoints) as well as the data plane that terminates
TLS.

Two hard rules:

* **Read-only.** This module consumes an export, an API response or a probe
  observation. It has no write path, opens no connection and never changes a
  device configuration — a network device is production infrastructure, and
  CryptoScan is a reader of facts, not a configuration manager (§14, §30).
* **No secrets.** An export routinely contains `enable secret`, SNMP community
  strings and local user passwords. Any such field rejects the whole device
  record: accepting it would put a credential in an evidence store that is
  meant to hold only crypto parameters.

Declared facts are ``NETWORK_CONFIGURED``. Only a probe result that carries
negotiated parameters may be ``NETWORK_ACTIVE_OBSERVED``; a declared surface
with no crypto detail is inventoried and left ``NOT_OBSERVED``.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

SCHEMA = "cryptoscan.network-evidence/1"
MODEL = "cryptoscan.network-device-surface/1"

DEVICE_ROLES = (
    "ROUTER",
    "SWITCH",
    "FIREWALL",
    "LOAD_BALANCER",
    "ADC",
    "WAF",
    "API_GATEWAY",
    "VPN_GATEWAY",
    "PROXY",
    "SD_WAN_EDGE",
    "WIRELESS_CONTROLLER",
    "NETWORK_MANAGEMENT",
    "UNKNOWN",
)

PLANES = ("MANAGEMENT", "CONTROL", "DATA", "VPN")

#: keys that must never appear in a device record — fail closed on all of them
FORBIDDEN_KEY_TOKENS = (
    "password",
    "passwd",
    "secret",
    "community",
    "private_key",
    "privatekey",
    "psk",
    "pre_shared_key",
    "preshared",
    "key_material",
    "api_token",
    "session_token",
    "cookie",
    "enable_secret",
    "authorization_code",
    "snmp_community",
)

#: CBOM roles for device crypto, kept distinct from TLS endpoint roles
ROLE_DEVICE_MANAGEMENT = "device-management-crypto"
ROLE_DEVICE_CONTROL = "device-control-plane-crypto"
ROLE_DEVICE_VPN = "device-vpn-crypto"
ROLE_DEVICE_DATA = "device-data-plane-crypto"

_PLANE_ROLE = {
    "MANAGEMENT": ROLE_DEVICE_MANAGEMENT,
    "CONTROL": ROLE_DEVICE_CONTROL,
    "VPN": ROLE_DEVICE_VPN,
    "DATA": ROLE_DEVICE_DATA,
}

LEGACY_TLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}


class UnsafeDeviceRecord(ValueError):
    """Raised when a device record carries credentials or secrets."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def validate_device(device: dict[str, Any]) -> None:
    """Reject any device record containing a secret-bearing field (fail closed)."""
    stack: list[Any] = [device]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                token = _norm(key)
                if any(forbidden in token for forbidden in FORBIDDEN_KEY_TOKENS):
                    raise UnsafeDeviceRecord(
                        f"field '{key}' looks like a credential or key material; device records carry "
                        "crypto parameters only"
                    )
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def _base(
    device: dict[str, Any],
    *,
    plane: str,
    protocol: str,
    surface: str,
    evidence_type: str,
    status: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "evidence_type": evidence_type,
        "evidence_id": f"ev-{uuid.uuid4().hex}",
        "target": {
            "endpoint": device.get("endpoint") or device.get("management_ip") or device.get("name"),
            "host": device.get("management_ip") or device.get("name"),
            "port": device.get("management_port"),
            "ip_address": device.get("management_ip"),
        },
        "protocol": protocol,
        "observation_status": status,
        "device": {
            "name": device.get("name"),
            "role": str(device.get("role") or "UNKNOWN").upper(),
            "vendor": device.get("vendor"),
            "model": device.get("model"),
            "plane": plane,
            "surface": surface,
        },
        "decomposition": {
            "key_exchange": None,
            "authentication": None,
            "encryption": None,
            "mode": None,
            "mac_or_prf": None,
            "key_size_bits": None,
        },
        "certificate": {},
        "certificate_chain": {},
        "mutual_tls": "UNKNOWN",
        "mtls_evidence": "NOT_PROBED",
        "policy_issues": [],
        "algorithm_verdict": {},
        "covered": True,
        # A device export describes intent; it is not a handshake.
        "source": str(device.get("source") or "CONFIG_EXPORT").upper(),
        "read_only": True,
        "limitations": [
            "device crypto is read from an export/API declaration — nothing was negotiated with the device",
            "CryptoScan never changes device configuration; this surface is inventory, not management",
        ],
        "observed_at": device.get("observed_at") or _now(),
        "scanner_version": "network-device-surface-v1.0",
        "scope_revision": device.get("scope_revision"),
        "scope_name": device.get("scope_name"),
        "confidence": "MEDIUM" if evidence_type == "NETWORK_ACTIVE_OBSERVED" else "LOW",
        "context": {
            "device": device.get("name"),
            "role": str(device.get("role") or "UNKNOWN").upper(),
            "plane": plane,
            "read_only": True,
            "source": str(device.get("source") or "CONFIG_EXPORT").upper(),
        },
    }


def _surface_record(
    device: dict[str, Any],
    *,
    plane: str,
    protocol: str,
    surface: str,
    detail: dict[str, Any] | None,
) -> dict[str, Any]:
    detail = detail or {}
    observed = bool(detail.get("observed")) and evidence_type_observed(detail)
    evidence_type = "NETWORK_ACTIVE_OBSERVED" if observed else "NETWORK_CONFIGURED"
    record = _base(
        device,
        plane=plane,
        protocol=protocol,
        surface=surface,
        evidence_type=evidence_type,
        status="OBSERVED" if observed else "DECLARED",
    )
    if not detail:
        record["observation_status"] = "NOT_OBSERVED"
        record["limitations"].append(
            "the device declares this surface without crypto parameters — its configuration is UNKNOWN"
        )
    cipher = detail.get("cipher_suite") or detail.get("cipher")
    record["tls_version"] = detail.get("tls_version")
    record["cipher_suite"] = cipher
    record["decomposition"].update(
        {
            "key_exchange": detail.get("key_exchange"),
            "authentication": detail.get("authentication") or detail.get("host_key"),
            "encryption": detail.get("encryption") or cipher,
            "mac_or_prf": detail.get("mac") or detail.get("integrity"),
            "key_size_bits": detail.get("key_size_bits"),
        }
    )
    record["snmp"] = detail.get("snmp") if protocol.upper() == "SNMP" else None
    return record


def evidence_type_observed(detail: dict[str, Any]) -> bool:
    """An observation needs negotiated parameters, not just a flag."""
    return bool(
        detail.get("tls_version")
        or detail.get("cipher_suite")
        or detail.get("cipher")
        or detail.get("negotiated")
        or (detail.get("ssh") or {}).get("negotiated")
    )


def build_device_evidence(
    device: dict[str, Any],
    *,
    scope_revision: str | None = None,
    scope_name: str | None = None,
    observed_at: str | None = None,
) -> list[dict[str, Any]]:
    """Turn one device record into one evidence record per crypto surface."""
    validate_device(device)
    device = dict(device)
    if scope_revision:
        device["scope_revision"] = scope_revision
    if scope_name:
        device["scope_name"] = scope_name
    if observed_at:
        device["observed_at"] = observed_at

    management = device.get("management") or {}
    records: list[dict[str, Any]] = []

    for surface, protocol in (
        ("telnet", "TELNET"),
        ("ssh", "SSH"),
        ("https", "TLS"),
        ("http", "HTTP"),
        ("snmp", "SNMP"),
        ("netconf", "NETCONF"),
    ):
        detail = management.get(surface)
        if detail is None:
            continue
        if detail is True:
            detail = {}
        if not isinstance(detail, dict):
            continue
        if detail.get("enabled") is False:
            continue
        record = _surface_record(device, plane="MANAGEMENT", protocol=protocol, surface=surface, detail=detail)
        issues = record["policy_issues"]
        if protocol == "TELNET":
            issues.append("DEVICE_TELNET_MANAGEMENT_ENABLED")
        if protocol == "HTTP":
            issues.append("DEVICE_PLAINTEXT_ADMIN_UI")
        if protocol == "SNMP":
            version = _norm((detail.get("snmp") or {}).get("version") or detail.get("version"))
            if version in {"v1", "v2c", "2c"}:
                issues.append(f"DEVICE_LEGACY_SNMP:{version}")
        if protocol in {"TLS", "NETCONF"} and record.get("tls_version"):
            if _norm(record["tls_version"]) in LEGACY_TLS:
                issues.append(f"DEVICE_LEGACY_ADMIN_TLS:{record['tls_version']}")
        if protocol == "SSH":
            kex = (detail.get("kex") or [])
            host_key = (detail.get("host_key") or [])
            if any(_norm(item) in {"ssh-rsa", "ssh-dss", "diffie-hellman-group1-sha1"} for item in list(kex) + list(host_key)):
                issues.append("DEVICE_LEGACY_SSH_ALGORITHM")
        records.append(record)

    for index, profile in enumerate(device.get("tls_profiles") or []):
        if not isinstance(profile, dict):
            continue
        record = _surface_record(
            device,
            plane="DATA",
            protocol="TLS",
            surface=f"tls-profile:{profile.get('name') or index}",
            detail=profile,
        )
        if record.get("tls_version") and _norm(record["tls_version"]) in LEGACY_TLS:
            record["policy_issues"].append(f"DEVICE_LEGACY_DATA_TLS:{record['tls_version']}")
        if profile.get("servers"):
            record["context"]["servers"] = list(profile.get("servers") or [])[:50]
        records.append(record)

    for index, tunnel in enumerate(device.get("vpn") or []):
        if not isinstance(tunnel, dict):
            continue
        record = _base(
            device,
            plane="VPN",
            protocol=str(tunnel.get("protocol") or "IPsec"),
            surface=f"vpn:{tunnel.get('name') or index}",
            evidence_type="NETWORK_CONFIGURED",
            status="DECLARED",
        )
        record["ike"] = {
            "version": tunnel.get("ike_version") or "UNKNOWN",
            "encryption": tunnel.get("encryption"),
            "integrity": tunnel.get("integrity"),
            "prf": tunnel.get("prf"),
            "dh_group": tunnel.get("dh_group"),
            "authentication": tunnel.get("authentication") or "UNKNOWN",
        }
        record["esp"] = {
            "status": "DECLARED" if tunnel.get("esp_encryption") else "NOT_OBSERVED",
            "encryption": tunnel.get("esp_encryption"),
            "integrity": tunnel.get("esp_integrity"),
            "pfs": "OFFERED" if tunnel.get("pfs") else "UNKNOWN",
        }
        record["decomposition"].update(
            {
                "key_exchange": tunnel.get("dh_group"),
                "encryption": tunnel.get("encryption"),
                "mac_or_prf": tunnel.get("integrity"),
            }
        )
        record["peer"] = tunnel.get("peer")
        record["limitations"].append(
            "tunnel crypto is the configured proposal set; the negotiated CHILD_SA is only visible in IKE_AUTH"
        )
        if _norm(tunnel.get("encryption")) in {"des", "3des", "null"}:
            record["policy_issues"].append(f"DEVICE_WEAK_VPN_ENCRYPTION:{tunnel.get('encryption')}")
        if _norm(tunnel.get("integrity")) in {"hmac-md5", "hmac-sha1", "md5"}:
            record["policy_issues"].append(f"DEVICE_WEAK_VPN_INTEGRITY:{tunnel.get('integrity')}")
        if _norm(tunnel.get("dh_group")) in {"modp-768", "modp-1024", "modp-1536", "group1", "group2", "group5"}:
            record["policy_issues"].append(f"DEVICE_WEAK_VPN_DH_GROUP:{tunnel.get('dh_group')}")
        records.append(record)

    for entry in device.get("trustpoints") or []:
        if not isinstance(entry, dict):
            continue
        record = _base(
            device,
            plane="CONTROL",
            protocol="PKI",
            surface=f"trustpoint:{entry.get('name') or 'unnamed'}",
            evidence_type="NETWORK_CONFIGURED",
            status="DECLARED",
        )
        record["certificate"] = {
            "subject": entry.get("subject"),
            "issuer": entry.get("issuer"),
            "public_key_algorithm": entry.get("public_key_algorithm"),
            "public_key_bits": entry.get("public_key_bits"),
            "signature_algorithm": entry.get("signature_algorithm"),
            "not_after": entry.get("not_after"),
        }
        record["decomposition"]["authentication"] = entry.get("public_key_algorithm")
        record["decomposition"]["key_size_bits"] = entry.get("public_key_bits")
        records.append(record)

    return records


def summarize_devices(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Count surfaces, roles and the exposures an operator must fix first."""
    records = list(records)
    by_role: dict[str, int] = {}
    by_plane: dict[str, int] = {}
    protocols: dict[str, int] = {}
    issues: dict[str, int] = {}
    devices: set[str] = set()
    declared = observed = 0
    telnet: set[str] = set()
    legacy_snmp: set[str] = set()
    plaintext_admin: set[str] = set()

    for record in records:
        device = record.get("device") or {}
        name = str(device.get("name") or "")
        if name:
            devices.add(name)
        by_role[str(device.get("role") or "UNKNOWN")] = by_role.get(str(device.get("role") or "UNKNOWN"), 0) + 1
        plane = str(device.get("plane") or "UNKNOWN")
        by_plane[plane] = by_plane.get(plane, 0) + 1
        protocol = str(record.get("protocol") or "UNKNOWN").upper()
        protocols[protocol] = protocols.get(protocol, 0) + 1
        if record.get("evidence_type") == "NETWORK_ACTIVE_OBSERVED":
            observed += 1
        elif record.get("evidence_type") == "NETWORK_CONFIGURED":
            declared += 1
        for issue in record.get("policy_issues") or []:
            key = issue.split(":")[0]
            issues[key] = issues.get(key, 0) + 1
            if key == "DEVICE_TELNET_MANAGEMENT_ENABLED" and name:
                telnet.add(name)
            if key == "DEVICE_LEGACY_SNMP" and name:
                legacy_snmp.add(name)
            if key == "DEVICE_PLAINTEXT_ADMIN_UI" and name:
                plaintext_admin.add(name)

    return {
        "model": MODEL,
        "devices": len(devices),
        "surfaces": len(records),
        "by_role": by_role,
        "by_plane": by_plane,
        "protocols": protocols,
        "issues": issues,
        "telnet_devices": sorted(telnet),
        "legacy_snmp_devices": sorted(legacy_snmp),
        "plaintext_admin_devices": sorted(plaintext_admin),
        "declared": declared,
        "observed": observed,
        "not_observed": len([r for r in records if r.get("observation_status") == "NOT_OBSERVED"]),
        "read_only": True,
        "configuration_changes": 0,
        "limitations": [
            "device surfaces are read from exports/API declarations unless a probe observed them",
            "SNMP v3 user/auth/privacy protocol detail is reported only when the export includes it",
            "CryptoScan never authenticates to a device and never writes configuration",
        ],
    }


def to_device_cbom_assets(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Project device surfaces into CBOM assets, one role per plane."""
    assets: list[dict[str, Any]] = []
    not_observed: list[str] = []
    for record in records:
        plane = str((record.get("device") or {}).get("plane") or "UNKNOWN")
        role = _PLANE_ROLE.get(plane, ROLE_DEVICE_CONTROL)
        if record.get("evidence_type") != "NETWORK_ACTIVE_OBSERVED" and not record.get("tls_version"):
            target = (record.get("target") or {}).get("endpoint")
            if target:
                not_observed.append(str(target))
        decomposition = record.get("decomposition") or {}
        device = record.get("device") or {}
        for algorithm, kind in (
            (decomposition.get("encryption"), "bulk"),
            (decomposition.get("key_exchange"), "key-exchange"),
            (decomposition.get("mac_or_prf"), "integrity"),
            ((record.get("certificate") or {}).get("public_key_algorithm"), "authentication"),
        ):
            if not algorithm:
                continue
            assets.append(
                {
                    "algorithm": str(algorithm),
                    "role": role,
                    "kind": kind,
                    "layer": "NETWORK_DEVICE",
                    "plane": plane,
                    "protocol": record.get("protocol"),
                    "device": device.get("name"),
                    "device_role": device.get("role"),
                    "surface": device.get("surface"),
                    "endpoint": (record.get("target") or {}).get("endpoint"),
                    "evidence_id": record.get("evidence_id"),
                    "evidence_type": record.get("evidence_type"),
                    "observed_at": record.get("observed_at"),
                    "confidence": record.get("confidence"),
                }
            )
    return {
        "model": "cryptoscan.device-cbom/1",
        "layer": "NETWORK_DEVICE",
        "asset_count": len(assets),
        "assets": assets,
        "not_observed": sorted(set(not_observed)),
        "boundary": (
            "device management/control/data-plane crypto as declared or observed — application and "
            "storage crypto on the device are separate layers"
        ),
    }
