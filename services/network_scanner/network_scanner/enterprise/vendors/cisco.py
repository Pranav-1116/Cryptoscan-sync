"""Cisco network scanner — device classification + crypto configuration parsing.

Covers IOS / IOS-XE / IOS-XR / NX-OS / ASA / Firepower / Meraki / Catalyst /
Nexus / ISR / ASR and wireless infrastructure. Cryptography is extracted from
structured configuration (``show running-config`` text or controller APIs):

- VPN: IPsec transform sets, IKEv1 policies, IKEv2 proposals, DH groups, PFS,
  certificate vs pre-shared-key authentication (PSK *metadata only*)
- SSH: version, host-key algorithms, KEX / MAC / cipher configuration
- TLS: protocol versions and trustpoints where configured
- routing-protocol authentication: OSPF message-digest areas, BGP neighbor
  encryption algorithms, key-chain algorithms (key material always redacted)
- PKI: trustpoints + certificate chains, trust anchors, crypto licenses,
  hardware crypto capability

Never emits secret material — key strings / passwords are stripped.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from network_scanner.enterprise.vendors.base import NetworkVendorPlugin, register_plugin
from network_scanner.enterprise.credentials import scrub_secrets

IOS_PLATFORMS = {
    # device families first: a Catalyst/Nexus banner identifies the family
    "catalyst": "Catalyst",
    "nexus": "Nexus",
    # software tokens before series tokens: "Cisco IOS XE Software, ASR1000"
    # is an IOS-XE device, while "Cisco ASR 1000 Series" (no IOS banner) is ASR.
    "ios-xr": "IOS-XR",
    "ios-xe": "IOS-XE",
    # banners spell it "Cisco IOS XE Software" / "Cisco IOS XR Software" (space)
    "ios xe": "IOS-XE",
    "ios xr": "IOS-XR",
    "ios": "IOS",
    "isr": "ISR",
    "asr": "ASR",
    "meraki": "Meraki",
    "asa": "ASA",
    "adaptive security": "ASA",
    "firepower": "Firepower",
    "nx-os": "NX-OS",
}

WEAK_IKE_ENCR = {"des", "3des"}
WEAK_IKE_HASH = {"md5", "sha", "sha1"}
WEAK_DH_GROUPS = {1, 2, 5}
WEAK_ESP = {"esp-des", "esp-3des", "esp-md5-hmac", "esp-sha-hmac"}


def classify_cisco_device(version_text: str, model: str | None = None, descr: str = "") -> dict[str, Any]:
    """Map version banner / model string to platform + device type."""
    banner = f"{version_text} {model or ''} {descr}".lower()
    platform = "IOS"
    for token, name in IOS_PLATFORMS.items():
        if token in banner:
            platform = name
            break
    device_type = "router"
    if platform in ("Catalyst", "Nexus") or "switch" in banner:
        device_type = "switch"
    if platform in ("ASA", "Firepower") or "firewall" in banner:
        device_type = "firewall"
    if "wireless" in banner or "controller" in banner and "wireless" in banner:
        device_type = "wireless_controller"
    if platform == "Meraki":
        device_type = "cloud_appliance"
    return {"platform": platform, "device_type": device_type}


# ------------------------------------------------------------------ parsing


def _lines(text: str) -> list[str]:
    return [line.rstrip() for line in text.splitlines()]


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def parse_ikev1_policies(lines: list[str]) -> list[dict[str, Any]]:
    """Parse 'crypto isakmp policy N' blocks (and 'crypto isakmp key' lines
    as PSK metadata only — the key itself is never captured)."""
    policies: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        stripped = line.strip()
        match = re.match(r"^crypto isakmp policy\s+(\d+)$", stripped)
        if match:
            if current:
                policies.append(current)
            current = {"policy": int(match.group(1)), "encryption": None, "hash": None,
                       "authentication": None, "group": None}
            continue
        if current is not None and stripped and _indent(line) <= 0 and not stripped.startswith(("crypto isakmp", "crypto ikev2")):
            policies.append(current)
            current = None
            continue
        if current is not None:
            if stripped.startswith("encryption "):
                current["encryption"] = stripped.split(None, 1)[1]
            elif stripped.startswith("hash "):
                current["hash"] = stripped.split(None, 1)[1]
            elif stripped.startswith("authentication "):
                current["authentication"] = stripped.split(None, 1)[1]
            elif stripped.startswith("group "):
                current["group"] = int(stripped.split()[1])
    if current:
        policies.append(current)
    return policies


def parse_ikev2_proposals(lines: list[str]) -> list[dict[str, Any]]:
    proposals: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        stripped = line.strip()
        match = re.match(r"^crypto ikev2 proposal\s+(\S+)$", stripped)
        if match:
            if current:
                proposals.append(current)
            current = {"name": match.group(1), "encryption": [], "integrity": [], "group": []}
            continue
        if current is not None and stripped and _indent(line) <= 0 and not stripped.startswith(("crypto ikev2", "crypto ipsec")):
            proposals.append(current)
            current = None
            continue
        if current is not None:
            if stripped.startswith("encryption "):
                current["encryption"] = stripped.split()[1:]
            elif stripped.startswith("integrity "):
                current["integrity"] = stripped.split()[1:]
            elif stripped.startswith("group "):
                current["group"] = [int(g) for g in stripped.split()[1:]]
    if current:
        proposals.append(current)
    return proposals


def parse_ipsec_transform_sets(lines: list[str]) -> list[dict[str, Any]]:
    sets: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in lines:
        stripped = line.strip()
        match = re.match(r"^crypto ipsec transform-set\s+(\S+)\s*(.*)$", stripped)
        if match:
            if current:
                sets.append(current)
            current = {"name": match.group(1), "esp": match.group(2).split() or []}
            continue
        if current is not None and stripped and _indent(line) <= 0 and not stripped.startswith("crypto ipsec"):
            sets.append(current)
            current = None
            continue
        if current is not None and stripped.startswith("mode ") and current["esp"]:
            current["mode"] = stripped.split()[1]
    if current:
        sets.append(current)
    return sets


def parse_vpn_metadata(lines: list[str]) -> dict[str, Any]:
    """VPN crypto summary + PFS + auth mode; PSK presence and *peer addresses*
    are metadata only — the key string itself is never captured."""
    pfs_groups: list[int] = []
    psk_used = False
    psk_peers: list[str] = []
    cert_auth = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("set pfs"):
            tokens = stripped.split()
            if len(tokens) >= 3 and tokens[2].lower().startswith("group"):
                try:
                    pfs_groups.append(int(tokens[2].replace("group", "")))
                except ValueError:
                    pass
        if stripped.startswith("crypto isakmp key"):
            psk_used = True
            match = re.search(r"\baddress\s+(\S+)", stripped)
            if match:
                peer = match.group(1)
                if peer not in psk_peers:
                    psk_peers.append(peer)
        if re.match(r"^crypto (isakmp|ikev2) (policy|proposal)", stripped) is None and "authentication rsa-sig" in stripped:
            cert_auth = True
    return {"pfs_groups": sorted(set(pfs_groups)), "pfs_configured": bool(pfs_groups),
            "pre_shared_key_used": psk_used, "psk_peers": sorted(psk_peers),
            "certificate_authentication": cert_auth}


def parse_ssh_config(lines: list[str]) -> dict[str, Any]:
    ssh: dict[str, Any] = {"version": None, "host_key_algorithms": [], "kex": [], "mac": [], "ciphers": []}
    for line in lines:
        stripped = line.strip()
        if re.match(r"^ip ssh version\s+", stripped):
            try:
                ssh["version"] = int(stripped.split()[-1])
            except ValueError:
                pass
        elif re.match(r"^ip ssh server algorithm", stripped):
            tokens = stripped.split()
            if "host-key" in tokens:
                ssh["host_key_algorithms"] = tokens[tokens.index("host-key") + 1:]
            elif "kex" in tokens:
                ssh["kex"] = tokens[tokens.index("kex") + 1:]
            elif "mac" in tokens:
                ssh["mac"] = tokens[tokens.index("mac") + 1:]
            elif "encryption" in tokens:
                ssh["ciphers"] = tokens[tokens.index("encryption") + 1:]
        elif re.match(r"^ip ssh ciphertext", stripped):
            ssh["ciphers"] = stripped.split()[2:]
    return ssh


def parse_tls_config(lines: list[str]) -> dict[str, Any]:
    tls: dict[str, Any] = {"versions": [], "trustpoints": [], "ciphers": []}
    for line in lines:
        stripped = line.strip()
        if re.match(r"^ssl\s+(version|server-version|client-version)", stripped):
            tls["versions"] = stripped.split()[2:]
        if stripped.startswith(("crypto ca trustpoint", "crypto pki trustpoint")):
            tls["trustpoints"].append(stripped.split()[-1])
        if stripped.startswith("ssl cipher") or stripped.startswith("tls cipher"):
            tls["ciphers"] = stripped.split()[2:]
    return tls


def parse_certificate_chains(lines: list[str]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    in_chain = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("crypto ca certificate chain", "crypto pki certificate chain")):
            if current:
                chains.append(current)
            current = {"name": stripped.split()[-1], "certificates": [], "trustpoint": None}
            in_chain = True
            continue
        if current is not None and in_chain:
            if stripped.startswith("certificate"):
                current["certificates"].append("***PEM-REDACTED***")
            elif stripped.startswith("quit"):
                in_chain = False
            elif stripped.startswith(("crypto ca trustpoint", "crypto pki trustpoint")):
                current["trustpoint"] = stripped.split()[-1]
    if current:
        chains.append(current)
    return chains


def parse_routing_auth(lines: list[str]) -> dict[str, Any]:
    routing: dict[str, Any] = {"ospf_authenticated_areas": [], "bgp_neighbors": [], "key_chains": []}
    current_key_chain: dict[str, Any] | None = None
    for line in lines:
        stripped = line.strip()
        if re.match(r"^router ospf\s", stripped):
            pass
        match = re.match(r"^area\s+(\S+)\s+authentication\s+(message-digest)?", stripped)
        if match:
            routing["ospf_authenticated_areas"].append(
                {"area": match.group(1), "algorithm": "MD5" if match.group(2) else "plaintext"}
            )
        match = re.match(r"^neighbor\s+(\S+)\s+encryption\s+algorithm\s+(\S+)", stripped)
        if match:
            routing["bgp_neighbors"].append({"neighbor": match.group(1), "algorithm": match.group(2).lower()})
        match = re.match(r"^neighbor\s+(\S+)\s+password", stripped)
        if match:
            routing["bgp_neighbors"].append({"neighbor": match.group(1),
                                             "algorithm": "password",
                                             "secret_redacted": True})
        if stripped.startswith("key chain"):
            if current_key_chain:
                routing["key_chains"].append(current_key_chain)
            current_key_chain = {"name": stripped.split()[-1], "keys": []}
            continue
        if current_key_chain is not None and stripped.startswith("cryptographic-algorithm"):
            current_key_chain["keys"].append({"algorithm": stripped.split()[-1], "key_string_redacted": True})
    if current_key_chain:
        routing["key_chains"].append(current_key_chain)
    return routing


def parse_crypto_licenses(lines: list[str]) -> dict[str, Any]:
    licenses: list[str] = []
    for line in lines:
        stripped = line.strip()
        if re.match(r"^technology-package", stripped):
            licenses.append(stripped)
        elif re.match(r"^license\s+", stripped) and "crypto" in stripped.lower():
            licenses.append(stripped)
    return {"crypto_licenses": licenses}


def parse_hardware_crypto(lines: list[str]) -> dict[str, Any]:
    """Look for hardware crypto capability hints (e.g. 'Hardware crypto
    accelerator: Enabled' from show version / show platform)."""
    for line in lines:
        stripped = line.strip().lower()
        if "crypto" in stripped and any(token in stripped for token in ("accelerator", "engine", "vpn module")):
            return {"hardware_crypto": stripped}
    return {"hardware_crypto": None}


def parse_cisco_running_config(text: str) -> dict[str, Any]:
    """Parse a Cisco running-config into a structured crypto profile."""
    lines = _lines(text)
    ikev1 = parse_ikev1_policies(lines)
    ikev2 = parse_ikev2_proposals(lines)
    ipsec = parse_ipsec_transform_sets(lines)
    vpn = parse_vpn_metadata(lines)
    ssh = parse_ssh_config(lines)
    tls = parse_tls_config(lines)
    chains = parse_certificate_chains(lines)
    routing = parse_routing_auth(lines)
    licenses = parse_crypto_licenses(lines)
    hardware = parse_hardware_crypto(lines)

    weak: list[str] = []
    for policy in ikev1:
        if (policy.get("encryption") or "").lower() in WEAK_IKE_ENCR:
            weak.append(f"WEAK_IKEV1_ENCRYPTION:{policy['policy']}:{policy['encryption']}")
        if (policy.get("hash") or "").lower() in WEAK_IKE_HASH:
            weak.append(f"WEAK_IKEV1_HASH:{policy['policy']}:{policy['hash']}")
        if policy.get("group") in WEAK_DH_GROUPS:
            weak.append(f"WEAK_IKEV1_DH_GROUP:{policy['policy']}:{policy['group']}")
    for proposal in ikev2:
        for enc in proposal.get("encryption") or []:
            if enc.lower() in WEAK_IKE_ENCR:
                weak.append(f"WEAK_IKEV2_ENCRYPTION:{proposal['name']}:{enc}")
        for integ in proposal.get("integrity") or []:
            if integ.lower() in WEAK_IKE_HASH:
                weak.append(f"WEAK_IKEV2_INTEGRITY:{proposal['name']}:{integ}")
        for group in proposal.get("group") or []:
            if group in WEAK_DH_GROUPS:
                weak.append(f"WEAK_IKEV2_DH_GROUP:{proposal['name']}:{group}")
    for ts in ipsec:
        for esp in ts.get("esp") or []:
            if esp.lower() in WEAK_ESP:
                weak.append(f"WEAK_IPSEC_ESP:{ts['name']}:{esp}")
    if vpn.get("pfs_groups") and all(g in WEAK_DH_GROUPS for g in vpn["pfs_groups"]):
        weak.append("WEAK_PFS_GROUP")
    if ssh.get("version") and ssh["version"] < 2:
        weak.append("WEAK_SSH_VERSION")
    if not vpn.get("pfs_configured"):
        weak.append("IPSEC_NO_PFS")
    for area in routing.get("ospf_authenticated_areas") or []:
        if area.get("algorithm") == "plaintext":
            weak.append(f"OSPF_PLAINTEXT_AUTH:{area['area']}")

    return {
        "ikev1": ikev1,
        "ikev2": ikev2,
        "ipsec_transform_sets": ipsec,
        "vpn": vpn,
        "ssh": ssh,
        "tls": tls,
        "pki": {"certificate_chains": chains,
                "trustpoints": tls.get("trustpoints") or [],
                "trust_anchors": [c["name"] for c in chains]},
        "routing_auth": routing,
        "licenses": licenses,
        "hardware": hardware,
        "issues": sorted(set(weak)),
    }


# ------------------------------------------------------------------ plugin


class CiscoPlugin(NetworkVendorPlugin):
    """Cisco IOS-family device discovery + crypto configuration collection."""

    vendor = "cisco"
    device_types = ("router", "switch", "firewall", "wireless_controller",
                    "vpn_gateway", "cloud_appliance", "load_balancer")

    def discover_devices(self, targets: list[str], **kw: Any) -> list[dict[str, Any]]:
        """Discover via injected discovery client (SNMP / RESTCONF / controller
        API). Without a client, fall back to safe transport probes."""
        client = kw.get("client") or self.options.get("client")
        devices: list[dict[str, Any]] = []
        if client is not None and hasattr(client, "list_devices"):
            try:
                devices = list(client.list_devices() or [])
            except Exception as exc:  # noqa: BLE001
                devices = [{"error": str(exc)[:200]}]
        for target in targets:
            devices.append({"ip": target, "vendor": "Cisco", "source": "probe"})
        return devices

    def collect_inventory(self, device: dict[str, Any], **kw: Any) -> dict[str, Any]:
        version_text = kw.get("version_text") or device.get("version_banner") or ""
        classification = classify_cisco_device(
            version_text,
            model=kw.get("model") or device.get("model"),
            descr=str(device.get("sys_descr") or ""),
        )
        return {
            "asset_identity": device.get("asset_identity") or device.get("ip"),
            "ip_addresses": [device.get("ip")] if device.get("ip") else [],
            "hostname": device.get("hostname") or device.get("sys_name"),
            "manufacturer": "Cisco",
            "model": device.get("model"),
            "os": classification["platform"],
            "os_version": kw.get("os_version") or device.get("os_version"),
            "device_type": classification["device_type"],
            "platform": classification["platform"],
            "interfaces": device.get("interfaces") or [],
            "routes": device.get("routes") or [],
        }

    def collect_crypto_configuration(self, device: dict[str, Any], **kw: Any) -> dict[str, Any]:
        """Parse injected running-config text (or a controller API payload)."""
        running = kw.get("running_config")
        if running is None:
            running = device.get("running_config")
        if isinstance(running, dict):
            return dict(running)  # already structured (e.g. from controller API)
        if isinstance(running, str):
            profile = parse_cisco_running_config(running)
            profile["config_available"] = True
            return scrub_secrets(profile)
        # No config available: record what was observable via probes (SSH/TLS/IPsec)
        return {
            "ikev1": [], "ikev2": [], "ipsec_transform_sets": [], "vpn": {},
            "ssh": device.get("ssh") or {}, "tls": device.get("tls") or {},
            "pki": {"certificate_chains": [], "trustpoints": [], "trust_anchors": []},
            "routing_auth": {}, "licenses": {}, "hardware": {}, "issues": [],
            "config_available": False,
        }

    def collect_certificates(self, device: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
        profile = kw.get("crypto_profile") or device.get("crypto_profile") or {}
        chains = ((profile.get("pki") or {}).get("certificate_chains")) or []
        return [{"name": chain.get("name"), "trustpoint": chain.get("trustpoint"),
                 "certificate_pem_redacted": bool(chain.get("certificates")),
                 "source": "running-config"} for chain in chains]

    def collect_protocols(self, device: dict[str, Any], **kw: Any) -> list[dict[str, Any]]:
        """Protocols configured on the device (CRYPTOGRAPHY_CONFIGURED)."""
        profile = kw.get("crypto_profile") or device.get("crypto_profile") or {}
        protocols: list[dict[str, Any]] = []
        if profile.get("ikev1") or profile.get("ikev2"):
            protocols.append({"protocol": "IPsec", "status": "CRYPTOGRAPHY_CONFIGURED",
                              "detail": f"ikev1={len(profile.get('ikev1') or [])} "
                                        f"ikev2={len(profile.get('ikev2') or [])}"})
        if profile.get("ssh", {}).get("version"):
            protocols.append({"protocol": "SSH", "status": "CRYPTOGRAPHY_CONFIGURED",
                              "detail": f"version={profile['ssh'].get('version')}"})
        if profile.get("tls", {}).get("trustpoints") or profile.get("tls", {}).get("versions"):
            protocols.append({"protocol": "TLS", "status": "CRYPTOGRAPHY_CONFIGURED",
                              "detail": "trustpoints configured"})
        if profile.get("routing_auth", {}).get("ospf_authenticated_areas"):
            protocols.append({"protocol": "OSPF-AUTH", "status": "CRYPTOGRAPHY_CONFIGURED"})
        if profile.get("routing_auth", {}).get("bgp_neighbors"):
            protocols.append({"protocol": "BGP-AUTH", "status": "CRYPTOGRAPHY_CONFIGURED"})
        return protocols

    def collect_topology(self, devices: list[dict[str, Any]], **kw: Any) -> list[dict[str, Any]]:
        """CDP/LLDP-style adjacency hints from injected data, or route tables."""
        edges: list[dict[str, Any]] = []
        for device in devices:
            source = device.get("asset_identity") or device.get("ip")
            for route in device.get("routes") or []:
                next_hop = route.get("routeNextHop")
                if next_hop:
                    edges.append({"from": source, "to": next_hop, "relationship": "ROUTES_TO",
                                  "source": "snmp-route-table"})
            for neighbor in device.get("neighbors") or []:
                edges.append({"from": source, "to": neighbor, "relationship": "CONNECTED_TO",
                              "source": "cdp/lldp"})
        return edges

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        inventory = self.collect_inventory(raw)
        return {
            "asset_identity": inventory["asset_identity"],
            "ip_addresses": inventory["ip_addresses"],
            "hostname": inventory["hostname"],
            "fqdn": raw.get("fqdn"),
            "device_type": inventory["device_type"],
            "manufacturer": "Cisco",
            "model": inventory["model"],
            "os": inventory["os"],
            "os_version": inventory["os_version"],
            "discovery_confidence": 0.9 if raw.get("source") in ("controller", "snmp") else 0.5,
            "source": raw.get("source") or "probe",
            "extra": {"platform": inventory["platform"]},
        }


register_plugin(CiscoPlugin)


# ------------------------------------------------------------------ controller adapters


class CiscoControllerAdapter:
    """Base for controller-managed discovery (Meraki, DNA Center, SD-WAN, ACI,
    Firepower Management Center). Controllers give far better accuracy than
    probing — inventory, topology, crypto and security policy over their API."""

    controller_kind = "controller"

    def __init__(self, client: Any, *, vault=None, **options: Any) -> None:
        self.client = client
        self.vault = vault
        self.options = options

    def list_devices(self) -> list[dict[str, Any]]:
        if hasattr(self.client, "list_devices"):
            return list(self.client.list_devices() or [])
        raise NotImplementedError(f"{self.controller_kind} client has no list_devices")

    def collect_crypto(self, device: dict[str, Any]) -> dict[str, Any]:
        if hasattr(self.client, "collect_crypto"):
            return self.client.collect_crypto(device.get("serial") or device.get("id"))
        return {"config_available": False}

    def collect_topology(self) -> list[dict[str, Any]]:
        if hasattr(self.client, "topology"):
            return list(self.client.topology() or [])
        return []


class MerakiControllerAdapter(CiscoControllerAdapter):
    controller_kind = "meraki"


class DnaCenterControllerAdapter(CiscoControllerAdapter):
    controller_kind = "dna-center"


class SdwanControllerAdapter(CiscoControllerAdapter):
    controller_kind = "sd-wan"


class AciControllerAdapter(CiscoControllerAdapter):
    controller_kind = "aci"


class FirepowerControllerAdapter(CiscoControllerAdapter):
    controller_kind = "firepower-mc"
