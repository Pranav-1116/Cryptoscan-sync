"""Validated, tenant-neutral network inventory document.

This module is the data contract for the network scanner's ten inventory
areas: devices, topology, configuration, services, security controls, WAN,
monitoring, wireless, firmware/software and documentation. It deliberately
stores references and observations, never passwords, community strings,
private keys, tokens or authentication material.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class InventoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, populate_by_name=True)


class Location(InventoryModel):
    datacenter: str | None = None
    building: str | None = None
    floor: str | None = None
    room: str | None = None
    rack: str | None = None
    ru_position: str | None = None
    coverage_area: str | None = None


class Firmware(InventoryModel):
    os: str | None = None
    version: str | None = None
    current_version: str | None = None
    latest_stable_version: str | None = None
    last_updated: date | None = None
    security_patches: list[str] = Field(default_factory=list)
    known_vulnerabilities: list[str] = Field(default_factory=list)
    upgrade_path: str | None = None


class NetworkInterface(InventoryModel):
    name: str
    interface_type: str | None = None
    speed: str | None = None
    status: Literal["up", "down", "admin_down", "unknown"] = "unknown"
    vlan: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    connected_to: str | None = None
    mac_address: str | None = None


class Redundancy(InventoryModel):
    mode: str | None = None
    ha_pair: str | None = None
    protocol: str | None = None
    cluster_members: list[str] = Field(default_factory=list)
    failover_tested_on: date | None = None
    backup_device: str | None = None


class PortConfiguration(InventoryModel):
    total_ports: int | None = Field(default=None, ge=0)
    used_ports: int | None = Field(default=None, ge=0)
    available_ports: int | None = Field(default=None, ge=0)
    port_speeds: list[str] = Field(default_factory=list)
    port_types: list[str] = Field(default_factory=list)


class FirewallConfiguration(InventoryModel):
    deployment_mode: Literal["TRANSPARENT_L2", "ROUTED_L3", "VIRTUAL_VM", "CLOUD_NATIVE", "UNKNOWN"] = "UNKNOWN"
    rated_throughput_gbps: float | None = Field(default=None, ge=0)
    features_enabled: list[Literal["IPS_IDS", "SSL_INSPECTION", "THREAT_INTELLIGENCE", "APPLICATION_CONTROL", "URL_FILTERING", "OTHER"]] = Field(default_factory=list)
    rule_base_reference: str | None = None
    high_availability: str | None = None
    cluster_members: list[str] = Field(default_factory=list)


class LoadBalancerConfiguration(InventoryModel):
    load_balancer_type: Literal["ADC", "L4", "L7", "UNKNOWN"] = "UNKNOWN"
    algorithms: list[str] = Field(default_factory=list)
    ssl_offloading: bool | None = None
    health_checks: list[str] = Field(default_factory=list)
    virtual_servers: list[str] = Field(default_factory=list)


class WirelessConfiguration(InventoryModel):
    controller_reference: str | None = None
    access_points: list[str] = Field(default_factory=list)
    ssids: list[str] = Field(default_factory=list)
    security: list[str] = Field(default_factory=list)
    frequencies: list[str] = Field(default_factory=list)


class NetworkApplianceCapabilities(InventoryModel):
    ids_ips: bool | None = None
    ddos_protection: bool | None = None
    vpn_concentrator: bool | None = None
    proxy_server: bool | None = None
    dns_server: bool | None = None
    dhcp_server: bool | None = None
    nac: bool | None = None


class NetworkDevice(InventoryModel):
    device_id: str = Field(min_length=1, max_length=160)
    device_type: Literal["router", "switch", "firewall", "load_balancer", "wireless_controller", "access_point", "ids_ips", "ddos", "vpn_concentrator", "proxy", "dns_server", "dhcp_server", "nac", "network_appliance", "other"]
    subtype: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    hardware_revision: str | None = None
    module_slots: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    location: Location = Field(default_factory=Location)
    management_ip: str | None = None
    management_fqdn: str | None = None
    role: str | None = None
    criticality: Literal["critical", "high", "medium", "low", "unknown"] = "unknown"
    redundancy: Redundancy = Field(default_factory=Redundancy)
    firmware: Firmware = Field(default_factory=Firmware)
    interfaces: list[NetworkInterface] = Field(default_factory=list)
    switch: PortConfiguration | None = None
    vlan_configuration: list[str] = Field(default_factory=list)
    spanning_tree: str | None = None
    stacking_vss: str | None = None
    firewall: FirewallConfiguration | None = None
    load_balancer: LoadBalancerConfiguration | None = None
    wireless: WirelessConfiguration | None = None
    appliance_capabilities: NetworkApplianceCapabilities = Field(default_factory=NetworkApplianceCapabilities)
    discovery_source: Literal["SNMP", "SSH", "API", "NMAP", "CONFIG_IMPORT", "MANUAL", "OTHER"] = "MANUAL"
    last_seen: datetime | None = None


class Cable(InventoryModel):
    cable_id: str | None = None
    cable_type: Literal["FIBER", "COPPER", "WIRELESS", "UNKNOWN"] = "UNKNOWN"
    length: str | None = None
    patch_panel_connection: str | None = None
    label: str | None = None


class PhysicalConnection(InventoryModel):
    connection_id: str
    source_device: str
    source_interface: str | None = None
    target_device: str
    target_interface: str | None = None
    cable: Cable = Field(default_factory=Cable)
    redundant: bool | None = None
    status: Literal["UP", "DOWN", "UNKNOWN"] = "UNKNOWN"


class LogicalSegment(InventoryModel):
    segment_id: str
    name: str
    trust_zone: str | None = None
    vlans: list[int] = Field(default_factory=list)
    subnets: list[str] = Field(default_factory=list)
    gateway: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    routing_protocol: str | None = None
    routing_area: str | None = None
    ospf_area: str | None = None
    bgp_as_number: int | None = None
    connected_segments: list[str] = Field(default_factory=list)
    segment_type: Literal["PRODUCTION", "DEVELOPMENT", "MANAGEMENT", "OUT_OF_BAND", "DMZ", "GUEST", "RESTRICTED", "OTHER"] | None = None


class DataFlow(InventoryModel):
    flow_id: str
    application: str | None = None
    source: str
    destination: str
    path: list[str] = Field(default_factory=list)
    traffic_direction: Literal["NORTH_SOUTH", "EAST_WEST", "INTERNAL", "UNKNOWN"] = "UNKNOWN"
    peak_bandwidth: str | None = None
    average_bandwidth: str | None = None
    critical: bool | None = None
    bottlenecks: list[str] = Field(default_factory=list)


class TopologySection(InventoryModel):
    architecture: Literal["THREE_TIER", "SPINE_LEAF", "HUB_SPOKE", "FULL_MESH", "PARTIAL_MESH", "OTHER", "UNKNOWN"] = "UNKNOWN"
    network_diagram_reference: str | None = None
    physical_topology_reference: str | None = None
    logical_topology_reference: str | None = None
    cabling: list[Cable] = Field(default_factory=list)
    physical_connections: list[PhysicalConnection] = Field(default_factory=list)
    redundant_paths: list[str] = Field(default_factory=list)
    cable_management: str | None = None
    network_segments: list[LogicalSegment] = Field(default_factory=list)
    data_flows: list[DataFlow] = Field(default_factory=list)
    application_flows_reference: str | None = None
    critical_paths: list[str] = Field(default_factory=list)


class DeviceConfiguration(InventoryModel):
    device_id: str
    running_config_reference: str | None = None
    startup_config_reference: str | None = None
    last_backup_at: datetime | None = None
    backup_location_reference: str | None = None
    version_control_reference: str | None = None
    change_tracking_reference: str | None = None
    drift_detection_enabled: bool | None = None
    template_reference: str | None = None


class RoutingConfiguration(InventoryModel):
    static_routes: list[str] = Field(default_factory=list)
    ospf_areas: list[str] = Field(default_factory=list)
    ospf_neighbors: list[str] = Field(default_factory=list)
    bgp_peers: list[str] = Field(default_factory=list)
    bgp_as_numbers: list[int] = Field(default_factory=list)
    bgp_route_filters: list[str] = Field(default_factory=list)
    eigrp: list[str] = Field(default_factory=list)
    isis: list[str] = Field(default_factory=list)
    route_redistribution: list[str] = Field(default_factory=list)
    default_routes: list[str] = Field(default_factory=list)
    policy_based_routing: list[str] = Field(default_factory=list)


class SwitchingConfiguration(InventoryModel):
    vlans: list[dict[str, Any]] = Field(default_factory=list)
    trunk_ports: list[str] = Field(default_factory=list)
    native_vlan: str | None = None
    spanning_tree_root_bridge: str | None = None
    spanning_tree_priorities: dict[str, int] = Field(default_factory=dict)
    port_states: dict[str, str] = Field(default_factory=dict)
    mac_address_limiting: str | None = None
    sticky_mac: bool | None = None
    violation_actions: list[str] = Field(default_factory=list)
    port_channels_lag: list[str] = Field(default_factory=list)
    qos_policies: list[str] = Field(default_factory=list)


class SecurityConfiguration(InventoryModel):
    standard_acls: list[str] = Field(default_factory=list)
    extended_acls: list[str] = Field(default_factory=list)
    named_acls: list[str] = Field(default_factory=list)
    applied_interfaces: dict[str, list[str]] = Field(default_factory=dict)
    firewall_rules_reference: str | None = None
    allow_deny_rules: list[str] = Field(default_factory=list)
    nat_rules: list[str] = Field(default_factory=list)
    application_rules: list[str] = Field(default_factory=list)
    microsegmentation: str | None = None
    vlan_isolation: str | None = None
    firewall_zones: list[str] = Field(default_factory=list)


class ConfigurationSection(InventoryModel):
    device_configurations: list[DeviceConfiguration] = Field(default_factory=list)
    routing: RoutingConfiguration = Field(default_factory=RoutingConfiguration)
    switching: SwitchingConfiguration = Field(default_factory=SwitchingConfiguration)
    security: SecurityConfiguration = Field(default_factory=SecurityConfiguration)


class DnsService(InventoryModel):
    authoritative_servers: list[str] = Field(default_factory=list)
    recursive_servers: list[str] = Field(default_factory=list)
    zones: list[str] = Field(default_factory=list)
    records_reference: str | None = None
    dnssec_enabled: bool | None = None
    dns_filtering: str | None = None
    split_dns: str | None = None
    server_type: str | None = None
    version: str | None = None


class DhcpScope(InventoryModel):
    subnet: str
    address_range: str | None = None
    lease_time: str | None = None
    gateway: str | None = None
    dns_servers: list[str] = Field(default_factory=list)
    reservations_reference: str | None = None


class DhcpService(InventoryModel):
    primary_servers: list[str] = Field(default_factory=list)
    backup_servers: list[str] = Field(default_factory=list)
    scopes: list[DhcpScope] = Field(default_factory=list)
    options: dict[str, str] = Field(default_factory=dict)


class NtpService(InventoryModel):
    servers: list[str] = Field(default_factory=list)
    stratum_levels: dict[str, int] = Field(default_factory=dict)
    authentication_enabled: bool | None = None
    time_zones: list[str] = Field(default_factory=list)


class IpamService(InventoryModel):
    allocation_reference: str | None = None
    subnet_plan_reference: str | None = None
    used_vs_available: dict[str, str] = Field(default_factory=dict)
    asset_ip_mapping_reference: str | None = None
    rogue_device_detection: bool | None = None


class NetworkAuthentication(InventoryModel):
    dot1x_enabled: bool | None = None
    radius_servers: list[str] = Field(default_factory=list)
    tacacs_servers: list[str] = Field(default_factory=list)
    nac_reference: str | None = None
    endpoint_compliance: str | None = None
    credential_reference: str | None = None


class NetworkServices(InventoryModel):
    dns: DnsService = Field(default_factory=DnsService)
    dhcp: DhcpService = Field(default_factory=DhcpService)
    ntp: NtpService = Field(default_factory=NtpService)
    ipam: IpamService = Field(default_factory=IpamService)
    authentication: NetworkAuthentication = Field(default_factory=NetworkAuthentication)


class VpnConfiguration(InventoryModel):
    site_to_site_tunnels: list[str] = Field(default_factory=list)
    remote_sites: list[str] = Field(default_factory=list)
    encryption_algorithms: list[str] = Field(default_factory=list)
    tunnel_endpoints: list[str] = Field(default_factory=list)
    remote_access_type: str | None = None
    concentrators: list[str] = Field(default_factory=list)
    authentication_methods: list[str] = Field(default_factory=list)
    split_tunneling: bool | None = None
    user_capacity: int | None = Field(default=None, ge=0)
    sdwan_overlay_reference: str | None = None


class TlsInspection(InventoryModel):
    inspection_points: list[str] = Field(default_factory=list)
    certificate_reference: str | None = None
    bypass_lists: list[str] = Field(default_factory=list)
    privacy_considerations: str | None = None


class NetworkSecurityControls(InventoryModel):
    internet_edge: list[str] = Field(default_factory=list)
    dmz_reference: str | None = None
    inbound_rules: list[str] = Field(default_factory=list)
    outbound_rules: list[str] = Field(default_factory=list)
    ddos_protection: list[str] = Field(default_factory=list)
    segmentation: list[str] = Field(default_factory=list)
    zero_trust_architecture: str | None = None
    east_west_firewalling: str | None = None
    microsegmentation: str | None = None
    vpn: VpnConfiguration = Field(default_factory=VpnConfiguration)
    sdwan: str | None = None
    ids_ips_deployment: Literal["INLINE", "PASSIVE", "HYBRID", "UNKNOWN"] = "UNKNOWN"
    ids_ips_detection_methods: list[str] = Field(default_factory=list)
    ids_ips_signature_version: str | None = None
    ids_ips_policies: list[str] = Field(default_factory=list)
    ids_ips_alert_configuration: str | None = None
    tls_inspection: TlsInspection = Field(default_factory=TlsInspection)
    nac_posture_assessment: str | None = None
    quarantine_network: str | None = None
    guest_network: str | None = None
    device_registration: str | None = None


class IspCircuit(InventoryModel):
    provider: str
    priority: Literal["PRIMARY", "BACKUP", "TERTIARY", "UNKNOWN"] = "UNKNOWN"
    circuit_id: str | None = None
    connection_type: str | None = None
    committed_information_rate: str | None = None
    burst_capacity: str | None = None
    upload_speed: str | None = None
    download_speed: str | None = None
    as_number: int | None = None
    bgp_peers: list[str] = Field(default_factory=list)
    route_advertisements: list[str] = Field(default_factory=list)
    prefix_filters: list[str] = Field(default_factory=list)


class MplsConnectivity(InventoryModel):
    provider: str | None = None
    sites_connected: list[str] = Field(default_factory=list)
    class_of_service: str | None = None
    sla: str | None = None


class SdwanConnectivity(InventoryModel):
    solution: str | None = None
    version: str | None = None
    overlay_network: str | None = None
    underlay_connections: list[str] = Field(default_factory=list)
    application_aware_routing: str | None = None
    zero_touch_provisioning: bool | None = None


class CloudConnectivity(InventoryModel):
    aws_direct_connect: list[str] = Field(default_factory=list)
    azure_express_route: list[str] = Field(default_factory=list)
    gcp_interconnect: list[str] = Field(default_factory=list)
    cloud_vpn: list[str] = Field(default_factory=list)


class DatacenterInterconnect(InventoryModel):
    technology: list[str] = Field(default_factory=list)
    bandwidth: str | None = None
    latency: str | None = None
    redundancy: list[str] = Field(default_factory=list)


class WanConnectivity(InventoryModel):
    isp_circuits: list[IspCircuit] = Field(default_factory=list)
    mpls: MplsConnectivity = Field(default_factory=MplsConnectivity)
    sdwan: SdwanConnectivity = Field(default_factory=SdwanConnectivity)
    cloud: CloudConnectivity = Field(default_factory=CloudConnectivity)
    datacenter_interconnect: DatacenterInterconnect = Field(default_factory=DatacenterInterconnect)


class MonitoringSection(InventoryModel):
    nms_systems: list[str] = Field(default_factory=list)
    snmp_version: Literal["v2c", "v3", "NONE", "UNKNOWN"] = "UNKNOWN"
    snmp_traps_reference: str | None = None
    flow_protocols: list[Literal["NETFLOW", "SFLOW", "IPFIX", "OTHER"]] = Field(default_factory=list)
    flow_collectors: list[str] = Field(default_factory=list)
    span_mirror_ports: list[str] = Field(default_factory=list)
    network_taps: list[str] = Field(default_factory=list)
    packet_analyzers: list[str] = Field(default_factory=list)
    bandwidth_monitoring: str | None = None
    latency_monitoring: str | None = None
    jitter_monitoring: str | None = None
    packet_loss_monitoring: str | None = None
    application_performance_monitoring: str | None = None
    syslog_servers: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    log_retention: str | None = None
    siem_integration: str | None = None
    audit_logs: str | None = None
    configuration_management: list[str] = Field(default_factory=list)
    infrastructure_as_code: list[str] = Field(default_factory=list)
    api_access_reference: str | None = None
    sdn_controllers: list[str] = Field(default_factory=list)


class WirelessNetworks(InventoryModel):
    controller: str | None = None
    indoor_access_points: list[str] = Field(default_factory=list)
    outdoor_access_points: list[str] = Field(default_factory=list)
    coverage_map_reference: str | None = None
    wireless_standards: list[str] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=list)
    transmit_power: str | None = None
    corporate_ssid: dict[str, Any] = Field(default_factory=dict)
    guest_ssid: dict[str, Any] = Field(default_factory=dict)
    iot_ssid: dict[str, Any] = Field(default_factory=dict)
    encryption: list[str] = Field(default_factory=list)
    client_isolation: bool | None = None
    rogue_ap_detection: bool | None = None
    wireless_ids_ips: str | None = None
    mac_filtering: str | None = None


class FirmwareSoftwareSection(InventoryModel):
    operating_systems: list[dict[str, Any]] = Field(default_factory=list)
    current_versions: dict[str, str] = Field(default_factory=dict)
    latest_stable_versions: dict[str, str] = Field(default_factory=dict)
    security_patches: list[dict[str, Any]] = Field(default_factory=list)
    known_vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    upgrade_paths: list[str] = Field(default_factory=list)
    management_software: list[dict[str, Any]] = Field(default_factory=list)
    sdn_controller_versions: dict[str, str] = Field(default_factory=dict)
    orchestration_platforms: list[str] = Field(default_factory=list)
    network_analytics: list[str] = Field(default_factory=list)
    automation_frameworks: list[str] = Field(default_factory=list)


class DocumentationSection(InventoryModel):
    physical_topology_reference: str | None = None
    logical_topology_reference: str | None = None
    application_flow_reference: str | None = None
    security_zone_reference: str | None = None
    wan_diagram_reference: str | None = None
    ip_plan_reference: str | None = None
    ip_documentation_reference: str | None = None
    reserved_ranges: list[str] = Field(default_factory=list)
    public_ips_reference: str | None = None
    configuration_standards_reference: str | None = None
    change_management_reference: str | None = None
    incident_response_reference: str | None = None
    disaster_recovery_reference: str | None = None
    escalation_procedures_reference: str | None = None
    support_contracts_reference: str | None = None
    maintenance_contracts_reference: str | None = None
    vendor_contacts_reference: str | None = None
    spare_parts_reference: str | None = None


class InventoryEvidence(InventoryModel):
    evidence_id: str = Field(min_length=1)
    evidence_type: Literal["DISCOVERY", "CONFIGURATION", "TOPOLOGY", "MONITORING", "DOCUMENTATION", "ATTESTATION", "OTHER"]
    reference: str = Field(min_length=1)
    status: Literal["PASS", "FAIL", "PENDING", "UNVERIFIED", "EXPIRED"] = "UNVERIFIED"
    captured_at: datetime | None = None
    source_system: str | None = None
    collector: str | None = None
    sha256: str | None = None
    limitations: list[str] = Field(default_factory=list)

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("evidence sha256 must be a 64-character hexadecimal digest")
        return value


class NetworkInventoryDocument(InventoryModel):
    inventory_schema: str = Field(default="cryptoscan.network-inventory/1", alias="schema")
    inventory_id: str | None = None
    captured_at: datetime | None = None
    source: Literal["SNMP", "SSH", "API", "NMAP", "CONFIG_IMPORT", "MANUAL", "MIXED"] = "MANUAL"
    devices: list[NetworkDevice] = Field(default_factory=list)
    topology: TopologySection = Field(default_factory=TopologySection)
    configuration: ConfigurationSection = Field(default_factory=ConfigurationSection)
    network_services: NetworkServices = Field(default_factory=NetworkServices)
    security_controls: NetworkSecurityControls = Field(default_factory=NetworkSecurityControls)
    wan_connectivity: WanConnectivity = Field(default_factory=WanConnectivity)
    monitoring: MonitoringSection = Field(default_factory=MonitoringSection)
    wireless_networks: WirelessNetworks = Field(default_factory=WirelessNetworks)
    firmware_software: FirmwareSoftwareSection = Field(default_factory=FirmwareSoftwareSection)
    documentation: DocumentationSection = Field(default_factory=DocumentationSection)
    evidence: list[InventoryEvidence] = Field(default_factory=list)

    @field_validator("inventory_schema")
    @classmethod
    def validate_schema(cls, value: str) -> str:
        if value != "cryptoscan.network-inventory/1":
            raise ValueError("unsupported network inventory schema")
        return value


_SECRET_KEY = re.compile(r"(?i)(password|community_string|secret|token|private_key|api_key|credential|shared_key)")
_SECRET_VALUE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|bearer\s+[a-z0-9._-]{20,}|[?&](?:token|api[_-]?key|password|secret)=[^&\s]+", re.IGNORECASE)


def reject_secrets(value: Any, path: str = "inventory") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            key_text = str(key)
            # References identify an external vault/document/artifact; they do
            # not contain the secret and are intentionally allowed.
            is_reference = key_text.lower().endswith(("_reference", "_ref"))
            if _SECRET_KEY.search(key_text) and not is_reference:
                raise ValueError(f"secret-bearing field is not accepted: {child_path}; use a reference")
            reject_secrets(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str) and _SECRET_VALUE.search(value):
        raise ValueError(f"secret value is not accepted at {path}")


def parse_inventory(value: dict[str, Any]) -> NetworkInventoryDocument:
    reject_secrets(value)
    return NetworkInventoryDocument.model_validate(value)


_REQUIRED_SECTIONS = (
    ("devices", lambda d: d.devices),
    ("topology", lambda d: d.topology.network_segments or d.topology.physical_connections or d.topology.network_diagram_reference),
    ("configuration", lambda d: d.configuration.device_configurations or d.configuration.routing.model_dump(exclude_defaults=True) or d.configuration.security.model_dump(exclude_defaults=True)),
    ("network_services", lambda d: d.network_services.model_dump(exclude_defaults=True)),
    ("security_controls", lambda d: d.security_controls.model_dump(exclude_defaults=True)),
    ("wan_connectivity", lambda d: d.wan_connectivity.model_dump(exclude_defaults=True)),
    ("monitoring", lambda d: d.monitoring.model_dump(exclude_defaults=True)),
    ("wireless_networks", lambda d: d.wireless_networks.model_dump(exclude_defaults=True)),
    ("firmware_software", lambda d: d.firmware_software.model_dump(exclude_defaults=True)),
    ("documentation", lambda d: d.documentation.model_dump(exclude_defaults=True)),
    ("evidence", lambda d: d.evidence),
)


def _present(value: Any) -> bool:
    if value is None or value == "" or value == [] or value == {}:
        return False
    if isinstance(value, dict):
        return any(_present(child) for child in value.values())
    return True


def inventory_completeness(document: NetworkInventoryDocument) -> dict[str, Any]:
    missing: list[str] = []
    sections: dict[str, dict[str, Any]] = {}
    for name, getter in _REQUIRED_SECTIONS:
        try:
            present = _present(getter(document))
        except (AttributeError, TypeError):
            present = False
        if not present:
            missing.append(name)
        sections[name] = {
            "status": "COMPLETE" if present else "INCOMPLETE",
            "score": 100.0 if present else 0.0,
            "missing": [] if present else [name],
            "next_actions": [] if present else [f"Provide {name} observations or mark the source limitation"],
        }
    present_count = len(_REQUIRED_SECTIONS) - len(missing)
    score = round((present_count / len(_REQUIRED_SECTIONS)) * 100, 2)
    return {
        "score": score,
        "status": "COMPLETE" if not missing else "INCOMPLETE",
        "required_sections": len(_REQUIRED_SECTIONS),
        "present_sections": present_count,
        "missing": missing,
        "next_actions": [f"Provide {name} observations or an evidence-backed unknown record" for name in missing],
        "sections": sections,
    }


def inventory_approval_issues(document: NetworkInventoryDocument) -> list[str]:
    issues: list[str] = []
    if not document.evidence:
        issues.append("evidence: at least one evidence record is required")
    for evidence in document.evidence:
        if evidence.status != "PASS":
            issues.append(f"evidence.{evidence.evidence_id}: status must be PASS")
    if document.devices and any(not device.management_ip for device in document.devices):
        issues.append("devices: every device needs a management IP or an evidence-backed exception")
    if document.monitoring.snmp_version == "UNKNOWN" and not document.monitoring.nms_systems:
        issues.append("monitoring: monitoring source and SNMP posture are unknown")
    if not document.documentation.disaster_recovery_reference:
        issues.append("documentation.disaster_recovery_reference: missing")
    return issues


def inventory_hash(document: NetworkInventoryDocument) -> str:
    payload = document.model_dump(mode="json", by_alias=True)
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def inventory_risk(document: NetworkInventoryDocument) -> dict[str, Any]:
    completeness = inventory_completeness(document)
    score = min(100.0, 100.0 - completeness["score"])
    factors: list[dict[str, Any]] = []

    def add(factor: str, points: float, reason: str) -> None:
        nonlocal score
        score += points
        factors.append({"factor": factor, "points": points, "reason": reason})

    if not document.devices:
        add("device_inventory", 15, "No physical or virtual network devices are recorded")
    else:
        unknown_management = sum(1 for item in document.devices if not item.management_ip)
        unknown_firmware = sum(1 for item in document.devices if not item.firmware.version)
        if unknown_management:
            add("management_identity", min(15, unknown_management * 2), "One or more devices lack a management address")
        if unknown_firmware:
            add("firmware_visibility", min(15, unknown_firmware * 2), "One or more devices lack firmware/version visibility")
    if not document.security_controls.inbound_rules or not document.security_controls.outbound_rules:
        add("perimeter_policy", 10, "Inbound or outbound perimeter rules are not recorded")
    if document.monitoring.snmp_version in {"UNKNOWN", "NONE"} and not document.monitoring.nms_systems:
        add("monitoring", 10, "No NMS or supported monitoring source is recorded")
    if not document.documentation.disaster_recovery_reference:
        add("network_recovery", 8, "Network disaster-recovery documentation is missing")
    if document.security_controls.vpn.split_tunneling is True:
        add("vpn_split_tunnel", 6, "Remote-access VPN split tunneling is enabled")
    score = round(min(100.0, score), 2)
    rating = "UNKNOWN" if completeness["status"] != "COMPLETE" else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
    return {
        "risk_score": score,
        "risk_rating": rating,
        "status": "INCOMPLETE" if completeness["status"] != "COMPLETE" else "EVALUATED",
        "completeness": completeness,
        "factors": factors,
        "disclaimer": "Network inventory screening signal only; absence of observations is not evidence that a control exists.",
    }


__all__ = [
    "NetworkInventoryDocument", "NetworkDevice", "TopologySection", "ConfigurationSection",
    "NetworkServices", "NetworkSecurityControls", "WanConnectivity", "MonitoringSection",
    "WirelessNetworks", "FirmwareSoftwareSection", "DocumentationSection", "InventoryEvidence",
    "parse_inventory", "inventory_completeness", "inventory_approval_issues", "inventory_hash", "inventory_risk",
]
