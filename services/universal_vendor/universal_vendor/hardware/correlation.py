"""Hardware-to-software / network / cloud correlation (§11–§13).

§11 hardware→software: physical server → CPU/TPM/NIC/HBA/HSM interface → OS
→ crypto libraries → applications → certificates/keys. Answers: "which
physical hardware ultimately supports this cryptographic operation?"

§12 hardware→network: physical server → NIC → switch → firewall → load
balancer → application.

§13 hardware→cloud: distinguish PHYSICAL HARDWARE vs VIRTUAL HARDWARE vs
CLOUD RESOURCE with the OBSERVED / PROVIDER_DECLARED / INFERRED / UNKNOWN
ladder — never claim physical host knowledge the provider hides.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_vendor.graph import VendorGraph


class HardwareCorrelationEngine:
    def __init__(self, graph: Optional[VendorGraph] = None) -> None:
        self.graph = graph or VendorGraph()

    # ── §11 hardware → software ────────────────────────────────────────

    def link_hardware_to_software(
        self, *, server: str, component: str, operating_system: str,
        crypto_library: str, application: str, certificate: str,
    ) -> None:
        """server → component (CPU/TPM/NIC/HBA/HSM) → OS → lib → app → cert."""
        self.graph.add_node(server, asset_type="server")
        self.graph.add_node(component, asset_type=component.lower()
                            if component.lower() in ("tpm", "hsm") else "component")
        self.graph.add_edge(server, component, "HOSTS_COMPONENT")
        self.graph.add_edge(component, operating_system, "SUPPORTS")
        self.graph.add_edge(operating_system, crypto_library, "USES")
        self.graph.add_edge(crypto_library, application, "POWERS")
        self.graph.add_edge(application, certificate, "USES")

    def underlying_hardware(self, certificate: str, max_depth: int = 6) -> list[str]:
        """Answer: which physical hardware supports this crypto operation?"""
        paths = self.graph.paths_reverse(certificate) if hasattr(
            self.graph, "paths_reverse") else self._reverse_paths(certificate, max_depth)
        return paths

    def _reverse_paths(self, target: str, max_depth: int) -> list[str]:
        hardware: list[str] = []
        for node in self.graph.nodes():
            if node.get("asset_type") in ("server", "hsm", "tpm"):
                if self.graph.paths(node["id"], target, max_depth=max_depth):
                    hardware.append(node["id"])
        return hardware

    # ── §12 hardware → network ─────────────────────────────────────────

    def link_hardware_to_network(
        self, *, server: str, nic: str, switch: str, firewall: str,
        load_balancer: str, application: str,
    ) -> None:
        self.graph.add_edge(server, nic, "CONTAINS")
        self.graph.add_edge(nic, switch, "LINKS_TO")
        self.graph.add_edge(switch, firewall, "LINKS_TO")
        self.graph.add_edge(firewall, load_balancer, "PROTECTS")
        self.graph.add_edge(load_balancer, application, "SERVES")

    def network_relationships(self, server: str) -> list[dict[str, Any]]:
        """§12 — when NIC hardware changes, which network relationships are
        affected: NIC → switch → firewall → load balancer → application."""
        out: list[dict[str, Any]] = []
        for node in self.graph.nodes():
            nid = node.get("id") or node.get("asset_id")
            if not nid or nid == server:
                continue
            if self.graph.paths(server, nid, max_depth=6):
                out.append({"node": nid,
                            "asset_type": node.get("asset_type") or "unknown"})
        return out

    # ── §13 hardware → cloud ───────────────────────────────────────────

    def cloud_visibility(self, raw: dict[str, Any]) -> str:
        """Classify what we can honestly claim about cloud hardware."""
        from universal_vendor.hardware.models import CloudVisibility

        declared = raw.get("provider_declared")
        observed = raw.get("observed")
        instance_type = raw.get("instance_type")
        if observed:
            return CloudVisibility.OBSERVED.value
        if declared:
            return CloudVisibility.PROVIDER_DECLARED.value
        if instance_type:
            return CloudVisibility.INFERRED.value
        return CloudVisibility.UNKNOWN.value

    def link_cloud_resource(self, *, cloud_vm: str, instance_type: str,
                            provider_capability: str, virtual_capability: str) -> None:
        """Cloud VM → instance type → provider hardware capability → virtual
        crypto capability (§13 example)."""
        self.graph.add_node(cloud_vm, asset_type="cloud_resource")
        self.graph.add_node(instance_type, asset_type="instance_type")
        self.graph.add_node(provider_capability, asset_type="hardware_capability")
        self.graph.add_node(virtual_capability, asset_type="virtual_capability")
        self.graph.add_edge(cloud_vm, instance_type, "HAS_TYPE")
        self.graph.add_edge(instance_type, provider_capability, "PROVIDES")
        self.graph.add_edge(provider_capability, virtual_capability, "ENABLES")
