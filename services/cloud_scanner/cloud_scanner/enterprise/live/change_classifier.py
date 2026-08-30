"""ZELNX Live Cloud Intelligence Engine — change classification (§2, §14).

Every normalized event is classified into one of:

    NEW_RESOURCE | UPDATED_RESOURCE | DELETED_RESOURCE | CRYPTO_CHANGE |
    IDENTITY_CHANGE | NETWORK_CHANGE

Classification drives the targeted-rescan planner: crypto changes select
crypto scanners, identity changes re-evaluate IAM access, network changes
update topology + crypto paths.  ``impact_of`` returns the required scanner
set for a change so the engine never deep-scans everything (§14).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CHANGE_TYPES, CloudEvent

# event_type -> change_type
EVENT_TO_CHANGE: dict[str, str] = {
    # keys
    "KEY_CREATED": "NEW_RESOURCE",
    "KEY_DISABLED": "CRYPTO_CHANGE",
    "KEY_ENABLED": "CRYPTO_CHANGE",
    "KEY_ROTATED": "CRYPTO_CHANGE",
    "KEY_SCHEDULED_FOR_DELETION": "UPDATED_RESOURCE",
    "KEY_POLICY_CHANGED": "IDENTITY_CHANGE",
    "KEY_PERMISSION_CHANGED": "IDENTITY_CHANGE",
    "KEY_ALGORITHM_CHANGED": "CRYPTO_CHANGE",
    "KEY_PROTECTION_LEVEL_CHANGED": "CRYPTO_CHANGE",
    # certificates
    "CERTIFICATE_CREATED": "NEW_RESOURCE",
    "CERTIFICATE_RENEWED": "CRYPTO_CHANGE",
    "CERTIFICATE_REPLACED": "CRYPTO_CHANGE",
    "CERTIFICATE_EXPIRED": "CRYPTO_CHANGE",
    "CERTIFICATE_REVOKED": "CRYPTO_CHANGE",
    "CERTIFICATE_ALGORITHM_CHANGED": "CRYPTO_CHANGE",
    # network
    "NEW_PUBLIC_ENDPOINT": "NETWORK_CHANGE",
    "NEW_PRIVATE_ENDPOINT": "NETWORK_CHANGE",
    "LOAD_BALANCER_CHANGE": "NETWORK_CHANGE",
    "TLS_TERMINATION_CHANGE": "NETWORK_CHANGE",
    "API_GATEWAY_CHANGE": "NETWORK_CHANGE",
    "VPN_CHANGE": "NETWORK_CHANGE",
    "ROUTE_CHANGE": "NETWORK_CHANGE",
    "SECURITY_POLICY_CHANGE": "NETWORK_CHANGE",
    "NETWORK_PEERING_CHANGE": "NETWORK_CHANGE",
    "CROSS_CLOUD_CONNECTION": "NETWORK_CHANGE",
    # kubernetes
    "K8S_NEW_NAMESPACE": "NEW_RESOURCE",
    "K8S_NEW_WORKLOAD": "NEW_RESOURCE",
    "K8S_NEW_INGRESS": "NETWORK_CHANGE",
    "K8S_CERTIFICATE_CHANGED": "CRYPTO_CHANGE",
    "K8S_MTLS_CHANGED": "CRYPTO_CHANGE",
    "K8S_MESH_CHANGED": "NETWORK_CHANGE",
    "K8S_IMAGE_CHANGED": "UPDATED_RESOURCE",
    "K8S_CRYPTO_DEPENDENCY_CHANGED": "CRYPTO_CHANGE",
    # serverless
    "SERVERLESS_NEW_DEPLOYMENT": "NEW_RESOURCE",
    "SERVERLESS_NEW_VERSION": "UPDATED_RESOURCE",
    "SERVERLESS_DEPENDENCY_CHANGE": "CRYPTO_CHANGE",
    "SERVERLESS_RUNTIME_CHANGE": "UPDATED_RESOURCE",
    "SERVERLESS_ENV_CONFIG_CHANGE": "UPDATED_RESOURCE",
    "SERVERLESS_KEY_REF_CHANGE": "CRYPTO_CHANGE",
    "SERVERLESS_CERT_REF_CHANGE": "CRYPTO_CHANGE",
    # generic
    "RESOURCE_DISCOVERED": "NEW_RESOURCE",
    "RESOURCE_CHANGED": "UPDATED_RESOURCE",
    "RESOURCE_REMOVED": "DELETED_RESOURCE",
    "KEY_CHANGED": "CRYPTO_CHANGE",
    "CERTIFICATE_CHANGED": "CRYPTO_CHANGE",
    "TLS_CHANGED": "CRYPTO_CHANGE",
    "NETWORK_CHANGED": "NETWORK_CHANGE",
    "DEPENDENCY_CHANGED": "UPDATED_RESOURCE",
}

# change_type -> scanners needed for the targeted rescan (§14)
CHANGE_TO_SCANNERS: dict[str, list[str]] = {
    "NEW_RESOURCE": ["inventory", "key_discovery", "certificate_discovery",
                     "encryption_discovery", "network_crypto", "tls_discovery"],
    "UPDATED_RESOURCE": ["inventory", "encryption_discovery"],
    "DELETED_RESOURCE": ["inventory"],
    "CRYPTO_CHANGE": ["key_discovery", "certificate_discovery", "tls_discovery",
                      "pqc_readiness", "dependency_graph", "compliance_mapping"],
    "IDENTITY_CHANGE": ["iam_access", "dependency_graph"],
    "NETWORK_CHANGE": ["network_crypto", "tls_discovery", "dependency_graph",
                       "pqc_readiness"],
}


@dataclass
class ClassifiedChange:
    """A change classified for targeted action."""

    event: CloudEvent
    change_type: str
    scanners: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event.event_id,
            "resource_id": self.event.resource_id,
            "provider": self.event.provider,
            "event_type": self.event.event_type,
            "change_type": self.change_type,
            "scanners": list(self.scanners),
        }


def classify_change(event: CloudEvent, *, override: str | None = None) -> ClassifiedChange:
    """Classify a normalized event; unknown event types fall back to the
    change type the caller supplies or UPDATED_RESOURCE."""
    change_type = override or EVENT_TO_CHANGE.get(event.event_type, "UPDATED_RESOURCE")
    if change_type not in CHANGE_TYPES:
        change_type = "UPDATED_RESOURCE"
    scanners = list(CHANGE_TO_SCANNERS.get(change_type, []))
    return ClassifiedChange(event=event, change_type=change_type, scanners=scanners)


def scanner_set_for(event_type: str) -> list[str]:
    """Required scanner set for an event type (impact analysis, §14)."""
    return classify_change(CloudEvent(
        event_id="", provider="", event_type=event_type, change_type="")).scanners
