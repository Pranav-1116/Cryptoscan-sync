"""ZELNX Live Cloud Intelligence Engine — universal cloud event schema (§6).

Every provider's event model is normalized into ONE shape so the engine
never has to think in per-cloud terms:

    CloudEvent
    ├── event_id
    ├── provider
    ├── organization_id
    ├── account_id
    ├── subscription_id
    ├── project_id
    ├── resource_id
    ├── resource_type
    ├── region
    ├── event_type
    ├── change_type
    ├── timestamp
    ├── actor_reference
    ├── source
    ├── evidence_reference
    └── confidence

Provider-specific detail is preserved in ``provider_metadata`` — never
dropped during normalization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CloudEvent:
    """One normalized universal cloud event."""

    event_id: str
    provider: str  # aws | azure | gcp
    event_type: str
    change_type: str
    resource_id: str = ""
    resource_type: str = ""
    organization_id: str = ""
    account_id: str = ""
    subscription_id: str = ""
    project_id: str = ""
    region: str = ""
    timestamp: str = ""
    actor_reference: str = ""
    source: str = ""  # events | audit | api_state | reconciliation | deep_discovery
    evidence_reference: str = ""
    confidence: str = "MEDIUM"  # MEASURED | PROVIDER_REPORTED | ESTIMATED | ASSUMED
    provider_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "provider": self.provider,
            "event_type": self.event_type,
            "change_type": self.change_type,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "organization_id": self.organization_id,
            "account_id": self.account_id,
            "subscription_id": self.subscription_id,
            "project_id": self.project_id,
            "region": self.region,
            "timestamp": self.timestamp,
            "actor_reference": self.actor_reference,
            "source": self.source,
            "evidence_reference": self.evidence_reference,
            "confidence": self.confidence,
            "provider_metadata": dict(self.provider_metadata),
        }


CHANGE_TYPES = (
    "NEW_RESOURCE",
    "UPDATED_RESOURCE",
    "DELETED_RESOURCE",
    "CRYPTO_CHANGE",
    "IDENTITY_CHANGE",
    "NETWORK_CHANGE",
)

EVENT_TYPES = (
    # keys (§8)
    "KEY_CREATED", "KEY_DISABLED", "KEY_ENABLED", "KEY_ROTATED",
    "KEY_SCHEDULED_FOR_DELETION", "KEY_POLICY_CHANGED", "KEY_PERMISSION_CHANGED",
    "KEY_ALGORITHM_CHANGED", "KEY_PROTECTION_LEVEL_CHANGED",
    # certificates (§9)
    "CERTIFICATE_CREATED", "CERTIFICATE_RENEWED", "CERTIFICATE_REPLACED",
    "CERTIFICATE_EXPIRED", "CERTIFICATE_REVOKED", "CERTIFICATE_ALGORITHM_CHANGED",
    # network (§10)
    "NEW_PUBLIC_ENDPOINT", "NEW_PRIVATE_ENDPOINT", "LOAD_BALANCER_CHANGE",
    "TLS_TERMINATION_CHANGE", "API_GATEWAY_CHANGE", "VPN_CHANGE", "ROUTE_CHANGE",
    "SECURITY_POLICY_CHANGE", "NETWORK_PEERING_CHANGE", "CROSS_CLOUD_CONNECTION",
    # kubernetes (§11)
    "K8S_NEW_NAMESPACE", "K8S_NEW_WORKLOAD", "K8S_NEW_INGRESS",
    "K8S_CERTIFICATE_CHANGED", "K8S_MTLS_CHANGED", "K8S_MESH_CHANGED",
    "K8S_IMAGE_CHANGED", "K8S_CRYPTO_DEPENDENCY_CHANGED",
    # serverless (§12)
    "SERVERLESS_NEW_DEPLOYMENT", "SERVERLESS_NEW_VERSION",
    "SERVERLESS_DEPENDENCY_CHANGE", "SERVERLESS_RUNTIME_CHANGE",
    "SERVERLESS_ENV_CONFIG_CHANGE", "SERVERLESS_KEY_REF_CHANGE",
    "SERVERLESS_CERT_REF_CHANGE",
    # generic (§18)
    "RESOURCE_DISCOVERED", "RESOURCE_CHANGED", "RESOURCE_REMOVED",
    "KEY_CHANGED", "CERTIFICATE_CHANGED", "TLS_CHANGED", "NETWORK_CHANGED",
    "DEPENDENCY_CHANGED",
)


def is_valid_event_type(event_type: str) -> bool:
    return str(event_type or "") in EVENT_TYPES


def is_valid_change_type(change_type: str) -> bool:
    return str(change_type or "") in CHANGE_TYPES
