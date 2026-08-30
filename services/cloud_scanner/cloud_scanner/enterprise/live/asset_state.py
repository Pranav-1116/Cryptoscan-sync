"""ZELNX Live Cloud Intelligence Engine — live cloud asset state engine (§7).

Every cloud resource keeps full state history:

    CloudAsset
    ├── Current State
    ├── Previous State
    ├── First Seen
    ├── Last Seen
    ├── Last API Verification
    ├── Last Crypto Verification
    ├── Last Deep Discovery
    ├── Last Change
    ├── Monitoring Status
    └── Evidence History

Transitions produce change records (e.g. an AWS KMS key:
FIRST_SEEN → LAST_SEEN → LAST_CHANGE: ROTATION_CONFIGURATION_CHANGED →
ACTION: CRYPTO_POLICY_REEVALUATION).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent


@dataclass
class StateTransition:
    """One observed transition for an asset."""

    transition_type: str  # FIRST_SEEN | CHANGED | REVERIFIED | REMOVED
    action: str = ""
    previous_state: dict[str, Any] = field(default_factory=dict)
    current_state: dict[str, Any] = field(default_factory=dict)
    change_fields: list[str] = field(default_factory=list)
    event_id: str = ""
    observed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_type": self.transition_type,
            "action": self.action,
            "previous_state": dict(self.previous_state),
            "current_state": dict(self.current_state),
            "change_fields": list(self.change_fields),
            "event_id": self.event_id,
            "observed_at": self.observed_at,
        }


@dataclass
class CloudAsset:
    """Live state + history of one cloud resource."""

    asset_id: str
    provider: str = ""
    account_id: str = ""
    region: str = ""
    resource_type: str = ""
    current_state: dict[str, Any] = field(default_factory=dict)
    previous_state: dict[str, Any] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""
    last_api_verification: str = ""
    last_crypto_verification: str = ""
    last_deep_discovery: str = ""
    last_change: str = ""  # e.g. ROTATION_CONFIGURATION_CHANGED
    last_action: str = ""  # e.g. CRYPTO_POLICY_REEVALUATION
    monitoring_status: str = "ACTIVE"  # ACTIVE | REMOVED | SUSPENDED
    history: list[StateTransition] = field(default_factory=list)
    evidence_history: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "provider": self.provider,
            "account_id": self.account_id,
            "region": self.region,
            "resource_type": self.resource_type,
            "current_state": dict(self.current_state),
            "previous_state": dict(self.previous_state),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_api_verification": self.last_api_verification,
            "last_crypto_verification": self.last_crypto_verification,
            "last_deep_discovery": self.last_deep_discovery,
            "last_change": self.last_change,
            "last_action": self.last_action,
            "monitoring_status": self.monitoring_status,
            "history": [t.to_dict() for t in self.history],
            "evidence_history": list(self.evidence_history),
        }


# action for a change, based on what kind of resource it is
_ACTION_BY_EVENT = {
    "KEY_ROTATED": "CRYPTO_POLICY_REEVALUATION",
    "KEY_DISABLED": "CRYPTO_POLICY_REEVALUATION",
    "KEY_ENABLED": "CRYPTO_POLICY_REEVALUATION",
    "KEY_POLICY_CHANGED": "ACCESS_REVIEW",
    "KEY_PERMISSION_CHANGED": "ACCESS_REVIEW",
    "KEY_ALGORITHM_CHANGED": "PQC_REEVALUATION",
    "KEY_PROTECTION_LEVEL_CHANGED": "PQC_REEVALUATION",
    "CERTIFICATE_RENEWED": "TLS_RECONFIGURATION",
    "CERTIFICATE_REPLACED": "TLS_RECONFIGURATION",
    "CERTIFICATE_EXPIRED": "TLS_RECONFIGURATION",
    "CERTIFICATE_REVOKED": "TLS_RECONFIGURATION",
    "TLS_TERMINATION_CHANGE": "TLS_RECONFIGURATION",
    "VPN_CHANGE": "NETWORK_RECONFIGURATION",
    "ROUTE_CHANGE": "NETWORK_RECONFIGURATION",
    "NEW_PUBLIC_ENDPOINT": "EXPOSURE_REVIEW",
    "K8S_MTLS_CHANGED": "MESH_REEVALUATION",
    "SERVERLESS_DEPENDENCY_CHANGE": "CRYPTO_LIBRARY_REVIEW",
}


def action_for_event(event_type: str) -> str:
    return _ACTION_BY_EVENT.get(event_type, "CRYPTO_POLICY_REEVALUATION")


class LiveCloudAssetStateEngine:
    """Track per-resource state + history; transitions are event-driven."""

    def __init__(self, clock: Any = None) -> None:
        self._assets: dict[str, CloudAsset] = {}
        self._clock = clock or (lambda: "")

    def observe(self, event: CloudEvent | None = None, *, asset_id: str = "",
                provider: str = "", account_id: str = "", region: str = "",
                resource_type: str = "", state: dict[str, Any] | None = None,
                event_type: str = "", observed_at: str = "") -> StateTransition | None:
        """Apply one observation; returns the transition (or None if no-op)."""
        asset_id = (event.resource_id if event is not None else asset_id) or ""
        if not asset_id:
            return None
        provider = (event.provider if event is not None else provider) or ""
        event_type = (event.event_type if event is not None else event_type) or ""
        state = dict(state or {})
        observed_at = observed_at or (event.timestamp if event is not None else "") or self._clock()
        asset = self._assets.get(asset_id)
        if asset is None:
            asset = CloudAsset(
                asset_id=asset_id,
                provider=provider,
                account_id=account_id or (event.account_id if event is not None else ""),
                region=region or (event.region if event is not None else ""),
                resource_type=resource_type or (event.resource_type if event is not None else ""),
                current_state=dict(state),
                first_seen=observed_at,
                last_seen=observed_at,
                monitoring_status="ACTIVE",
            )
            if event is not None:
                asset.account_id = asset.account_id or event.account_id
                asset.region = asset.region or event.region
                asset.resource_type = asset.resource_type or event.resource_type
            transition = StateTransition(
                transition_type="FIRST_SEEN",
                action="ASSET_REGISTRATION",
                current_state=dict(state),
                event_id=(event.event_id if event is not None else ""),
                observed_at=observed_at,
            )
            asset.history.append(transition)
            if event is not None:
                asset.evidence_history.append(event.evidence_reference or event.event_id)
            self._assets[asset_id] = asset
            return transition

        # existing asset: detect change
        prev = dict(asset.current_state)
        changed = self._diff_fields(prev, state)
        asset.previous_state = prev
        asset.current_state = dict(state)
        asset.last_seen = observed_at
        if event is not None:
            asset.account_id = asset.account_id or event.account_id
            asset.region = asset.region or event.region
            asset.resource_type = asset.resource_type or event.resource_type
        if changed:
            asset.last_change = event_type or "RESOURCE_CHANGED"
            asset.last_action = action_for_event(event_type)
            transition = StateTransition(
                transition_type="CHANGED",
                action=asset.last_action,
                previous_state=prev,
                current_state=dict(state),
                change_fields=changed,
                event_id=(event.event_id if event is not None else ""),
                observed_at=observed_at,
            )
            asset.history.append(transition)
            if event is not None:
                asset.evidence_history.append(event.evidence_reference or event.event_id)
            return transition
        transition = StateTransition(
            transition_type="REVERIFIED",
            action="STATE_VERIFIED",
            previous_state=prev,
            current_state=dict(state),
            event_id=(event.event_id if event is not None else ""),
            observed_at=observed_at,
        )
        asset.history.append(transition)
        return transition

    def remove(self, event: CloudEvent | None = None, *, asset_id: str = "",
               observed_at: str = "") -> StateTransition | None:
        asset_id = (event.resource_id if event is not None else asset_id) or ""
        asset = self._assets.get(asset_id)
        if asset is None:
            return None
        asset.monitoring_status = "REMOVED"
        asset.last_seen = observed_at or (event.timestamp if event is not None else "") or self._clock()
        asset.last_change = "RESOURCE_REMOVED"
        asset.last_action = "DEPENDENCY_REBUILD"
        transition = StateTransition(
            transition_type="REMOVED",
            action="DEPENDENCY_REBUILD",
            previous_state=dict(asset.current_state),
            event_id=(event.event_id if event is not None else ""),
            observed_at=asset.last_seen,
        )
        asset.history.append(transition)
        return transition

    def verify(self, asset_id: str, *, kind: str = "api", observed_at: str = "") -> None:
        asset = self._assets.get(asset_id)
        if asset is None:
            return
        stamp = observed_at or self._clock()
        if kind == "crypto":
            asset.last_crypto_verification = stamp
        elif kind == "deep":
            asset.last_deep_discovery = stamp
        else:
            asset.last_api_verification = stamp

    def get(self, asset_id: str) -> CloudAsset | None:
        return self._assets.get(asset_id)

    def all(self) -> list[CloudAsset]:
        return list(self._assets.values())

    def count(self, *, active_only: bool = True) -> int:
        if not active_only:
            return len(self._assets)
        return sum(1 for asset in self._assets.values()
                   if asset.monitoring_status == "ACTIVE")

    def to_dicts(self) -> list[dict[str, Any]]:
        return [asset.to_dict() for asset in self.all()]

    def changed_since(self, observed_at: str) -> list[CloudAsset]:
        return [asset for asset in self._assets.values()
                if asset.last_change and asset.last_seen and asset.last_seen >= observed_at]

    def summary(self) -> dict[str, Any]:
        return {
            "assets": len(self._assets),
            "active": self.count(),
            "removed": self.count(active_only=False) - self.count(),
            "by_provider": {
                provider: sum(1 for a in self._assets.values() if a.provider == provider)
                for provider in ("aws", "azure", "gcp")
            },
        }

    @staticmethod
    def _diff_fields(prev: dict[str, Any], curr: dict[str, Any]) -> list[str]:
        keys = set(prev) | set(curr)
        return sorted(key for key in keys if prev.get(key) != curr.get(key))
