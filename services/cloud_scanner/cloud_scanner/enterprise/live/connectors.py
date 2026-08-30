"""ZELNX Live Cloud Intelligence Engine — provider connectors (§3–5) and
universal event normalization (§6).

Each provider has a connector over three source families:
- real-time events (event bus / event grid / pub-sub)
- audit / activity logs (CloudTrail / Activity Logs / Cloud Audit Logs)
- resource APIs (continuous state polls)

Connectors are fully injectable: raw payloads come from callables, so
tests need no cloud SDKs.  The normalizer maps provider-specific event
names to the universal event schema while preserving provider-specific
detail in ``provider_metadata``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.live.event_schema import CloudEvent

PayloadSource = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


# provider event-name hints -> universal event type (hints are normalized
# the same way as the token: lower, no spaces/dashes/slashes)
_AWS_EVENT_MAP = {
    "kms:creat": "KEY_CREATED",
    "kms:disable": "KEY_DISABLED",
    "kms:enable": "KEY_ENABLED",
    "kms:rotate": "KEY_ROTATED",
    "kms:schedulekeydeletion": "KEY_SCHEDULED_FOR_DELETION",
    "kms:putkeypolicy": "KEY_POLICY_CHANGED",
    "kms:creategrant": "KEY_PERMISSION_CHANGED",
    "acm:import": "CERTIFICATE_CREATED",
    "acm:renew": "CERTIFICATE_RENEWED",
    "acm:delete": "CERTIFICATE_REVOKED",
    "elbv2:createlistener": "LOAD_BALANCER_CHANGE",
    "elbv2:modifylistener": "TLS_TERMINATION_CHANGE",
    "ec2:createvpn": "VPN_CHANGE",
    "ec2:createroute": "ROUTE_CHANGE",
    "ec2:authorizesecuritygroup": "SECURITY_POLICY_CHANGE",
    "eks:createcluster": "K8S_NEW_WORKLOAD",
    "lambda:create": "SERVERLESS_NEW_DEPLOYMENT",
    "lambda:update": "SERVERLESS_NEW_VERSION",
    "iam:putrolepolicy": "KEY_PERMISSION_CHANGED",
}

_AZURE_EVENT_MAP = {
    "microsoft.keyvault/vaults/keys": "KEY_CHANGED",
    "microsoft.keyvault/vaults/certificates": "CERTIFICATE_CREATED",
    "microsoft.network/loadbalancers": "LOAD_BALANCER_CHANGE",
    "microsoft.network/applicationgateways": "LOAD_BALANCER_CHANGE",
    "microsoft.network/vpngateways": "VPN_CHANGE",
    "microsoft.web/sites": "SERVERLESS_NEW_VERSION",
    "microsoft.compute/virtualmachines": "RESOURCE_CHANGED",
    "microsoft.storage/storageaccounts": "RESOURCE_CHANGED",
}

_GCP_EVENT_MAP = {
    "cloudkms": "KEY_CHANGED",
    "certificatemanager": "CERTIFICATE_CHANGED",
    "compute.googleapis.com": "NETWORK_CHANGED",
    "cloudfunctions": "SERVERLESS_NEW_VERSION",
    "run.googleapis.com": "SERVERLESS_NEW_VERSION",
    "container": "K8S_NEW_WORKLOAD",
}


def _normalize_token(value: str) -> str:
    return str(value or "").lower().replace(" ", "").replace("-", "").replace("/", "")


def _match_event_type(provider: str, raw_type: str, raw: dict[str, Any]) -> str:
    """Map a provider event name to a universal event type (hint matching)."""
    token = _normalize_token(raw_type)
    if provider == "aws":
        for hint, event_type in _AWS_EVENT_MAP.items():
            if _normalize_token(hint) in token:
                return event_type
    elif provider == "azure":
        for hint, event_type in _AZURE_EVENT_MAP.items():
            if _normalize_token(hint) in token:
                return event_type
    elif provider == "gcp":
        for hint, event_type in _GCP_EVENT_MAP.items():
            if _normalize_token(hint) in token:
                return event_type
    # fall back to the explicit event_type the source supplies
    return str(_pick(raw, "event_type", "type", default="RESOURCE_CHANGED") or "RESOURCE_CHANGED")


class UniversalEventNormalizer:
    """Normalize raw provider payloads into universal :class:`CloudEvent`."""

    def normalize(self, raw: dict[str, Any], *, provider: str, source: str) -> CloudEvent | None:
        if not isinstance(raw, dict) or not raw:
            return None
        provider = str(provider or raw.get("provider") or "").lower()
        if provider not in ("aws", "azure", "gcp"):
            return None
        raw_type = str(_pick(raw, "event_name", "operation", "resource_type", "event_type",
                             "type", "methodName", "operationName", default="") or "")
        event_type = _match_event_type(provider, raw_type, raw)
        change_type = str(_pick(raw, "change_type", default="") or "")
        event_id = str(_pick(raw, "event_id", "id", "eventId", "messageId",
                             default="") or "") or f"{provider}:{source}:{event_type}:{raw_type}"
        return CloudEvent(
            event_id=event_id,
            provider=provider,
            event_type=event_type,
            change_type=change_type,
            resource_id=str(_pick(raw, "resource_id", "resourceArn", "resourceId", "subject",
                                  "resourceName", "asset_id", default="") or ""),
            resource_type=str(_pick(raw, "resource_type", "resourceType", "service", default="") or ""),
            organization_id=str(_pick(raw, "organization_id", "org_id", "organization",
                                      default="") or ""),
            account_id=str(_pick(raw, "account_id", "account", "aws_account_id", default="") or ""),
            subscription_id=str(_pick(raw, "subscription_id", "subscription", default="") or ""),
            project_id=str(_pick(raw, "project_id", "project", default="") or ""),
            region=str(_pick(raw, "region", "awsRegion", "location", "zone", default="") or ""),
            timestamp=str(_pick(raw, "timestamp", "eventTime", "time", "occurred_at",
                                default="") or ""),
            actor_reference=str(_pick(raw, "actor_reference", "actor", "userIdentity",
                                      "principal", "caller", default="") or ""),
            source=source,
            evidence_reference=str(_pick(raw, "evidence_reference", default="") or ""),
            confidence=str(_pick(raw, "confidence", default="MEDIUM") or "MEDIUM"),
            provider_metadata={k: v for k, v in raw.items()
                               if k not in {"provider", "source"}},
        )


@dataclass
class ProviderConnector:
    """One provider's 24/7 monitoring surface (all sources injectable)."""

    provider: str  # aws | azure | gcp
    event_source: PayloadSource | None = None       # LAYER 1 — realtime events
    audit_source: PayloadSource | None = None       # LAYER 2 — audit/activity logs
    api_state_source: PayloadSource | None = None   # LAYER 3 — continuous API state
    reconcile_source: PayloadSource | None = None   # LAYER 4 — periodic reconciliation
    organization_id: str = ""
    errors: list[dict[str, Any]] = field(default_factory=list)

    def poll_events(self) -> list[CloudEvent]:
        return self._collect("events", self.event_source)

    def poll_audit(self) -> list[CloudEvent]:
        return self._collect("audit", self.audit_source)

    def poll_api_state(self) -> list[CloudEvent]:
        return self._collect("api_state", self.api_state_source)

    def reconcile(self) -> list[CloudEvent]:
        return self._collect("reconciliation", self.reconcile_source)

    def poll_all(self) -> dict[str, list[CloudEvent]]:
        return {
            "events": self.poll_events(),
            "audit": self.poll_audit(),
            "api_state": self.poll_api_state(),
            "reconciliation": self.reconcile(),
        }

    def _collect(self, source: str, callable_: PayloadSource | None) -> list[CloudEvent]:
        if callable_ is None:
            return []
        try:
            rows = callable_() or []
        except Exception as exc:  # noqa: BLE001 — connectors never crash a cycle
            self.errors.append({"provider": self.provider, "source": source,
                                "detail": str(exc)[:300]})
            return []
        normalizer = UniversalEventNormalizer()
        events: list[CloudEvent] = []
        for row in rows:
            event = normalizer.normalize(row, provider=self.provider, source=source)
            if event is None:
                continue
            if self.organization_id and not event.organization_id:
                event.organization_id = self.organization_id
            events.append(event)
        return events


def aws_connector(*, event_source: PayloadSource | None = None,
                  audit_source: PayloadSource | None = None,
                  api_state_source: PayloadSource | None = None,
                  reconcile_source: PayloadSource | None = None,
                  organization_id: str = "") -> ProviderConnector:
    return ProviderConnector(provider="aws", event_source=event_source,
                             audit_source=audit_source, api_state_source=api_state_source,
                             reconcile_source=reconcile_source,
                             organization_id=organization_id)


def azure_connector(*, event_source: PayloadSource | None = None,
                    audit_source: PayloadSource | None = None,
                    api_state_source: PayloadSource | None = None,
                    reconcile_source: PayloadSource | None = None,
                    organization_id: str = "") -> ProviderConnector:
    return ProviderConnector(provider="azure", event_source=event_source,
                             audit_source=audit_source, api_state_source=api_state_source,
                             reconcile_source=reconcile_source,
                             organization_id=organization_id)


def gcp_connector(*, event_source: PayloadSource | None = None,
                  audit_source: PayloadSource | None = None,
                  api_state_source: PayloadSource | None = None,
                  reconcile_source: PayloadSource | None = None,
                  organization_id: str = "") -> ProviderConnector:
    return ProviderConnector(provider="gcp", event_source=event_source,
                             audit_source=audit_source, api_state_source=api_state_source,
                             reconcile_source=reconcile_source,
                             organization_id=organization_id)
