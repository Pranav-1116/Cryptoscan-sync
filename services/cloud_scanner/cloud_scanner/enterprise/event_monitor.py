"""ZELNX Cloud Discovery Engine — cloud event-driven monitoring (spec §21).

    AWS Events ──▶ Azure Events ──▶ GCP Events
        ──▶ Cloud Event Normalizer ──▶ Crypto Change Detector
        ──▶ CBOM Update ──▶ Policy Evaluation ──▶ Drift Detection

Consumes provider event envelopes (metadata only — events are never
scanned for secret values), normalizes them to a single shape, detects
crypto-relevant changes, updates the CBOM, evaluates policy rules and
feeds drift detection — keeping the CBOM close to a live cryptographic
environment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.compliance_mapping import ComplianceMappingEngine, ComplianceReport
from cloud_scanner.enterprise.drift import DriftResult, DriftObservation, classify_drift

EventSink = Callable[[dict[str, Any]], None]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class CloudEvent:
    """One normalized cloud event."""

    event_id: str
    provider: str = ""
    event_type: str = ""
    resource: str = ""
    account: str = ""
    region: str = ""
    occurred_at: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    crypto_relevant: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "provider": self.provider,
            "event_type": self.event_type,
            "resource": self.resource,
            "account": self.account,
            "region": self.region,
            "occurred_at": self.occurred_at,
            "details": dict(self.details),
            "crypto_relevant": self.crypto_relevant,
        }


CRYPTO_EVENT_HINTS = (
    "kms", "keyvault", "cloudkms", "certificate", "acm", "encryption", "tls",
    "secret", "vault", "crypto", "signing", "iam", "permission", "cipher",
    "securitypolicy", "ssl",
)

# provider event name -> normalized event type
EVENT_TYPE_MAP = {
    "aws.kms": "KMS_KEY_CHANGE",
    "aws.acm": "CERTIFICATE_CHANGE",
    "aws.secretsmanager": "SECRET_CHANGE",
    "aws.elbv2": "TLS_POLICY_CHANGE",
    "aws.iam": "PERMISSION_CHANGE",
    "azure.keyvault": "KEY_VAULT_CHANGE",
    "azure.security": "SECURITY_CHANGE",
    "azure.network": "NETWORK_CHANGE",
    "gcp.cloudkms": "CLOUD_KMS_CHANGE",
    "gcp.certificatemanager": "CERTIFICATE_CHANGE",
    "gcp.secretmanager": "SECRET_CHANGE",
}


class CloudEventNormalizer:
    """Normalize provider event envelopes into ``CloudEvent`` rows."""

    def __init__(self, clock: Callable[[], str] | None = None) -> None:
        from datetime import datetime, timezone

        self._clock = clock or (lambda: datetime.now(timezone.utc).isoformat())

    def normalize(self, raw: dict[str, Any]) -> CloudEvent | None:
        provider = str(_pick(raw, "provider", "cloud", default="") or "").lower()
        event_type = str(_pick(raw, "event_type", "type", "eventName", "operationName",
                               default="") or "")
        if not provider or not event_type:
            return None
        resource = str(_pick(raw, "resource", "resource_id", "resourceArn", "subject",
                             "resourceName", default="") or "")
        details = dict(_pick(raw, "details", "detail", "request", default={}) or {})
        if not details and not resource:
            return None
        normalized_type = (EVENT_TYPE_MAP.get(f"{provider}.{event_type.lower()}")
                           or event_type.upper())
        crypto_relevant = self.is_crypto_relevant(provider, event_type, details)
        return CloudEvent(
            event_id=str(_pick(raw, "event_id", "id", "eventId", default="") or "")
            or f"{provider}:{event_type}:{resource}:{self._clock()}",
            provider=provider,
            event_type=normalized_type,
            resource=resource,
            account=str(_pick(raw, "account", "account_id", "subscription", "project",
                              default="") or ""),
            region=str(_pick(raw, "region", "awsRegion", "location", default="") or ""),
            occurred_at=str(_pick(raw, "occurred_at", "timestamp", "eventTime",
                                  default=self._clock()) or self._clock()),
            details=details,
            crypto_relevant=crypto_relevant,
        )

    @staticmethod
    def is_crypto_relevant(provider: str, event_type: str, details: dict[str, Any]) -> bool:
        haystack = f"{provider} {event_type}".lower()
        for hint in CRYPTO_EVENT_HINTS:
            if hint in haystack:
                return True
        # event-type map hit counts as relevant
        if f"{provider}.{event_type.lower()}" in EVENT_TYPE_MAP:
            return True
        return False


@dataclass
class CbomEntry:
    """One CBOM component (a crypto resource in its current state)."""

    resource: str
    kind: str = ""
    provider: str = ""
    account: str = ""
    region: str = ""
    state: dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""
    revision: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource": self.resource,
            "kind": self.kind,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "state": dict(self.state),
            "updated_at": self.updated_at,
            "revision": self.revision,
        }


class CloudCbom:
    """Event-sourced CBOM for the cloud estate (live cryptographic env)."""

    def __init__(self) -> None:
        self._entries: dict[str, CbomEntry] = {}
        self._history: list[dict[str, Any]] = []

    def upsert(self, event: CloudEvent) -> CbomEntry | None:
        if not event.resource:
            return None
        entry = self._entries.get(event.resource)
        if entry is None:
            entry = CbomEntry(
                resource=event.resource,
                kind=event.event_type,
                provider=event.provider,
                account=event.account,
                region=event.region,
            )
        entry.state.update(event.details)
        entry.kind = event.event_type
        entry.updated_at = event.occurred_at
        entry.revision += 1
        self._entries[event.resource] = entry
        self._history.append({
            "resource": event.resource,
            "event_type": event.event_type,
            "revision": entry.revision,
            "occurred_at": event.occurred_at,
        })
        return entry

    def entries(self) -> list[CbomEntry]:
        return list(self._entries.values())

    def to_dicts(self) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in self.entries()]

    def count(self) -> int:
        return len(self._entries)

    def history(self) -> list[dict[str, Any]]:
        return list(self._history)

    def summary(self) -> dict[str, Any]:
        return {
            "components": self.count(),
            "events_applied": len(self._history),
            "by_provider": {
                provider: sum(1 for e in self._entries.values() if e.provider == provider)
                for provider in ("aws", "azure", "gcp")
            },
        }


@dataclass
class EventMonitorResult:
    """Outcome of one event-monitoring pass."""

    events: list[CloudEvent] = field(default_factory=list)
    changes: list[dict[str, Any]] = field(default_factory=list)
    cbom_updates: list[dict[str, Any]] = field(default_factory=list)
    policy_evaluations: list[dict[str, Any]] = field(default_factory=list)
    drift: DriftResult = field(default_factory=DriftResult)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": [event.to_dict() for event in self.events],
            "changes": list(self.changes),
            "cbom_updates": list(self.cbom_updates),
            "policy_evaluations": list(self.policy_evaluations),
            "drift": self.drift.to_dicts(),
            "drift_summary": self.drift.summary(),
        }


class CloudEventMonitor:
    """Event pipeline: normalize → change detect → CBOM → policy → drift."""

    def __init__(
        self,
        *,
        normalizer: CloudEventNormalizer | None = None,
        cbom: CloudCbom | None = None,
        compliance: ComplianceMappingEngine | None = None,
        sinks: list[EventSink] | None = None,
    ) -> None:
        self.normalizer = normalizer or CloudEventNormalizer()
        self.cbom = cbom or CloudCbom()
        self.compliance = compliance or ComplianceMappingEngine()
        self._sinks = list(sinks or [])

    def process(self, raw_events: list[dict[str, Any]],
                *, approved_changes: set[tuple[str, str]] | None = None) -> EventMonitorResult:
        result = EventMonitorResult()
        before = self._cbom_snapshot()
        for raw in raw_events:
            event = self.normalizer.normalize(raw)
            if event is None:
                continue
            result.events.append(event)
            if not event.crypto_relevant:
                continue
            change = self._detect_change(event)
            if change:
                result.changes.append(change)
                for sink in self._sinks:
                    try:
                        sink(change)
                    except Exception:  # noqa: BLE001 — sinks never break the pipeline
                        pass
            entry = self.cbom.upsert(event)
            if entry is not None:
                result.cbom_updates.append(entry.to_dict())
        # policy evaluation over the current CBOM (live crypto environment)
        policy: ComplianceReport | None = None
        try:
            policy = self.compliance.evaluate_observations(self._cbom_observations())
            result.policy_evaluations.extend(policy.to_dicts())
        except Exception as exc:  # noqa: BLE001
            result.policy_evaluations.append({"error": str(exc)[:300]})
        # drift: compare CBOM states before/after this pass
        after = self._cbom_snapshot()
        result.drift = self._diff_snapshots(before, after, approved_changes=approved_changes)
        return result

    # ------------------------------------------------------------------

    def _detect_change(self, event: CloudEvent) -> dict[str, Any] | None:
        if event.event_type in ("SECRET_CHANGE", "NETWORK_CHANGE", "SECURITY_CHANGE"):
            return None
        return {
            "change_id": f"change-{event.event_id}",
            "event_type": event.event_type,
            "resource": event.resource,
            "provider": event.provider,
            "account": event.account,
            "region": event.region,
            "occurred_at": event.occurred_at,
            "details": dict(event.details),
        }

    def _cbom_snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            entry.resource: {
                "kind": entry.kind,
                "provider": entry.provider,
                "account": entry.account,
                "region": entry.region,
                **entry.state,
            }
            for entry in self.cbom.entries()
        }

    def _cbom_observations(self) -> dict[str, dict[str, Any]]:
        """CBOM entries mapped to compliance observation shape."""
        observations: dict[str, dict[str, Any]] = {}
        for entry in self.cbom.entries():
            kind = entry.kind
            if "KMS" in kind or "VAULT" in kind or "CLOUD_KMS" in kind:
                kind = "key"
            elif "CERTIFICATE" in kind:
                kind = "certificate"
            elif "TLS" in kind or "POLICY" in kind:
                kind = "tls"
            observations[entry.resource] = {"kind": kind, "provider": entry.provider,
                                            **entry.state}
        return observations

    @staticmethod
    def _diff_snapshots(before: dict[str, dict[str, Any]],
                        after: dict[str, dict[str, Any]],
                        *, approved_changes: set[tuple[str, str]] | None) -> DriftResult:
        approved = {tuple(item) for item in (approved_changes or [])}
        result = DriftResult()
        for resource in sorted(set(before) | set(after)):
            prev = before.get(resource) or {}
            curr = after.get(resource) or {}
            if prev == curr:
                continue
            kind = _event_drift_kind(prev, curr)
            if kind is None:
                continue
            classification = classify_drift(kind, approved=(kind, resource) in approved)
            result.observations.append(DriftObservation(
                drift_id=f"event-drift-{resource}",
                kind=kind,
                resource=resource,
                provider=str(curr.get("provider") or prev.get("provider") or ""),
                account=str(curr.get("account") or prev.get("account") or ""),
                before={k: v for k, v in prev.items() if k not in ("provider", "account", "kind")},
                after={k: v for k, v in curr.items() if k not in ("provider", "account", "kind")},
                classification=classification,
                alert=classification in ("UNEXPECTED", "HIGH_RISK"),
            ))
        return result


def _event_drift_kind(prev: dict[str, Any], curr: dict[str, Any]) -> str | None:
    prev_type = str(prev.get("kind") or "")
    curr_type = str(curr.get("kind") or "")
    if "CERTIFICATE" in prev_type or "CERTIFICATE" in curr_type:
        if prev_type != curr_type or prev.get("serial") != curr.get("serial"):
            return "CERTIFICATE_CHANGED"
    if "KMS" in prev_type or "KMS" in curr_type or "KEY_VAULT" in curr_type \
            or "CLOUD_KMS" in curr_type:
        if curr.get("rotation_enabled") is False and prev.get("rotation_enabled") is not False:
            return "KMS_KEY_ROTATION_DISABLED"
    if "TLS" in prev_type or "TLS" in curr_type:
        if prev.get("tls_version") != curr.get("tls_version"):
            return "TLS_POLICY_CHANGED"
    if prev_type != curr_type:
        return "NEW_CRYPTO_ALGORITHM"
    return None
