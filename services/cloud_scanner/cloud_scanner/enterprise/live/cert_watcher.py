"""ZELNX Live Cloud Intelligence Engine — multi-cloud certificate watcher
(§9).

AWS ACM + Azure Key Vault + GCP Certificate Manager feed ONE universal
certificate watcher with change kinds:

    CREATED | RENEWED | REPLACED | EXPIRED | REVOKED | ALGORITHM_CHANGED

Each change updates: certificate graph, TLS endpoints, application
dependencies, cloud CBOM, PQC readiness and compliance status.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.live.event_schema import CloudEvent

CERTIFICATE_CHANGE_KINDS = (
    "CREATED", "RENEWED", "REPLACED", "EXPIRED", "REVOKED", "ALGORITHM_CHANGED",
)

CERT_EVENT_TO_KIND = {
    "CERTIFICATE_CREATED": "CREATED",
    "CERTIFICATE_RENEWED": "RENEWED",
    "CERTIFICATE_REPLACED": "REPLACED",
    "CERTIFICATE_EXPIRED": "EXPIRED",
    "CERTIFICATE_REVOKED": "REVOKED",
    "CERTIFICATE_ALGORITHM_CHANGED": "ALGORITHM_CHANGED",
    # universal generic event (§18) — any certificate mutation
    "CERTIFICATE_CHANGED": "REPLACED",
}


def is_certificate_event(event_type: str) -> bool:
    return str(event_type or "") in CERT_EVENT_TO_KIND


@dataclass
class CertificateChange:
    """One certificate lifecycle change with its downstream impact."""

    certificate_id: str
    provider: str = ""
    change_kind: str = ""
    tls_endpoints: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    severity: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "provider": self.provider,
            "change_kind": self.change_kind,
            "tls_endpoints": list(self.tls_endpoints),
            "applications": list(self.applications),
            "severity": self.severity,
        }


class MultiCloudCertificateWatcher:
    """Watch certificate events and map downstream consumers.

    ``find_consumers(certificate_id)`` returns rows with kind
    (tls_endpoint | application | load_balancer) — injectable.
    """

    def __init__(self, *, find_consumers=None, severity_fn=None) -> None:
        self._find_consumers = find_consumers or (lambda cert_id: [])
        self._severity = severity_fn or default_cert_severity
        self._changes: list[CertificateChange] = []

    def watch(self, event: CloudEvent) -> CertificateChange | None:
        if not is_certificate_event(event.event_type):
            return None
        kind = CERT_EVENT_TO_KIND[event.event_type]
        consumers = self._find_consumers(event.resource_id)
        change = CertificateChange(
            certificate_id=event.resource_id,
            provider=event.provider,
            change_kind=kind,
            tls_endpoints=[str(row.get("resource") if isinstance(row, dict) else row)
                           for row in consumers
                           if str(row.get("kind") if isinstance(row, dict) else "") in
                           ("tls_endpoint", "endpoint", "lb", "load_balancer")],
            applications=[str(row.get("resource") if isinstance(row, dict) else row)
                          for row in consumers
                          if str(row.get("kind") if isinstance(row, dict) else "") in
                          ("application", "workload", "function", "app")],
        )
        change.severity = self._severity(event, change)
        self._changes.append(change)
        return change

    def changes(self) -> list[CertificateChange]:
        return list(self._changes)

    def summary(self) -> dict[str, Any]:
        return {
            "changes": len(self._changes),
            "by_kind": {
                kind: sum(1 for c in self._changes if c.change_kind == kind)
                for kind in CERTIFICATE_CHANGE_KINDS
            },
        }


def default_cert_severity(event: CloudEvent, change: CertificateChange) -> str:
    if change.change_kind in ("EXPIRED", "REVOKED"):
        return "CRITICAL"
    if change.change_kind == "ALGORITHM_CHANGED":
        return "HIGH"
    if change.tls_endpoints:
        return "MEDIUM"
    return "LOW"
