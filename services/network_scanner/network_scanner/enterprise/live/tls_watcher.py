"""Live TLS Monitoring.

Watch TLS endpoints continuously and detect changes in: TLS version, cipher
suites, certificate, certificate expiry, signature algorithm, public key
algorithm, key size, certificate chain, ALPN, and mTLS.

Example: TLS 1.3 + ECDSA → TLS 1.2 + RSA ⇒ CRYPTO_DRIFT ALERT.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from network_scanner.enterprise.live.drift import DriftDetector

TLS_STATE_FIELDS = (
    "tls_version", "cipher_suites", "certificate_fingerprint",
    "certificate_expiry", "signature_algorithm", "public_key_algorithm",
    "public_key_size", "key_size", "certificate_chain", "alpn", "mtls",
)


@dataclass
class TlsStateChange:
    endpoint: str
    previous: dict[str, Any]
    current: dict[str, Any]
    changed_fields: list[str] = field(default_factory=list)
    drift: list[dict[str, Any]] = field(default_factory=list)
    alert: bool = False
    observed_at: Any = None

    def to_dict(self) -> dict[str, Any]:
        observed = self.observed_at
        if hasattr(observed, "isoformat"):
            observed = observed.isoformat()
        return {"endpoint": self.endpoint,
                "previous": dict(self.previous),
                "current": dict(self.current),
                "changed_fields": list(self.changed_fields),
                "drift": list(self.drift),
                "alert": self.alert,
                "observed_at": observed}


class TlsWatcher:
    """Holds the last-known TLS state per endpoint and classifies changes."""

    def __init__(self, *,
                 detector: DriftDetector | None = None,
                 clock: Callable[[], Any] | None = None) -> None:
        self._last: dict[str, dict[str, Any]] = {}
        self._changes: list[TlsStateChange] = []
        self._detector = detector or DriftDetector()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {endpoint: dict(state) for endpoint, state in self._last.items()}

    def changes(self) -> list[TlsStateChange]:
        return list(self._changes)

    def observe(self, endpoint: str, state: dict[str, Any], *,
                change_id: str | None = None) -> TlsStateChange | None:
        """Record a new TLS state for ``endpoint``.

        Returns None on first observation; returns a ``TlsStateChange`` when
        anything in ``TLS_STATE_FIELDS`` changed.
        """
        relevant = {k: state.get(k) for k in TLS_STATE_FIELDS if k in state}
        previous = self._last.get(endpoint)
        if previous is None:
            self._last[endpoint] = dict(relevant)
            return None

        changed = [k for k in relevant if relevant.get(k) != previous.get(k)]
        drift = self._detector.detect(previous, relevant,
                                      asset_id=endpoint, change_id=change_id)
        drift_dicts = [d.to_dict() for d in drift]
        alert = any(d["classification"] == "CRITICAL_DRIFT" for d in drift_dicts)
        change = TlsStateChange(endpoint=endpoint,
                                previous=dict(previous),
                                current=dict(relevant),
                                changed_fields=changed,
                                drift=drift_dicts,
                                alert=alert,
                                observed_at=self._clock())
        self._last[endpoint] = dict(relevant)
        if not changed and not drift_dicts:
            # nothing observable changed — no change event
            return None
        self._changes.append(change)
        return change
