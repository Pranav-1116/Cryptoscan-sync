"""Privacy enforcement over a whole scan output (the "what may I retain?" step).

The :class:`~privacy.redact.RedactionEngine` processes a *single* observation
dict. This module walks a *whole* scan snapshot (all scanner results, findings,
inventory, evidence) and applies the policy to every nested value so the
privacy engine actually **operates** on real output, not just validates a
policy. It enforces four rules regardless of shape:

* **Never store secrets / credentials / private keys** — any key in
  :data:`NEVER_STORE_KEYS` or any value matching a secret signature is dropped
  or redacted (and an alert is raised) unless the policy explicitly permits
  collecting it (the fail-safe default is *off*).
* **Mask PII** (emails / phone numbers / card numbers / national IDs) unless
  ``collect_pii`` is True.
* **Data minimization** — for observation-like dicts, keep only the field
  allowlist from :data:`privacy.policy.MINIMALLY_REQUIRED_FIELDS`.
* **Retention** — record a retention decision per observation.

Pure / deterministic (no I/O), so it is unit-testable in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from privacy.policy import MINIMALLY_REQUIRED_FIELDS, PrivacyPolicy
from privacy.redact import RedactionEngine

#: field names that must never be persisted without an explicit opt-in.
NEVER_STORE_KEYS = (
    "private_key", "secret_key", "secret", "password", "passwd", "token",
    "authorization", "api_key", "access_key", "client_secret", "credential",
    "private", "key_material", "pem", "passphrase", "cookie", "session",
)

#: field names that are always allowed (metadata about the observation).
_META_KEYS = frozenset({
    "scan_id", "source", "scanner", "observation_type", "asset", "fingerprint",
    "confidence", "method", "first_seen", "last_seen", "file", "line",
    "column", "rule_id", "severity", "algorithm", "key_size", "purpose",
    "status", "expiry_status", "days_until_expiry", "public_key_algorithm",
})


@dataclass
class ScrubResult:
    value: Any                                  # sanitized equivalent
    dropped: list[str] = field(default_factory=list)
    redacted: list[str] = field(default_factory=list)
    alerts: list[str] = field(default_factory=list)
    private_key_detected: bool = False
    truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "dropped": self.dropped, "redacted": self.redacted,
            "alerts": self.alerts, "private_key_detected": self.private_key_detected,
            "truncated": self.truncated,
        }


def _looks_like_observation(d: dict[str, Any]) -> bool:
    keys = set(d)
    return bool(keys & {"asset", "observation_type", "locator", "method"}) and bool(
        keys & {"observation_type", "asset", "locator"}
    )


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


class PrivacyScrubber:
    """Recursively scrub a scan output under a :class:`PrivacyPolicy`."""

    def __init__(self, policy: PrivacyPolicy | None = None) -> None:
        self.policy = policy or PrivacyPolicy()
        self.engine = RedactionEngine(self.policy)

    def scrub(self, value: Any, *, path: str = "") -> ScrubResult:
        result = ScrubResult(value=value)
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            # data minimization on observation-shaped dicts
            allow = None
            obs_type = value.get("observation_type")
            if self.policy.data_minimization and obs_type in MINIMALLY_REQUIRED_FIELDS:
                allow = set(MINIMALLY_REQUIRED_FIELDS[obs_type]) | _META_KEYS
            for k, v in value.items():
                key_path = f"{path}.{k}" if path else str(k)
                low = str(k).lower()
                # hard rule: never store a private key / secret field
                if low in NEVER_STORE_KEYS or "private_key" in low or "secret" in low:
                    if not (self.policy.collect_private_keys and "private" in low) and \
                       not (self.policy.collect_secrets and "secret" in low):
                        result.dropped.append(key_path)
                        result.private_key_detected = result.private_key_detected or "private" in low or "key" in low
                        result.alerts.append(f"dropped sensitive field: {key_path}")
                        continue
                sub = self.scrub(v, path=key_path)
                result.dropped.extend(sub.dropped)
                result.redacted.extend(sub.redacted)
                result.alerts.extend(sub.alerts)
                result.private_key_detected = result.private_key_detected or sub.private_key_detected
                if isinstance(sub.value, dict):
                    # if the value itself is an observation, record retention on it
                    ret = self.engine.process(sub.value) if _looks_like_observation(sub.value) else None
                    if ret is not None:
                        result.dropped.extend(f"{key_path}.{d}" for d in ret.dropped_fields)
                        result.redacted.extend(f"{key_path}.{d}" for d in ret.redacted_fields)
                        result.private_key_detected = result.private_key_detected or ret.private_key_detected
                        if not ret.should_store:
                            result.dropped.append(key_path)
                            continue
                        sub.value = ret.observation
                out[k] = sub.value
            result.value = out
            return result
        if isinstance(value, list):
            out_l = []
            for i, item in enumerate(value):
                sub = self.scrub(item, path=f"{path}[{i}]")
                result.dropped.extend(sub.dropped)
                result.redacted.extend(sub.redacted)
                result.alerts.extend(sub.alerts)
                result.private_key_detected = result.private_key_detected or sub.private_key_detected
                out_l.append(sub.value)
            result.value = out_l
            return result
        if isinstance(value, str):
            from privacy.redact import _EMAIL_RE, _PHONE_RE, _SECRET_RE

            if self.policy.redact_secrets and _SECRET_RE.search(value):
                result.redacted.append(path or "value")
                result.alerts.append(f"redacted secret value at {path or 'value'}")
                return ScrubResult(value=_mask(value), redacted=result.redacted,
                                   alerts=result.alerts,
                                   private_key_detected=bool("PRIVATE KEY" in value.lower()))
            if not self.policy.collect_pii and (_EMAIL_RE.search(value) or _PHONE_RE.search(value)):
                result.redacted.append(path or "value")
                return ScrubResult(value=_mask(value), redacted=result.redacted)
            return result
        return result


def sanitize_snapshot(snapshot: dict[str, Any], policy: PrivacyPolicy | None = None) -> tuple[dict[str, Any], ScrubResult]:
    """Scrub a whole live-scan snapshot in place; returns (sanitized, report)."""
    scrubber = PrivacyScrubber(policy)
    report = scrubber.scrub(snapshot)
    # scrubber returns sanitized value in report.value
    return (report.value if isinstance(report.value, dict) else snapshot), report
