"""First-class configuration drift detection.

Compares config facts between an approved baseline scan and a current scan
and emits CONFIG_* change events — the "Drift v2.0" capability the platform
previously lacked (config files were scanned, but drift only ever compared
code findings).

Transitions:

- fact in current, not in baseline     -> CONFIG_ADDED
- fact in baseline, not in current     -> CONFIG_REMOVED
- fact in both, value differs          -> CONFIG_CHANGED (severity reflects
                                          whether the new value is weaker)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from drift.core.config_facts import ConfigFact, fact_weakness_rank


@dataclass(frozen=True)
class ConfigDriftChange:
    change_type: str          # CONFIG_ADDED / CONFIG_REMOVED / CONFIG_CHANGED
    config_key: str
    file_path: str
    library: str
    severity: str             # CRITICAL / HIGH / MEDIUM / INFO
    reason: str
    baseline_value: str | None = None
    current_value: str | None = None
    algorithm: str = "UNKNOWN"
    secret_present: bool = False
    secret_hash: str | None = None

    def to_event_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type,
            "config_key": self.config_key,
            "file_path": self.file_path,
            "library": self.library,
            "severity": self.severity,
            "reason": self.reason,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "algorithm": self.algorithm,
            "secret_present": self.secret_present,
            "secret_hash": self.secret_hash,
        }


@dataclass
class ConfigDriftResult:
    changes: list[ConfigDriftChange] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.changes)

    def events(self) -> list[dict[str, Any]]:
        return [c.to_event_dict() for c in self.changes]


def _classify_changed(baseline: ConfigFact, current: ConfigFact) -> ConfigDriftChange:
    """Severity for a value change: degraded crypto is worse than hardening."""
    b_rank = fact_weakness_rank(baseline)
    c_rank = fact_weakness_rank(current)
    secret_len_delta = 0
    if baseline.secret_present and current.secret_present:
        bl = baseline.secret_length or 0
        cl = current.secret_length or 0
        secret_len_delta = cl - bl
    if c_rank > b_rank:
        severity, reason = "CRITICAL", "crypto configuration weakened"
    elif secret_len_delta < 0:
        severity, reason = "HIGH", "secret length decreased"
    elif secret_len_delta > 0:
        severity, reason = "INFO", "secret length increased (hardening)"
    elif c_rank < b_rank:
        severity, reason = "INFO", "crypto configuration hardened"
    else:
        severity, reason = "MEDIUM", "crypto configuration changed (same strength)"
    return ConfigDriftChange(
        change_type="CONFIG_CHANGED",
        config_key=baseline.config_key,
        file_path=current.file_path or baseline.file_path,
        library=current.library or baseline.library,
        severity=severity,
        reason=reason,
        baseline_value=baseline.value,
        current_value=current.value,
        algorithm=current.algorithm or baseline.algorithm,
        secret_present=current.secret_present,
        secret_hash=current.secret_hash or baseline.secret_hash,
    )


def detect_config_drift(
    baseline_facts: Iterable[ConfigFact],
    current_facts: Iterable[ConfigFact],
) -> ConfigDriftResult:
    """Compare two fact sets; emit CONFIG_* changes."""
    baseline = {f.config_key: f for f in baseline_facts}
    current = {f.config_key: f for f in current_facts}
    changes: list[ConfigDriftChange] = []

    for key, fact in current.items():
        if key not in baseline:
            rank = fact_weakness_rank(fact)
            weak_value = (fact.value or "").upper() in {"SSLV2", "SSLV3", "TLS1.0", "TLS1.1"}
            weak_algo = (fact.algorithm or "").upper() in {"SSLV2", "SSLV3", "TLS1.0", "TLS1.1"}
            severity = "CRITICAL" if rank >= 2 or weak_value or weak_algo else "MEDIUM"
            changes.append(
                ConfigDriftChange(
                    change_type="CONFIG_ADDED",
                    config_key=key,
                    file_path=fact.file_path,
                    library=fact.library,
                    severity=severity,
                    reason="new cryptographic configuration appeared"
                    if severity == "MEDIUM"
                    else "new weak cryptographic configuration appeared",
                    current_value=fact.value,
                    algorithm=fact.algorithm,
                    secret_present=fact.secret_present,
                    secret_hash=fact.secret_hash,
                )
            )

    for key, fact in baseline.items():
        if key not in current:
            changes.append(
                ConfigDriftChange(
                    change_type="CONFIG_REMOVED",
                    config_key=key,
                    file_path=fact.file_path,
                    library=fact.library,
                    severity="MEDIUM",
                    reason="cryptographic configuration removed",
                    baseline_value=fact.value,
                    algorithm=fact.algorithm,
                    secret_present=fact.secret_present,
                    secret_hash=fact.secret_hash,
                )
            )

    for key in baseline.keys() & current.keys():
        if baseline[key].value != current[key].value:
            changes.append(_classify_changed(baseline[key], current[key]))

    changes.sort(key=lambda c: (c.severity != "CRITICAL", c.severity != "HIGH", c.config_key))
    return ConfigDriftResult(changes=changes)
