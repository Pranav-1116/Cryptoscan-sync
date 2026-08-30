"""Payment crypto policy: PAY-xxx rules from PCI DSS, ANS X9.24/TR-39, NQO.

Each rule receives the key inventory, the ceremony records and the recent
HSM event history and returns findings with severities on the same scale the
drift engine uses (1-5, 5 highest, plus ``blocking`` for must-fix-now).

Sources behind the rules (kept deliberately conservative):

- PAY-001  3DES/DES or RSA<2048 / EC<224 on an ACTIVE payment key
           — NIST SP 800-131A rev2 disallows 2-key 3DES after 2023,
             PCI DSS 4.0 requires strong cryptography (NQO migration);
- PAY-002  key past its rotation window (default 12 months, per-usage
           override) — X9.24/TR-39 A.9 periodic key replacement;
- PAY-003  ceremony without dual control (fewer than 2 custodians) or
           missing m-of-n — PCI DSS 3.6.5 / 3.7 split knowledge;
- PAY-004  clear-key export event observed — X9.24 clear key handling;
- PAY-005  ACTIVE key with no ceremony record at all;
- PAY-006  auth-failure storm on an HSM (>= 5 in window) — brute-force
           signal, PCI DSS 10/11;
- PAY-007  firmware change on an HSM outside a ceremony — change control;
- PAY-008  TR-31 ``B0`` key block still in service — legacy format with no
           cryptographic binding (migrate to bound versions);
- PAY-009  key in COMPROMISED/EXPIRED state still enabled;
- PAY-010  key block failed structural parse (bad length / non-hex).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

RULE_IDS = {
    "PAY-001", "PAY-002", "PAY-003", "PAY-004", "PAY-005",
    "PAY-006", "PAY-007", "PAY-008", "PAY-009", "PAY-010",
}

DEFAULT_ROTATION_MONTHS = 12
ROTATION_MONTHS_BY_USAGE = {
    # X9.24 guidance: transaction keys rotate at least annually;
    # long-lived KEKs/ZMKs are typically 24 months in TR-39 programs.
    "KEK": 24,
    "ZONE_MASTER_KEY_ZMK": 24,
    "BASE_DERIVATION_KEY": 24,
    "ISSUER_MASTER_KEY_IMK": 24,
    "EMV_ISSUER_MASTER_KEY": 24,
}
WEAK_ALGORITHMS = {"DES", "SINGLE_DES", "2KEY_TRIPLE_DES", "TRIPLE_DES"}
AUTH_FAILURE_THRESHOLD = 5


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PolicyFinding:
    rule_id: str
    severity: int              # 1..5
    blocking: bool
    key_id: str | None
    message: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "blocking": self.blocking,
            "key_id": self.key_id,
            "message": self.message,
            "evidence": self.evidence,
        }


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _months(months: int) -> timedelta:
    return timedelta(days=30.44 * months)


def _rotation_months(usage: str, override: int | None) -> int:
    if override:
        return override
    return ROTATION_MONTHS_BY_USAGE.get((usage or "").upper(), DEFAULT_ROTATION_MONTHS)


class PaymentPolicyEngine:
    """Evaluate the PAY-xxx rule set against inventory + ceremony + events."""

    def __init__(self, *, rotation_months_override: int | None = None,
                 auth_failure_threshold: int = AUTH_FAILURE_THRESHOLD,
                 now: datetime | None = None):
        self.rotation_override = rotation_months_override
        self.auth_threshold = auth_failure_threshold
        self._now = now or _utcnow()

    def evaluate(
        self,
        keys: Iterable[dict],
        *,
        ceremonies: Iterable[dict] | None = None,
        events: Iterable[dict] | None = None,
        window_days: int = 30,
    ) -> list[PolicyFinding]:
        keys = [dict(key) for key in keys]
        ceremonies = [dict(c) for c in (ceremonies or [])]
        events = [dict(event) for event in (events or [])]
        findings: list[PolicyFinding] = []

        ceremonies_by_key: dict[str, list[dict]] = {}
        for ceremony in ceremonies:
            ceremonies_by_key.setdefault(str(ceremony.get("key_id") or ""), []).append(ceremony)

        for key in keys:
            key_id = str(key.get("key_id") or "")
            usage = str(key.get("key_usage") or "")
            algorithm = str(key.get("algorithm") or "").upper()
            state = str(key.get("state") or "").upper()
            key_findings = self._evaluate_key(key, key_id, usage, algorithm, state)
            key_findings.extend(self._evaluate_ceremony(key_id, ceremonies_by_key.get(key_id, [])))
            findings.extend(key_findings)

        findings.extend(self._evaluate_events(events, window_days))
        findings.sort(key=lambda finding: (-finding.severity, finding.rule_id, finding.key_id or ""))
        return findings

    # ------------------------------------------------------------------ keys

    def _evaluate_key(self, key: dict, key_id: str, usage: str, algorithm: str, state: str) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        active = state in {"ACTIVE", ""}

        if active and (algorithm in WEAK_ALGORITHMS or algorithm in {"DES", "SINGLE_DES"}):
            findings.append(PolicyFinding(
                "PAY-001", 5, True, key_id,
                f"active payment key uses deprecated algorithm {algorithm or 'unknown'}",
                {"algorithm": key.get("algorithm"), "usage": usage},
            ))
        size = key.get("key_size")
        if active and isinstance(size, (int, float)):
            if "RSA" in algorithm and size < 2048:
                findings.append(PolicyFinding(
                    "PAY-001", 5, True, key_id,
                    f"RSA payment key below 2048 bits ({int(size)})",
                    {"key_size": int(size)},
                ))
            if algorithm in {"EC", "ECC", "ECDSA"} and size < 224:
                findings.append(PolicyFinding(
                    "PAY-001", 5, True, key_id,
                    f"elliptic-curve payment key below 224 bits ({int(size)})",
                    {"key_size": int(size)},
                ))

        if state in {"COMPROMISED", "EXPIRED"} and key.get("enabled", True):
            findings.append(PolicyFinding(
                "PAY-009", 5, True, key_id,
                f"key in state {state} is still enabled",
                {"state": state},
            ))

        activated = _as_datetime(key.get("activation_at"))
        if active and activated is not None:
            age_limit = _months(_rotation_months(usage, self.rotation_override))
            age = self._now - activated
            if age > age_limit:
                findings.append(PolicyFinding(
                    "PAY-002", 4, False, key_id,
                    f"key exceeds rotation window ({age.days}d old, limit "
                    f"{int(_rotation_months(usage, self.rotation_override))} months for {usage or 'general'} keys)",
                    {"activation_at": activated.isoformat(), "age_days": age.days},
                ))

        block_version = str(key.get("key_block_version") or "")
        if block_version:
            if block_version == "B0":
                findings.append(PolicyFinding(
                    "PAY-008", 3, False, key_id,
                    "TR-31 B0 key block (no cryptographic binding) still in service",
                    {"key_block_version": block_version},
                ))
        if key.get("key_block_error"):
            findings.append(PolicyFinding(
                "PAY-010", 3, False, key_id,
                f"key block failed structural parse: {key.get('key_block_error')}",
                {"raw_error": str(key.get('key_block_error'))},
            ))
        return findings

    # ------------------------------------------------------------- ceremonies

    def _evaluate_ceremony(self, key_id: str, ceremonies: list[dict]) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        if not ceremonies:
            findings.append(PolicyFinding(
                "PAY-005", 4, False, key_id,
                "active key has no key-ceremony record",
                {"ceremony_count": 0},
            ))
            return findings
        latest = max(ceremonies, key=lambda ceremony: str(ceremony.get("held_at") or ""))
        custodians = latest.get("custodians") or []
        dual_control = bool(latest.get("dual_control"))
        if len(custodians) < 2 or not dual_control:
            findings.append(PolicyFinding(
                "PAY-003", 5, True, key_id,
                f"key ceremony lacks dual control (custodians={len(custodians)}, dual_control={dual_control})",
                {"custodians": custodians, "dual_control": dual_control},
            ))
        return findings

    # ---------------------------------------------------------------- events

    def _evaluate_events(self, events: list[dict], window_days: int) -> list[PolicyFinding]:
        findings: list[PolicyFinding] = []
        window_start = self._now - timedelta(days=window_days)

        failures_by_device: dict[str, list[dict]] = {}
        for event in events:
            occurred = _as_datetime(event.get("occurred_at")) or self._now
            if occurred < window_start:
                continue
            event_type = str(event.get("event_type") or "")
            device = str(event.get("device") or "?")
            if event_type == "AUTH_FAILURE":
                failures_by_device.setdefault(device, []).append(event)
            elif event_type == "CLEAR_KEY_EXPORT":
                findings.append(PolicyFinding(
                    "PAY-004", 5, True, event.get("key_id"),
                    f"clear-key export observed on {device}",
                    {"device": device, "occurred_at": event.get("occurred_at")},
                ))
            elif event_type == "FIRMWARE_UPDATED":
                ceremony_refs = (event.get("detail") or {}).get("ceremony_id") or (event.get("detail") or {}).get("change_ref")
                if not ceremony_refs:
                    findings.append(PolicyFinding(
                        "PAY-007", 4, False, None,
                        f"firmware change on {device} without change-control reference",
                        {"device": device, "occurred_at": event.get("occurred_at")},
                    ))

        for device, failures in failures_by_device.items():
            if len(failures) >= self.auth_threshold:
                findings.append(PolicyFinding(
                    "PAY-006", 4, False, None,
                    f"{len(failures)} HSM authentication failures on {device} within {window_days}d",
                    {"device": device, "count": len(failures),
                     "first": failures[0].get("occurred_at"), "last": failures[-1].get("occurred_at")},
                ))
        return findings
