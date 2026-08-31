"""Vendor Crypto Drift (24/7 spec §10).

Compare EXPECTED VENDOR STATE vs CURRENT VENDOR STATE and classify:

    NO_CHANGE | EXPECTED | APPROVED | UNEXPECTED | CRYPTO_DRIFT | CRITICAL_CRYPTO_DRIFT

A change is EXPECTED when it matches a scheduled change (e.g. firmware
upgrade window); APPROVED when an operator explicitly approved it;
UNEXPECTED when the fingerprint changed without approval;
CRYPTO_DRIFT when the changed crypto material deviates from the baseline;
CRITICAL_CRYPTO_DRIFT when the drift introduces deprecated or
quantum-vulnerable cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from universal_vendor.live.fingerprint import crypto_relevant_diff


class DriftState(str, Enum):
    NO_CHANGE = "NO_CHANGE"
    EXPECTED = "EXPECTED"
    APPROVED = "APPROVED"
    UNEXPECTED = "UNEXPECTED"
    CRYPTO_DRIFT = "CRYPTO_DRIFT"
    CRITICAL_CRYPTO_DRIFT = "CRITICAL_CRYPTO_DRIFT"


# Algorithms that make drift critical when they appear: deprecated (MD5,
# SHA-1, RC4, DES/3DES, TLS 1.0/1.1) or quantum-vulnerable (RSA, ECDSA, ECDH,
# DH — asymmetric without PQ replacements).
_CRITICAL_TOKENS = (
    "md5", "sha-1", "sha1", "rc4", "des", "3des", "tls1.0", "tls 1.0",
    "tls1.1", "tls 1.1", "rsa", "ecdsa", "ecdh", "diffie-hellman", "dh ",
)


@dataclass
class DriftVerdict:
    asset_id: str
    state: DriftState
    config_hash: Optional[str] = None
    changed_lines: list[str] = field(default_factory=list)
    reason: str = ""
    approved_by: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"asset_id": self.asset_id, "state": self.state.value,
                "config_hash": self.config_hash,
                "changed_lines": self.changed_lines, "reason": self.reason,
                "approved_by": self.approved_by}


class CryptoDriftEngine:
    def __init__(self) -> None:
        self._baseline: dict[str, str] = {}          # asset_id -> config hash
        self._expected: dict[str, set[str]] = {}     # asset_id -> expected hashes
        self._approved: dict[str, set[str]] = {}     # asset_id -> approved hashes
        self._history: list[DriftVerdict] = []

    def set_baseline(self, asset_id: str, config: Any) -> None:
        from universal_vendor.live.fingerprint import config_hash

        self._baseline[asset_id] = config_hash(config)

    def expect(self, asset_id: str, config: Any, *, by: str = "scheduler") -> None:
        from universal_vendor.live.fingerprint import config_hash

        digest = config_hash(config)
        self._expected.setdefault(asset_id, set()).add(digest)
        self._approved.setdefault(asset_id, set()).add(digest)

    def approve(self, asset_id: str, config_hash: str, *, by: str) -> None:
        self._approved.setdefault(asset_id, set()).add(config_hash)

    def evaluate(self, asset_id: str, config: Any,
                 *, approved_by: Optional[str] = None) -> DriftVerdict:
        """Compare current config against the expected/approved/baseline set."""
        from universal_vendor.live.fingerprint import config_hash

        digest = config_hash(config)
        baseline = self._baseline.get(asset_id)
        if digest == baseline:
            verdict = DriftVerdict(asset_id=asset_id, state=DriftState.NO_CHANGE,
                                   config_hash=digest)
            self._history.append(verdict)
            return verdict

        if digest in self._expected.get(asset_id, set()):
            verdict = DriftVerdict(asset_id=asset_id, state=DriftState.EXPECTED,
                                   config_hash=digest)
            self._history.append(verdict)
            return verdict

        if digest in self._approved.get(asset_id, set()):
            verdict = DriftVerdict(asset_id=asset_id, state=DriftState.APPROVED,
                                   config_hash=digest, approved_by=approved_by)
            self._history.append(verdict)
            return verdict

        # Unknown change → assess crypto relevance and criticality
        diff = crypto_relevant_diff(baseline or "", config)
        if not diff["hash_changed"]:
            verdict = DriftVerdict(asset_id=asset_id, state=DriftState.NO_CHANGE,
                                   config_hash=digest)
            self._history.append(verdict)
            return verdict

        lowered = "\n".join(diff["changed_lines"]).lower()
        critical = [token for token in _CRITICAL_TOKENS if token in lowered]
        if critical:
            verdict = DriftVerdict(
                asset_id=asset_id, state=DriftState.CRITICAL_CRYPTO_DRIFT,
                config_hash=digest, changed_lines=diff["changed_lines"],
                reason=f"crypto drift introduced critical algorithms: {critical}",
            )
        elif diff["crypto_relevant"]:
            verdict = DriftVerdict(
                asset_id=asset_id, state=DriftState.CRYPTO_DRIFT,
                config_hash=digest, changed_lines=diff["changed_lines"],
                reason="crypto-relevant configuration drift",
            )
        else:
            verdict = DriftVerdict(
                asset_id=asset_id, state=DriftState.UNEXPECTED,
                config_hash=digest, changed_lines=diff["changed_lines"],
                reason="configuration changed without approval",
            )
        self._history.append(verdict)
        return verdict

    def history(self) -> list[DriftVerdict]:
        return list(self._history)
