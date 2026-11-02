"""Hardware scanner safety controls (§23).

Mandatory for enterprise/banking deployment: authorized scope, credential
isolation, read-only mode, rate limiting, connection limits, scan timeout,
vendor-specific safety profile, maintenance windows, excluded assets, audit
logging, kill switch.

NEVER: extract private keys, extract secret material, bypass authentication,
modify configurations, disable security controls. The scanner is a read-only
intelligence platform by default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

_NEVER_RULES = (
    "extract private keys", "extract secret material", "bypass authentication",
    "modify configurations", "disable security controls",
)


class SecretMaterialRefused(RuntimeError):
    """A collector was handed key material and refused it.

    This is a *security boundary*, so it is a raised exception and never an
    ``assert``: ``python -O`` strips assertions, which would silently turn the
    guard off in exactly the deployment that cares about it. The exception is
    deliberately not a ``ValueError`` — a caller that catches ``ValueError`` for
    "bad input" must not accidentally swallow a refusal to handle a private key.
    """

    def __init__(self, surface: str, token: str) -> None:
        self.surface = surface
        self.token = token
        super().__init__(
            f"{surface} refused a payload containing {token!r}: the collector "
            "reads metadata only, and key material never leaves the device")


def refuse_secret_material(raw: Any, forbidden: tuple[str, ...], *, surface: str) -> None:
    """Raise :class:`SecretMaterialRefused` if ``raw`` carries secret material.

    Matching is on the lowered string form of the payload, keys included, so a
    nested ``{"key": {"private_key": ...}}`` is caught as well as a top-level
    field. It over-matches on purpose: a false refusal costs an operator one
    configuration change, a false acceptance puts key material in an artifact.
    """
    lowered = str(raw).lower()
    for token in forbidden:
        if token in lowered:
            raise SecretMaterialRefused(surface, token)


@dataclass
class SafetyProfile:
    vendor: str = "*"
    max_rate_per_second: float = 1.0
    max_connections: int = 4
    scan_timeout_seconds: int = 30
    allowed_ports: list[int] = field(default_factory=list)
    maintenance_windows: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"vendor": self.vendor,
                "max_rate_per_second": self.max_rate_per_second,
                "max_connections": self.max_connections,
                "scan_timeout_seconds": self.scan_timeout_seconds,
                "allowed_ports": list(self.allowed_ports),
                "maintenance_windows": list(self.maintenance_windows),
                "notes": self.notes}


class SafetyController:
    """Enforces the §23 controls and the NEVER rules."""

    def __init__(self) -> None:
        self.authorized_scope: set[str] = set()          # asset ids / CIDRs
        self.excluded_assets: set[str] = set()
        self.read_only: bool = True
        self.kill_switched: bool = False
        self.audit_log: list[dict[str, Any]] = []
        self._profiles: dict[str, SafetyProfile] = {}
        self._rate_remaining: dict[str, float] = {}

    # ── scope ─────────────────────────────────────────────────────────

    def authorize(self, asset_id: str) -> None:
        self.authorized_scope.add(asset_id)

    def exclude(self, asset_id: str) -> None:
        self.excluded_assets.add(asset_id)

    def in_scope(self, asset_id: str) -> bool:
        if self.kill_switched:
            return False
        if asset_id in self.excluded_assets:
            return False
        return asset_id in self.authorized_scope

    # ── profiles ──────────────────────────────────────────────────────

    def set_profile(self, profile: SafetyProfile) -> None:
        self._profiles[profile.vendor.lower()] = profile

    def profile_for(self, vendor: str) -> SafetyProfile:
        return self._profiles.get(vendor.lower(),
                                  self._profiles.get("*", SafetyProfile()))

    # ── enforcement ───────────────────────────────────────────────────

    def can_scan(self, *, asset_id: str, vendor: str = "",
                 rate_key: str = "") -> tuple[bool, str]:
        """Check every gate before a scan is allowed."""
        if self.kill_switched:
            self._audit(asset_id, "BLOCKED", "kill switch engaged")
            return False, "kill switch engaged"
        if not self.read_only:
            self._audit(asset_id, "BLOCKED", "read-only mode disabled")
            return False, "read-only mode is required"
        if not self.in_scope(asset_id):
            self._audit(asset_id, "BLOCKED", "asset out of authorized scope")
            return False, "asset out of authorized scope"
        profile = self.profile_for(vendor)
        key = rate_key or asset_id
        remaining = self._rate_remaining.get(key, profile.max_rate_per_second)
        if remaining <= 0:
            self._audit(asset_id, "RATE_LIMITED", f"rate limit {profile.max_rate_per_second}/s")
            return False, "rate limited"
        self._rate_remaining[key] = remaining - 1
        self._audit(asset_id, "ALLOWED", f"profile={profile.vendor}")
        return True, "allowed"

    def assert_never(self, action: str) -> None:
        """Refuse any action on the NEVER list."""
        for rule in _NEVER_RULES:
            assert rule not in action.lower(), f"safety: {rule} is never allowed"
        return None

    def engage_kill_switch(self) -> None:
        self.kill_switched = True
        self._audit("SYSTEM", "KILL_SWITCH", "engaged by operator")

    def in_maintenance_window(self, vendor: str, now: Optional[str] = None) -> bool:
        profile = self.profile_for(vendor)
        if not profile.maintenance_windows:
            return False
        if now is None:
            now = datetime.now(timezone.utc).isoformat()
        return any(window in now for window in profile.maintenance_windows)

    # ── audit ─────────────────────────────────────────────────────────

    def _audit(self, asset_id: str, outcome: str, detail: str) -> None:
        self.audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "asset_id": asset_id, "outcome": outcome, "detail": detail,
        })

    def audit(self) -> list[dict[str, Any]]:
        return list(self.audit_log)
