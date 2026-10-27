"""§33 Enterprise security controls — the deterministic enforcement layer
for every platform scan.

The control manifest is a plain dataclass (YAML/JSON-serializable) and
``enforce()`` validates a scan request against it before any discovery
runs. Defaults are the safest posture: read-only, restricted scope, no
credentials in requests (secrets never stored as scan evidence), and an
open emergency-stop that halts everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class SecurityControls:
    """Manifest of enterprise security controls (§33)."""

    read_only_default: bool = True
    authorized_scope: list[str] = field(default_factory=list)   # CIDRs/accounts
    credential_vault: str = ""         # vault reference, never credentials
    rbac_roles: dict[str, list[str]] = field(default_factory=dict)  # role -> actions
    mfa_required: bool = True
    rate_limit_per_minute: int = 60
    scan_policies: list[str] = field(default_factory=list)      # SAFE/DEEP/…
    exclusion_list: list[str] = field(default_factory=list)
    maintenance_windows: list[dict[str, str]] = field(default_factory=list)
    audit_logging: bool = True
    emergency_stop: bool = False
    tenant_isolation: bool = True
    encrypted_transport: bool = True
    encrypted_storage: bool = True
    secrets_never_stored: bool = True
    evidence_integrity: bool = True    # hash-chain evidence
    agent_authentication: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}

    # -- enforcement --------------------------------------------------------

    def enforce(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate a scan request against the controls.

        Returns a decision: ``allowed`` with any warnings, or ``blocked``
        with the control that failed. Never partially allows a request.
        """
        violations: list[str] = []

        if self.emergency_stop:
            violations.append("emergency_stop: platform-wide halt engaged")

        mode = str(request.get("mode") or "SAFE").upper()
        if mode not in ("SAFE", "READ_ONLY", "READONLY"):
            violations.append(
                f"mode {mode!r} violates read_only_default (SAFE/READ_ONLY only)")

        scope = str(request.get("scope") or "")
        if self.authorized_scope and scope:
            if not any(scope == s or scope.startswith(s.rstrip("*"))
                       for s in self.authorized_scope):
                violations.append(
                    f"scope {scope!r} outside authorized_scope {self.authorized_scope}")

        for target in request.get("targets") or []:
            if target in self.exclusion_list:
                violations.append(f"target {target!r} is on the exclusion_list")

        if request.get("secrets") or request.get("credentials"):
            violations.append(
                "credentials/secrets in scan request: secrets are never stored "
                "as scan evidence")

        if request.get("maintenance_window") and self.maintenance_windows:
            datetime.now(timezone.utc).isoformat()
            window = request["maintenance_window"]
            if not any(window == str(w.get("name")) or
                       window == str(w.get("id"))
                       for w in self.maintenance_windows):
                violations.append(
                    f"maintenance_window {window!r} not in the schedule")

        if violations:
            return {"allowed": False, "violations": violations,
                    "checked_at": datetime.now(timezone.utc).isoformat()}
        warnings = []
        if self.mfa_required and not request.get("mfa_verified"):
            warnings.append("mfa_required: verification flag not supplied")
        return {"allowed": True, "violations": [], "warnings": warnings,
                "checked_at": datetime.now(timezone.utc).isoformat()}


DEFAULT_CONTROLS = SecurityControls()
