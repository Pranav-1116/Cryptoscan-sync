"""In-platform plugin registry (installed/quarantined catalog).

Pure selection policy over stored plugin rows. Actual persistence lives in
the API layer; this module decides whether a candidate install supersedes the
current version and what lifecycle state a plugin occupies.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from marketplace.manifest import PluginManifest
from marketplace.verify import _semver_tuple


class PluginState(str, Enum):
    UPLOADED = "UPLOADED"        # received, not yet verified
    VERIFIED = "VERIFIED"        # pins/signature valid, not enabled
    ENABLED = "ENABLED"          # active and used by scanners
    DISABLED = "DISABLED"        # operator-disabled
    QUARANTINED = "QUARANTINED"  # failed verification — never executed


@dataclass(frozen=True)
class InstalledPlugin:
    manifest: PluginManifest
    state: PluginState
    trusted: bool = False
    signer_key_id: str | None = None


def is_newer(candidate: str, current: str | None) -> bool:
    """True if ``candidate`` semver is greater than ``current`` (or none)."""
    if not current:
        return True
    return _semver_tuple(candidate) > _semver_tuple(current)


def decide_state(
    manifest: PluginManifest,
    *,
    verified_ok: bool,
    trusted: bool,
    operator_enable: bool,
) -> PluginState:
    """Deterministic lifecycle decision after verification.

    Fail-closed: anything that failed verification is quarantined and can
    never reach ENABLED.
    """
    if not verified_ok:
        return PluginState.QUARANTINED
    if manifest.is_executable and not trusted:
        # executable but not signed by a pinned authority -> quarantine
        return PluginState.QUARANTINED
    if operator_enable:
        return PluginState.ENABLED
    return PluginState.VERIFIED


def select_enable_target(candidates: list[InstalledPlugin], plugin_id: str) -> InstalledPlugin | None:
    """Pick the highest-version ENABLED-eligible plugin for an id (deterministic)."""
    viable = [
        p for p in candidates
        if p.manifest.plugin_id == plugin_id
        and p.state in (PluginState.VERIFIED, PluginState.ENABLED)
    ]
    if not viable:
        return None
    return max(viable, key=lambda p: _semver_tuple(p.manifest.version))
