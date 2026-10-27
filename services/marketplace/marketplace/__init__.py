"""ZELNX plugin marketplace core — deterministic, hash-pinned, signed plugins."""

from marketplace.manifest import (
    DATA_TYPES,
    EXECUTABLE_TYPES,
    ManifestError,
    PluginManifest,
)
from marketplace.registry import (
    InstalledPlugin,
    PluginState,
    decide_state,
    is_newer,
    select_enable_target,
)
from marketplace.verify import (
    VerificationResult,
    content_digest,
    platform_supports,
    sign_plugin,
    signing_payload,
    verify_plugin,
)

__all__ = [
    "DATA_TYPES",
    "EXECUTABLE_TYPES",
    "ManifestError",
    "PluginManifest",
    "InstalledPlugin",
    "PluginState",
    "decide_state",
    "is_newer",
    "select_enable_target",
    "VerificationResult",
    "content_digest",
    "platform_supports",
    "sign_plugin",
    "signing_payload",
    "verify_plugin",
]
