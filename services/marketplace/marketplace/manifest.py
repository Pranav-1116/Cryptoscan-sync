"""Plugin manifest model for the ZELNX marketplace.

A plugin ships a manifest (metadata + pins) separate from its payload and a
detached Ed25519 signature over the canonical manifest+content digest. Every
field here is deterministic — there is no model inference; a plugin is a
versioned bundle of detection rules, signatures, or parsers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: plugin types that may execute code (must be signed by a trusted authority)
EXECUTABLE_TYPES = frozenset({"scanner", "ingestor", "integrator"})
#: data-only plugin types (rules/signatures/knowledge) — still must match pins,
#: but do not require code-execution trust.
DATA_TYPES = frozenset({"ruleset", "signatures", "knowledge", "parser-config"})
ALL_TYPES = EXECUTABLE_TYPES | DATA_TYPES

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")

#: conservative content size cap (a plugin bundle is text rules / small code)
MAX_CONTENT_BYTES = 5 * 1024 * 1024


class ManifestError(ValueError):
    """Raised when a plugin manifest is structurally invalid."""


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    version: str
    plugin_type: str
    name: str
    description: str = ""
    content_sha256: str = ""
    min_platform: str = "0.0.0"
    ruleset_version: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)
    author: str = ""

    @staticmethod
    def from_dict(data: dict[str, Any]) -> PluginManifest:
        if not isinstance(data, dict):
            raise ManifestError("manifest must be an object")
        required = ("plugin_id", "version", "plugin_type", "name", "content_sha256")
        missing = [k for k in required if not data.get(k)]
        if missing:
            raise ManifestError(f"missing required field(s): {', '.join(missing)}")

        plugin_id = str(data["plugin_id"])
        if not ID_RE.match(plugin_id):
            raise ManifestError(f"invalid plugin_id: {plugin_id!r}")

        version = str(data["version"])
        if not SEMVER_RE.match(version):
            raise ManifestError(f"version must be semver X.Y.Z, got {version!r}")

        ptype = str(data["plugin_type"]).lower()
        if ptype not in ALL_TYPES:
            raise ManifestError(
                f"plugin_type must be one of {sorted(ALL_TYPES)}, got {ptype!r}"
            )

        digest = str(data["content_sha256"]).lower().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ManifestError("content_sha256 must be a 64-char hex SHA-256")

        min_platform = str(data.get("min_platform") or "0.0.0")
        if not SEMVER_RE.match(min_platform):
            raise ManifestError(f"min_platform must be semver, got {min_platform!r}")

        tags = tuple(str(t) for t in (data.get("tags") or ()) if str(t).strip())
        return PluginManifest(
            plugin_id=plugin_id,
            version=version,
            plugin_type=ptype,
            name=str(data["name"]),
            description=str(data.get("description") or ""),
            content_sha256=digest,
            min_platform=min_platform,
            ruleset_version=str(data.get("ruleset_version") or ""),
            tags=tags,
            author=str(data.get("author") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "version": self.version,
            "plugin_type": self.plugin_type,
            "name": self.name,
            "description": self.description,
            "content_sha256": self.content_sha256,
            "min_platform": self.min_platform,
            "ruleset_version": self.ruleset_version,
            "tags": list(self.tags),
            "author": self.author,
        }

    @property
    def is_executable(self) -> bool:
        return self.plugin_type in EXECUTABLE_TYPES
