"""Conservative exact identities for package/release joins (no name/tag inference)."""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote

SCHEMA = "cryptoscan.software-supply-chain/1"
MAX_COMPONENTS = 5000
MAX_SBOM_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
_PURL = re.compile(r"^pkg:[a-z][a-z0-9.+-]*/[^?#]+@([^?#/]+)(?:\?[^#]*)?(?:#.*)?$")


def artifact_digest(value: str) -> str:
    value = value.strip()
    if not _DIGEST.fullmatch(value):
        raise ValueError("artifact digest must be sha256: followed by 64 hexadecimal characters; tags/paths are not identities")
    return value.lower()


def scope_key(tenant: str | None) -> str:
    return "platform" if tenant is None else "tenant:" + tenant


def package_identity(purl: Any, version: Any = None) -> str | None:
    """Exact, version-bearing PURL only; ranges/conflicting versions stay unknown.

    This is intentionally not broad package-name matching or PURL equivalence
    resolution. Case/qualifiers/subpaths remain significant to this join.
    """
    if not isinstance(purl, str) or len(purl) > 500 or any(c.isspace() for c in purl):
        return None
    match = _PURL.fullmatch(purl)
    if not match:
        return None
    resolved = unquote(match.group(1))
    if (not resolved or re.search(r"[\s^~<>=*|]", resolved)
            or resolved.lower() in {"latest", "main", "master", "head", "x"}):
        return None
    if version is not None and str(version) != resolved:
        return None
    return purl
