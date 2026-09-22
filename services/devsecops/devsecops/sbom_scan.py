"""SBOM scanner — deterministic bill-of-materials generation for source trees
and container targets (CycloneDX 1.5 / SPDX 2.3), end to end.

Pipelines:
  source    walk a source tree, parse package manifests with the container
            scanner's deterministic parsers (requirements.txt, package.json,
            pom.xml, go.mod, Cargo.toml, Gemfile, composer.json, *.csproj),
            enrich with name-based crypto-relevance, and render CDX/SPDX.
  container run the real ContainerScanner (filesystem root, docker-save .tar,
            or registry image) and render its result as CDX/SPDX.

Declared-dependency policy: source SBOMs reflect the package manifests
(declared dependencies), not the resolved closure of an installed
environment — node_modules/vendor artifacts are skipped by default so the
SBOM is reproducible from the repository alone. ``include_vendored`` relaxes
only the ``vendor/`` directory.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# Deterministic name-based crypto-relevance registry (documented, curated).
# Marks components whose "name" identifies a well-known cryptography
# library; it is a relevance flag for the crypto inventory, not a deep
# audit of the package contents.
CRYPTO_PACKAGES: dict[str, dict[str, Any]] = {
    "cryptography": {"vendor": "pyca", "algorithms": ["AES", "SHA-256/384/512", "ECDSA", "Ed25519", "ChaCha20-Poly1305"]},
    "openssl": {"vendor": "OpenSSL", "algorithms": ["AES", "SHA-256/384/512", "RSA", "ECDSA", "Ed25519"]},
    "libssl": {"vendor": "OpenSSL", "algorithms": ["AES", "SHA-256/384/512", "RSA", "ECDSA"]},
    "libssl3": {"vendor": "OpenSSL", "algorithms": ["AES", "SHA-256/384/512", "RSA", "ECDSA"]},
    "pyopenssl": {"vendor": "pyca", "algorithms": ["RSA", "ECDSA", "SHA-256/384"]},
    "pycryptodome": {"vendor": "pycryptodome (H. van Vliet)", "algorithms": ["AES", "RSA", "SHA-256/512", "ChaCha20"]},
    "pycrypto": {"vendor": "pycrypto", "algorithms": ["AES", "RSA", "SHA-256"], "deprecated": True},
    "pynacl": {"vendor": "PyNaCl/libsodium", "algorithms": ["ChaCha20-Poly1305", "X25519", "Ed25519", "Curve25519"]},
    "libsodium": {"vendor": "Coherent Cryptography (libsodium)", "algorithms": ["ChaCha20-Poly1305", "X25519", "Ed25519"]},
    "sodium": {"vendor": "Coherent Cryptography (libsodium)", "algorithms": ["ChaCha20-Poly1305", "X25519", "Ed25519"]},
    "bouncycastle": {"vendor": "Legion of the Bouncy Castle", "algorithms": ["AES", "RSA", "SHA-256/512", "ECDSA"]},
    "bcprov-jdk15on": {"vendor": "Legion of the Bouncy Castle", "algorithms": ["AES", "RSA", "SHA-256/512"]},
    "bcprov-jdk18on": {"vendor": "Legion of the Bouncy Castle", "algorithms": ["AES", "RSA", "SHA-256/512"]},
    "jose4j": {"vendor": "Lodsys (jose4j)", "algorithms": ["RSA", "ECDSA", "EdDSA", "A256GCM"]},
    "jose": {"vendor": "py-jose", "algorithms": ["RSA", "ECDSA", "EdDSA"]},
    "webcrypto": {"vendor": "web-platform (WebCrypto)", "algorithms": ["AES-GCM", "HMAC-SHA", "ECDSA", "RSA-PSS"]},
    "aws-lc": {"vendor": "AWS (AWS-LC)", "algorithms": ["AES", "SHA-256/512", "ECDSA", "Ed25519", "ML-KEM"]},
    "mbedtls": {"vendor": "ARM (mbed TLS)", "algorithms": ["AES", "SHA-256/512", "ECDSA", "Ed25519"]},
    "gnutls": {"vendor": "GnuTLS", "algorithms": ["AES", "SHA-256/512", "RSA", "ECDSA"]},
    "net-sspi": {"vendor": "Windows SChannel (net-sspi)", "algorithms": ["AES", "SHA-256", "RSA"]},
    "security": {"vendor": "Go crypto (golang.org/x/crypto)", "algorithms": ["ChaCha20-Poly1305", "Ed25519", "X25519"]},
    "go-crypto": {"vendor": "Go crypto (golang.org/x/crypto)", "algorithms": ["ChaCha20-Poly1305", "Ed25519", "X25519"]},
    "x-crypto": {"vendor": "Go crypto (golang.org/x/crypto)", "algorithms": ["ChaCha20-Poly1305", "Ed25519", "X25519"]},
    "ring": {"vendor": "Mozilla (ring)", "algorithms": ["AES-GCM", "ECDSA", "Ed25519", "ChaCha20"]},
    "rust-crypto": {"vendor": "RustCrypto", "algorithms": ["AES", "SHA-256/512", "Ed25519"]},
}

# Directories never scanned (VCS internals, caches, resolved install trees).
_ALWAYS_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".cache", ".next", ".nuxt", ".output", ".parcel-cache", "node_modules",
    "dist", "build", "out", "target", "coverage",
}
_VENDORED_DIR = "vendor"
_MAX_FILES_WALKED = 50000
_MAX_MANIFEST_BYTES = 1_000_000

_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")


def is_image_ref(raw: str) -> bool:
    """True when the target reads as a registry image reference (not a path)."""
    value = str(raw or "").strip()
    if not value or " " in value or any(ch in value for ch in ";|`$<>"):
        return False
    return bool(_IMAGE_REF_RE.match(value))


def _crypto_libraries_for(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Name-based crypto relevance for parsed packages (deterministic)."""
    seen: dict[str, dict[str, Any]] = {}
    for pkg in packages:
        name = str(pkg.get("name") or "").lower()
        if name in CRYPTO_PACKAGES and name not in seen:
            seen[name] = {"name": name, **CRYPTO_PACKAGES[name]}
    return list(seen.values())


_RAW_PIP_SPEC = re.compile(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9_.+-]*)")


def _raw_pip_specs(path: Path) -> dict[str, str]:
    """Raw specifiers (with range operators) from a requirements file — the
    canonical parsers normalize them away, but pinning checks need the
    operator to distinguish `pkg==1.0` from `pkg>=1.0`."""
    specs: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return specs
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "-")):
            continue
        m = _RAW_PIP_SPEC.match(stripped)
        if m:
            specs.setdefault(m.group(1).lower(), stripped.split("#", 1)[0].strip())
    return specs


def _parse_manifest(path: Path, parsers: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        if path.stat().st_size > _MAX_MANIFEST_BYTES:
            return []
    except OSError:
        return []
    key = path.name
    parser = parsers.get(key) or (
        parsers.get("requirements.txt") if key.startswith("requirements") else None
    )
    if parser is None:
        return []
    try:
        return parser(path)
    except Exception:  # noqa: BLE001 — one bad manifest must not kill the scan
        return []


def scan_source(root: str, *, include_vendored: bool = False) -> dict[str, Any]:
    """Walk a source tree and build the canonical scan result from manifests."""
    from container_scanner.parsers import package_parsers as pp

    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise ValueError(f"source target is not a directory: {root}")

    parsers: dict[str, Any] = {
        "requirements.txt": pp.parse_requirements,
        "package.json": pp.parse_package_json,
        "pom.xml": pp.parse_pom,
        "go.mod": pp.parse_gomod,
        "Cargo.toml": pp.parse_cargo,
        "Gemfile": pp.parse_gemfile,
        "composer.json": pp.parse_composer,
    }
    skip = set(_ALWAYS_SKIP_DIRS)
    if not include_vendored:
        skip.add(_VENDORED_DIR)

    packages: list[dict[str, Any]] = []
    manifests: list[str] = []
    files_walked = 0
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            files_walked += 1
            if files_walked > _MAX_FILES_WALKED:
                break
            path = Path(dirpath) / fn
            rel = path.relative_to(base)
            if len(rel.parts) > 12:  # pathological nesting guard
                continue
            if fn in parsers:
                found = _parse_manifest(path, parsers)
            elif fn.endswith(".csproj"):
                found = _parse_manifest(path, {"csproj": pp.parse_csproj})
            else:
                continue
            if found:
                manifests.append(str(rel))
                raw_specs = _raw_pip_specs(path) if fn.startswith("requirements") else {}
                for item in found:
                    item["manifest"] = str(rel)
                    if item.get("manager") == "pip" and item.get("name") in raw_specs:
                        item["raw_spec"] = raw_specs[item["name"]]
                packages.extend(found)
        if files_walked > _MAX_FILES_WALKED:
            break

    # de-duplicate on (manager, name, version) — keep first manifest seen
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for pkg in packages:
        key = (str(pkg.get("manager") or "generic"),
               str(pkg.get("name") or "").lower(),
               str(pkg.get("version") or ""))
        dedup.setdefault(key, pkg)
    components = list(dedup.values())

    return {
        "target": str(base),
        "target_kind": "source",
        "packages": components,
        "libraries": _crypto_libraries_for(components),
        "binaries": [],
        "vulnerabilities": [],
        "manifests": manifests,
        "manifest_count": len(set(manifests)),
        "files_walked": files_walked,
    }


def scan_container(target: str, *, as_image: bool = False) -> dict[str, Any]:
    """Run the real ContainerScanner (deterministic, no live CVE feed).

    ``target`` is a filesystem root, a docker-save .tar, or a registry image
    reference (pulled only when a runtime is available; otherwise the
    scanner's honest error surfaces to the caller).
    """
    from container_scanner.config.settings import load_settings
    from container_scanner.core.scan_context import ScanContext
    from container_scanner.core.scanner import ContainerScanner
    from container_scanner.workspace.cleanup_handler import ensure_cleanup
    from container_scanner.workspace.workspace_manager import WorkspaceManager

    path = Path(target).expanduser()
    is_tar = path.is_file() and target.endswith((".tar", ".tar.gz", ".tgz"))
    use_image = as_image or is_tar or not path.exists()

    settings = load_settings()
    workspace = WorkspaceManager(settings.workspace_dir)
    workdir = workspace.create()
    context = ScanContext(target=target, live_cve=False, workdir=str(workdir))
    scanner = ContainerScanner(live_cve=False, resolver=None)
    with ensure_cleanup(workspace, workdir):
        if use_image:
            result = scanner.scan_image(target, scan_id=context.scan_id, workdir=workdir)
        else:
            result = scanner.scan_filesystem(path, scan_id=context.scan_id)
    result["scan_context"] = context.to_dict()
    result.setdefault("target", target)
    result.setdefault("target_kind", "image" if use_image else "filesystem")
    return result


def render_sbom(result: dict[str, Any], *, fmt: str) -> dict[str, Any]:
    """Render a canonical scan result as CycloneDX 1.5 or SPDX 2.3 JSON."""
    if fmt in ("cyclonedx", "cdx"):
        from container_scanner.reports.sbom import build_sbom
        return build_sbom(result)
    if fmt == "spdx":
        from container_scanner.reports.spdx import build_spdx
        return build_spdx(result)
    raise ValueError(f"unsupported SBOM format: {fmt}")
