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

import logging

logger = logging.getLogger(__name__)


import json
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
        # A parser registered under an extension (``*.csproj``) is dispatched by
        # suffix. Looking the parser up by exact filename cannot ever match, and
        # the failure is silent — an empty SBOM is a valid-looking answer.
        parser = next(
            (candidate for suffix, candidate in parsers.items()
             if suffix.startswith(".") and key.lower().endswith(suffix.lower())),
            None,
        )
    if parser is None:
        return []
    try:
        return parser(path)
    except Exception:  # noqa: BLE001 — one bad manifest must not kill the scan
        return []


def scan_source(root: str, *, include_vendored: bool = False,
                use_lockfiles: bool = True) -> dict[str, Any]:
    """Walk a source tree and build the canonical scan result.

    Declared dependencies come from the package manifests; when
    ``use_lockfiles`` is on (default) the resolved graphs in lockfiles
    (package-lock.json, yarn.lock, poetry.lock, Pipfile.lock, Cargo.lock,
    composer.lock, Gemfile.lock, go.sum, packages.lock.json, gradle.lockfile)
    are merged in — resolved versions win for a component that appears in
    both, and transitive (lockfile-only) components are included, each row
    tagged ``scope`` = declared|resolved and ``direct`` where determinable.
    """
    from container_scanner.parsers import package_parsers as pp

    from devsecops import sbom_lockfiles as lf

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
        "pyproject.toml": pp.parse_pyproject,
        "Pipfile": pp.parse_pipfile,
    }
    skip = set(_ALWAYS_SKIP_DIRS)
    if not include_vendored:
        skip.add(_VENDORED_DIR)

    packages: list[dict[str, Any]] = []
    manifests: list[str] = []
    lockfiles: list[str] = []
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
            if use_lockfiles and lf.is_lockfile(fn):
                found_locked = lf.parse_lockfile(path)
                if found_locked:
                    lockfiles.append(str(rel))
                    for item in found_locked:
                        item["manifest"] = str(rel)
                    packages.extend(found_locked)
                continue
            if fn in parsers:
                found = _parse_manifest(path, parsers)
            elif fn.lower().endswith(".csproj"):
                found = _parse_manifest(path, {".csproj": pp.parse_csproj})
            else:
                continue
            if found:
                manifests.append(str(rel))
                raw_specs = _raw_pip_specs(path) if fn.startswith("requirements") else {}
                for item in found:
                    item["manifest"] = str(rel)
                    item["scope"] = "declared"
                    spec = raw_specs.get(item.get("name"))
                    if spec:
                        item["raw_spec"] = spec
                        digest = _pip_hash_for(path, item.get("name"))
                        if digest:
                            item["integrity"] = digest
                packages.extend(found)
        if files_walked > _MAX_FILES_WALKED:
            break

    components = _merge_declared_and_resolved(packages)

    return {
        "target": str(base),
        "target_kind": "source",
        "packages": components,
        "libraries": _crypto_libraries_for(components),
        "binaries": [],
        "vulnerabilities": [],
        "manifests": manifests,
        "manifest_count": len(set(manifests)),
        "lockfiles": lockfiles,
        "lockfile_count": len(set(lockfiles)),
        "dependencies": _dependency_edges(components),
        "files_walked": files_walked,
    }


def _pip_hash_for(path: Path, name: str | None) -> str | None:
    """sha256 from a ``--hash=sha256:…`` option on the package's line."""
    if not name:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    target = str(name).lower()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|!=|>|<)", stripped)
        if not m or m.group(1).lower() != target:
            continue
        h = re.search(r"--hash[= ]sha256:([0-9a-fA-F]{64})", stripped)
        if h:
            return f"sha256:{h.group(1).lower()}"
    return None


def _merge_declared_and_resolved(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per (manager, name).

    Resolved (lockfile) rows carry the real version; a declared row for the
    same component contributes its specifier (``declared_spec``) so a range
    pin stays visible. Lockfile-only rows are transitive dependencies.
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    declared_meta: dict[tuple[str, str], dict[str, Any]] = {}
    for pkg in packages:
        manager = str(pkg.get("manager") or "generic")
        name = str(pkg.get("name") or "").lower()
        if not name:
            continue
        key = (manager, name)
        if str(pkg.get("scope")) == "resolved":
            row = merged.get(key)
            if row is None:
                merged[key] = dict(pkg, scope="resolved")
            elif row.get("scope") == "declared":
                # the lockfile is authoritative for the version — replace the
                # declared row but keep what the manifest asked for
                spec = str(row.get("raw_spec") or row.get("version") or "")
                replacement = dict(pkg, scope="resolved")
                if spec:
                    replacement["declared_spec"] = spec
                if row.get("integrity") and not replacement.get("integrity"):
                    replacement["integrity"] = row["integrity"]
                merged[key] = replacement
            else:
                # two lockfiles disagree — keep the first, record the other
                other = str(pkg.get("version") or "")
                if other and other != str(row.get("version") or ""):
                    row.setdefault("also_resolved_as", []).append(other)
            continue
        declared_meta.setdefault(key, pkg)
        if key not in merged:
            # a dependency declared in a manifest is a direct dependency
            merged[key] = dict(pkg, scope="declared", direct=True)
        else:
            row = merged[key]
            spec = str(pkg.get("raw_spec") or "")
            if spec:
                row["declared_spec"] = spec
            if not row.get("integrity") and pkg.get("integrity"):
                row["integrity"] = pkg["integrity"]

    for key, declared in declared_meta.items():
        row = merged.get(key)
        if row is None:
            continue
        spec = str(declared.get("raw_spec") or declared.get("version") or "")
        if spec and not row.get("declared_spec"):
            row["declared_spec"] = spec
        if declared.get("integrity") and not row.get("integrity"):
            row["integrity"] = declared["integrity"]
        if row.get("scope") == "resolved":
            row["direct"] = True
    return [merged[k] for k in sorted(merged)]


def _dependency_edges(components: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Edges between components, resolved by name (lockfiles reference names)."""
    by_name = {str(c.get("name") or "").lower(): c for c in components}
    edges: list[dict[str, str]] = []
    for comp in components:
        parent = str(comp.get("name") or "").lower()
        if not parent or parent not in by_name:
            continue
        for dep in comp.get("depends_on") or []:
            child = str(dep).lower()
            if child in by_name and child != parent:
                edges.append({"from": parent, "to": child})
    return edges


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


def render_sbom(result: dict[str, Any], *, fmt: str, enrich: bool = True,
                created_by: str | None = None) -> dict[str, Any]:
    """Render a canonical scan result as CycloneDX 1.5 or SPDX 2.3 JSON.

    ``enrich`` adds what the base renderer does not know about: the resolved
    dependency graph (lockfile edges), declared licenses, scope/direct
    metadata, and package checksums in the format's own vocabulary.
    """
    if fmt in ("cyclonedx", "cdx"):
        from container_scanner.reports.sbom import build_sbom
        bom = build_sbom(result)
    elif fmt == "spdx":
        from container_scanner.reports.spdx import build_spdx
        bom = build_spdx(result)
    else:
        raise ValueError(f"unsupported SBOM format: {fmt}")
    if not enrich:
        return bom
    return attach_remediation(enrich_bom(bom, result, created_by=created_by), result)


# manager -> advisory-feed ecosystem name (mirrors the purl type vocabulary
# used by the container scanner's CVE matcher)
MANAGER_ECOSYSTEM = {
    "pip": "pypi",
    "pip-site-packages": "pypi",
    "npm": "npm",
    "cargo": "cargo",
    "go": "golang",
    "composer": "composer",
    "bundler": "gem",
    "maven": "maven",
    "gradle": "maven",
    "nuget": "nuget",
    "dpkg": "deb",
    "apk": "apk",
    "rpm": "rpm",
    # a crypto implementation parsed out of a binary has no package ecosystem;
    # "generic" is the honest bucket, and it is what the purl says too, so a feed
    # row carrying ecosystem "generic" can match it by name and version
    "binary": "generic",
}

_SPDX_ID_SAFE = re.compile(r"^[A-Za-z0-9.+-]+$")
_INTEGRITY_PREFIX = re.compile(r"^(sha1|sha256|sha384|sha512|sha3-256|sha3-512)[-_](.+)$")

def attach_remediation(bom: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Add remediation data to the document's advisories.

    CycloneDX expresses "this version is fixed" as
    ``affects[].versions[{version, status: "unaffected"}]`` — that is what a
    consumer reads to plan an upgrade, so the scanner fills it from the matched
    advisory instead of leaving the document with a bare CVE id.
    """
    fixes = {}
    for vuln in result.get("vulnerabilities") or []:
        cve = str(vuln.get("cve") or "").strip()
        fixed = vuln.get("fixed_version")
        if cve and fixed:
            fixes[cve] = str(fixed)
    if not fixes:
        return bom
    for vuln in bom.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        fixed = fixes.get(str(vuln.get("id") or ""))
        if not fixed:
            continue
        vuln["recommendation"] = f"upgrade to {fixed} or later"
        for entry in vuln.get("affects") or []:
            if not isinstance(entry, dict):
                continue
            versions = [v for v in (entry.get("versions") or []) if isinstance(v, dict)]
            versions.append({"version": fixed, "status": "unaffected"})
            entry["versions"] = versions
        props = [x for x in (vuln.get("properties") or []) if isinstance(x, dict)]
        if not any(x.get("name") == "cryptoscan:fixed-version" for x in props):
            props.append({"name": "cryptoscan:fixed-version", "value": fixed})
            vuln["properties"] = props
    return bom

_ALG_NAMES = {
    "sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
    "sha3-256": "SHA3-256", "sha3-512": "SHA3-512",
}


def decode_integrity(value: str | None) -> list[dict[str, str]]:
    """CycloneDX hash entries for an SRI/hex integrity string.

    Understands ``sha512-<base64>`` (npm/ NuGet SRI), plain ``sha256:<hex>``,
    and the strongest algorithm when several are present. Go's ``h1:`` hashes
    are *not* file digests (they hash a canonical directory listing), so they
    are deliberately not converted into component hashes.
    """
    import base64

    raw = str(value or "").strip()
    if not raw or raw.startswith("h1:"):
        return []  # go module dirhash — not a component content digest
    strength = {"sha1": 1, "sha256": 2, "sha384": 3, "sha512": 4, "sha3-256": 3, "sha3-512": 4}
    best: tuple[int, dict[str, str]] | None = None
    for token in raw.split():
        if token.startswith("h1:"):
            continue
        m = _INTEGRITY_PREFIX.match(token)
        if m:
            alg, payload = m.group(1), m.group(2)
            if len(payload) == 64 and re.fullmatch(r"[0-9a-fA-F]+", payload) and alg == "sha256":
                candidate = {"alg": "SHA-256", "content": payload.lower()}
            else:
                try:
                    digest = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True).hex()
                except Exception as _handler_exc:  # noqa: BLE001 — malformed integrity is skipped, not guessed
                    logger.warning(
                        "exception_suppressed",
                        extra={"error_type": type(_handler_exc).__name__},
                    )
                    continue
                candidate = {"alg": _ALG_NAMES.get(alg, alg.upper()), "content": digest}
        else:
            m = re.fullmatch(r"(sha1|sha256|sha384|sha512|sha3-256|sha3-512):([0-9a-fA-F]{16,})", token)
            if not m:
                continue
            alg = m.group(1)
            candidate = {"alg": _ALG_NAMES[alg], "content": m.group(2).lower()}
        rank = strength.get(alg, 0)
        if best is None or rank > best[0]:
            best = (rank, candidate)
    return [best[1]] if best else []


def enrich_vulnerabilities(result: dict[str, Any], feed: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Deterministically match discovered components against an NVD-style feed.

    ``feed`` rows follow the container scanner's advisory shape
    (``{"cve_id", "severity", "affected": [{"ecosystem", "package", "ranges"}]}``);
    passing an empty/absent feed leaves the SBOM with no vulnerabilities rather
    than inventing any. Ecosystem is derived from the package manager so the
    same feed works for source and container scans.
    """
    from devsecops.container_scan import match_packages

    packages = result.get("packages") or []
    if not feed:
        result.setdefault("vulnerabilities", [])
        return []
    rows = [
        {"name": p.get("name"), "version": p.get("version"),
         "ecosystem": MANAGER_ECOSYSTEM.get(str(p.get("manager") or ""), str(p.get("manager") or ""))}
        for p in packages
        if p.get("name") and p.get("version")
    ]
    matches = match_packages(rows, feed)
    by_name = {str(p.get("name") or "").lower(): str(p.get("manager") or "") for p in packages}
    entries = [
        {"cve": m.cve_id, "severity": m.severity, "package": m.package, "version": m.version,
         "manager": by_name.get(m.package.lower(), m.ecosystem),
         "fixed_version": m.fixed_version, "summary": m.summary}
        for m in matches
    ]
    result["vulnerabilities"] = entries
    return entries


def _license_node(value: str | None) -> dict[str, Any] | None:
    """CycloneDX license object for a declared license string."""
    if not value:
        return None
    text = str(value).strip()
    if not text or text.upper() in ("NOASSERTION", "UNKNOWN"):
        return None
    if "," in text:
        return {"expression": text}
    if _SPDX_ID_SAFE.match(text):
        return {"license": {"id": text}}
    return {"license": {"name": text}}


def enrich_bom(bom: dict[str, Any], result: dict[str, Any],
               *, created_by: str | None = None) -> dict[str, Any]:
    """Attach dependency graph, licenses, supplier and scope metadata to a BOM.

    ``created_by`` records the SBOM author (the NTIA "author of SBOM data"
    element) when the scan was run by a known operator. Component suppliers are
    filled in only where the curated registry actually knows the vendor — an
    unknown supplier stays absent rather than being invented.
    """
    packages = {}
    for pkg in result.get("packages") or []:
        name = str(pkg.get("name") or "").strip().lower()
        if name:
            packages.setdefault(name, pkg)
    binaries = {str(b.get("name") or "").strip().lower() for b in (result.get("binaries") or [])}
    vendors = {str(lib.get("name") or "").strip().lower(): str(lib.get("vendor") or "")
               for lib in (result.get("libraries") or [])}
    edges = result.get("dependencies")
    if edges is None:
        edges = _dependency_edges(list(packages.values()))

    if str(bom.get("bomFormat") or "").lower() == "cyclonedx":
        metadata = bom.get("metadata") if isinstance(bom.get("metadata"), dict) else {}
        if created_by and not metadata.get("authors"):
            metadata["authors"] = [{"name": str(created_by)}]
        bom["metadata"] = metadata
        refs: dict[str, str] = {}
        for comp in bom.get("components") or []:
            name = str(comp.get("name") or "").strip().lower()
            ref = comp.get("bom-ref")
            if name and ref:
                refs.setdefault(name, str(ref))
            vendor = vendors.get(name)
            if vendor and not comp.get("supplier"):
                comp["supplier"] = {"name": vendor}
            if name in binaries or name not in packages:
                continue
            pkg = packages[name]
            props = [p for p in (comp.get("properties") or []) if isinstance(p, dict)]
            seen = {p.get("name") for p in props}
            extra = [
                ("cryptoscan:scope", str(pkg.get("scope") or "")),
                ("cryptoscan:direct", "" if pkg.get("direct") is None else str(bool(pkg["direct"])).lower()),
                ("cryptoscan:declared-spec", str(pkg.get("declared_spec") or "")),
                ("cryptoscan:integrity", str(pkg.get("integrity") or "")),
            ]
            for prop_name, value in extra:
                if prop_name not in seen:
                    props.append({"name": prop_name, "value": value})
            props = [p for p in props if p.get("value") not in (None, "")]
            if props:
                comp["properties"] = props
            if pkg.get("license") and not comp.get("licenses"):
                node = _license_node(str(pkg["license"]))
                if node:
                    comp["licenses"] = [node]
            if not comp.get("hashes"):
                hashes = decode_integrity(pkg.get("integrity"))
                if hashes:
                    comp["hashes"] = hashes
        if edges:
            depends: dict[str, list[str]] = {}
            for edge in edges:
                parent = refs.get(str(edge.get("from") or "").lower())
                child = refs.get(str(edge.get("to") or "").lower())
                if parent and child:
                    depends.setdefault(parent, [])
                    if child not in depends[parent]:
                        depends[parent].append(child)
            if depends:
                bom["dependencies"] = [{"ref": ref, "dependsOn": sorted(children)}
                                       for ref, children in sorted(depends.items())]
        return bom

    # SPDX 2.3
    pkg_ids: dict[str, str] = {}
    for entry in bom.get("packages") or []:
        name = str(entry.get("name") or "").strip().lower()
        spdx_id = entry.get("SPDXID")
        if name and spdx_id:
            pkg_ids.setdefault(name, str(spdx_id))
        vendor = vendors.get(name)
        if vendor and str(entry.get("supplier") or "") in ("", "NOASSERTION"):
            entry["supplier"] = f"Organization: {vendor}"
        meta = packages.get(name)
        if meta is None:
            continue
        if meta.get("license"):
            node = _license_node(str(meta["license"]))
            license_id = None
            if node and "license" in node:
                license_id = node["license"].get("id") or node["license"].get("name")
            elif node and "expression" in node:
                license_id = node["expression"]
            if license_id:
                entry["licenseDeclared"] = license_id
        if not entry.get("checksums"):
            spdx_alg = {"SHA-1": "SHA1", "SHA-256": "SHA256", "SHA-384": "SHA384",
                        "SHA-512": "SHA512", "SHA3-256": "SHA3-256", "SHA3-512": "SHA3-512"}
            checksums = [{"algorithm": spdx_alg[h["alg"]], "checksumValue": h["content"]}
                         for h in decode_integrity(meta.get("integrity"))
                         if h["alg"] in spdx_alg]
            if checksums:
                entry["checksums"] = checksums
    if edges:
        relationships = [r for r in (bom.get("relationships") or []) if isinstance(r, dict)]
        existing = {(r.get("spdxElementId"), r.get("relatedSpdxElement"), r.get("relationshipType"))
                    for r in relationships}
        for edge in edges:
            parent = pkg_ids.get(str(edge.get("from") or "").lower())
            child = pkg_ids.get(str(edge.get("to") or "").lower())
            if parent and child and (parent, child, "DEPENDS_ON") not in existing:
                relationships.append({"spdxElementId": parent, "relationshipType": "DEPENDS_ON",
                                      "relatedSpdxElement": child})
                existing.add((parent, child, "DEPENDS_ON"))
        bom["relationships"] = relationships
    return bom


# ------------------------------------------------------------ signing ------- #
def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    """Canonical bytes for signing (signature fields excluded)."""
    body = {k: v for k, v in manifest.items() if k not in ("signature", "signature_alg")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_manifest(manifest: dict[str, Any], secret: str) -> str:
    import hashlib
    import hmac

    return hmac.new(str(secret).encode("utf-8"), canonical_manifest(manifest), hashlib.sha256).hexdigest()


def verify_manifest(manifest: dict[str, Any], secret: str) -> bool:
    import hmac

    signature = str(manifest.get("signature") or "")
    if not signature:
        return False
    return hmac.compare_digest(signature, sign_manifest(manifest, secret))


def verify_artifact(manifest: dict[str, Any], blob: bytes, secret: str | None) -> dict[str, Any]:
    """Provenance check for a stored artifact: blob digest + manifest signature."""
    import hashlib

    checks: list[dict[str, Any]] = []
    expected = str(manifest.get("sha256") or "")
    actual = hashlib.sha256(blob).hexdigest()
    blob_ok = bool(expected) and actual == expected
    checks.append({"check": "blob_sha256", "ok": blob_ok,
                   "expected": expected[:16], "actual": actual[:16]})
    if manifest.get("signature"):
        sig_ok = bool(secret) and verify_manifest(manifest, str(secret))
        checks.append({"check": "manifest_signature", "ok": sig_ok,
                       "expected": "HMAC-SHA256", "actual": str(manifest.get("signature_alg") or "none")})
        verdict = "OK" if (blob_ok and sig_ok) else "TAMPERED"
    else:
        checks.append({"check": "manifest_signature", "ok": False, "expected": "HMAC-SHA256",
                       "actual": "unsigned (no platform signing secret)"})
        verdict = "OK" if blob_ok else "TAMPERED"
    return {"verdict": verdict, "signed": bool(manifest.get("signature")), "checks": checks}
