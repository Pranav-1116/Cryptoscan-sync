"""The evidence bundle a bank-side collector hands to the platform (spec 100).

The platform's discovery engine (spec 93) already turns *one* evidence graph into
six BOM projections. What it did not have was a way to receive that evidence from
the bank's side of the gap: the CLI's collectors run inside the bank, the platform
runs the projections, and the only thing that should cross between them is
**evidence**, not six pre-built inventories.

This module is that crossing point, and it is deliberately the smallest part of
the architecture:

* :func:`build_manifest` describes a bundle — one entry per member, each with its
  own sha256 and size, plus the coverage counters the collector actually observed;
* :func:`verify_bundle` checks a bundle a receiver is holding against that
  manifest and says exactly what it proved;
* :func:`summarise_coverage` turns the collector's counters into a state, and
  computes the difference between *expected* and *accounted* targets instead of
  reporting a percentage that hides it.

Five rules make the verdict honest, and each one is enforced here rather than in
a caller:

1. **A bundle with no members proves nothing.** Building one raises; verifying one
   returns ``REJECTED`` / ``BUNDLE_EMPTY``.
2. **A digest that matches is not an author.** The manifest's signature is checked
   with :mod:`release_signature`, which reports ``SIGNED_UNVERIFIED`` when no
   trusted key was supplied — so an unsigned bundle is ``UNSIGNED`` and a signed
   one without a trust root is ``SIGNATURE_UNCHECKED``. Neither is ``VERIFIED``.
3. **Files the manifest does not cover are a failure, not an extra.** A receiver
   handed `observations/extra.json` cannot tell whether it belongs, so
   ``MEMBER_NOT_IN_MANIFEST`` rejects the bundle.
4. **A missing or altered member is rejected with its path named.** One reason per
   member, so the operator can see which collector lied or which file was cut.
5. **Coverage never becomes "percent complete".** Counters stay counters; the
   observed fraction is returned with its denominator, or ``None`` when the
   collector expected nothing (which is ``UNKNOWN``, not 100%).

What this module does not do, and must not be read as doing: it does not ingest,
normalise, resolve identities or project a BOM. Verification is a gate, and the
gates behind it are named in the response's ``next`` member.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from shared_models import release_signature

BUNDLE_SCHEMA = "cryptoscan.bundle/1"

#: member path prefixes a bundle may carry; anything else is refused rather than guessed
MEMBER_KINDS = ("observations", "imports", "certificates", "relationships", "errors")

#: the named top-level documents a bundle may carry (the collector's own scope, target
#: list and coverage detail). Everything else must live under a :data:`MEMBER_KINDS` prefix.
BUNDLE_FILES = ("scope.json", "targets.json", "coverage.json", "hashes.json")

#: a hard ceiling so a malformed bundle cannot exhaust the receiver; a transfer
#: larger than this belongs in chunked uploads (not built — see LIMITS)
MAX_MEMBERS = 200_000

# verification states — only the first one means "proved"
VERIFIED = "VERIFIED"
UNSIGNED = "UNSIGNED"
SIGNATURE_UNCHECKED = "SIGNATURE_UNCHECKED"
REJECTED = "REJECTED"

# reason codes, reported one per member where a member is the problem
MEMBER_MISSING = "MEMBER_MISSING"
MEMBER_DIGEST_MISMATCH = "MEMBER_DIGEST_MISMATCH"
MEMBER_SIZE_MISMATCH = "MEMBER_SIZE_MISMATCH"
MEMBER_NOT_IN_MANIFEST = "MEMBER_NOT_IN_MANIFEST"
MEMBER_PATH_REFUSED = "MEMBER_PATH_REFUSED"
BUNDLE_EMPTY = "BUNDLE_EMPTY"
MANIFEST_MALFORMED = "MANIFEST_MALFORMED"
SCHEMA_UNSUPPORTED = "BUNDLE_SCHEMA_UNSUPPORTED"
TOO_MANY_MEMBERS = "BUNDLE_TOO_MANY_MEMBERS"
SIGNATURE_INVALID = "SIGNATURE_INVALID"
SIGNATURE_MALFORMED = "SIGNATURE_MALFORMED"
SIGNATURE_KEY_MISMATCH = "SIGNATURE_KEY_MISMATCH"

# coverage reasons
COVERAGE_UNKNOWN = "COVERAGE_UNKNOWN"
COVERAGE_UNACCOUNTED_TARGETS = "COVERAGE_UNACCOUNTED_TARGETS"
COVERAGE_FAILED_TARGETS = "COVERAGE_FAILED_TARGETS"

#: the counters a collector is expected to be able to report; missing ones stay missing
COVERAGE_KEYS = (
    "expected",
    "attempted",
    "collected",
    "partial",
    "failed",
    "unauthorized",
    "unavailable",
)
#: counters that account for an expected target. `attempted` is a subset of these.
ACCOUNTING_KEYS = ("collected", "partial", "failed", "unauthorized", "unavailable")

LIMITS = [
    "a verified bundle proves the manifest's bytes were signed by the key you chose to "
    "trust, and that every member still matches its recorded sha256 — it proves nothing "
    "about whether the collector was authorised to reach the targets it names",
    "verification does not ingest: normalisation, identity resolution and the six BOM "
    "projections happen after this gate, in the estate engine, and are not covered by "
    "this verdict",
    "chunked transfer and resumption are not implemented; this module verifies a bundle "
    "it is given in one piece, so a very large estate currently needs a bounded slice",
    "the signature carries no trusted timestamp and no revocation check: a bundle signed "
    "by a revoked key still verifies against that key",
    "coverage counters are the collector's own report. A collector that never attempted a "
    "target can still report `expected` correctly and `collected: 0` — that is a truthful "
    "zero, not proof the target has no crypto",
]


# --------------------------------------------------------------------------------------
# digests and canonical form
# --------------------------------------------------------------------------------------

def member_sha256(data: bytes) -> str:
    """The digest of one member, exactly as the manifest records it."""
    return hashlib.sha256(data).hexdigest()


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Digest of the manifest itself, over the same canonical bytes the signature covers."""
    return hashlib.sha256(release_signature.canonical_bytes(manifest)).hexdigest()


def _safe_path(path: Any) -> str:
    """Refuse absolute paths, parent traversal and Windows separators."""
    text = str(path)
    if not text or "\\" in text:
        raise ValueError(f"member path is not a POSIX relative path: {text!r}")
    pure = PurePosixPath(text)
    if pure.is_absolute() or any(part in {"..", "."} for part in pure.parts):
        raise ValueError(f"member path escapes the bundle: {text!r}")
    if pure.parts[0] in BUNDLE_FILES and len(pure.parts) == 1:
        return str(pure)
    if pure.parts[0] not in MEMBER_KINDS:
        raise ValueError(
            f"member path must start with one of {', '.join(MEMBER_KINDS)} "
            f"or be one of {', '.join(BUNDLE_FILES)}: {text!r}"
        )
    return str(pure)


def _kind_of(path: str) -> str:
    first = PurePosixPath(path).parts[0]
    return "bundle" if first in BUNDLE_FILES else first


# --------------------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------------------

def summarise_coverage(counts: Mapping[str, Any] | None) -> dict[str, Any]:
    """The collector's counters, with the gap between expected and accounted named.

    ``observed_fraction`` is returned only when the collector expected something, and it
    always travels with its denominator. A zero expectation is ``UNKNOWN`` — an estate
    nobody registered is not 100% covered.
    """
    source = {key: counts.get(key) for key in COVERAGE_KEYS} if isinstance(counts, Mapping) else {}
    clean: dict[str, int | None] = {}
    for key in COVERAGE_KEYS:
        value = source.get(key)
        if value is None:
            clean[key] = None
            continue
        try:
            number = int(value)
        except (TypeError, ValueError):
            clean[key] = None
            continue
        clean[key] = number if number >= 0 else None

    reasons: list[str] = []
    expected = clean["expected"]
    if expected is None:
        reasons.append(COVERAGE_UNKNOWN)
        unaccounted: int | None = None
        accounted: int | None = None
        state = "UNKNOWN"
        fraction = None
    else:
        accounted = sum(clean[key] or 0 for key in ACCOUNTING_KEYS)
        unaccounted = expected - accounted
        if unaccounted < 0:
            # more targets accounted for than expected is a collector bug, not a bonus
            reasons.append(COVERAGE_UNACCOUNTED_TARGETS)
            state = "PARTIAL"
        elif unaccounted > 0:
            reasons.append(COVERAGE_UNACCOUNTED_TARGETS)
            state = "PARTIAL"
        elif (clean["failed"] or 0) or (clean["unauthorized"] or 0) or (clean["unavailable"] or 0) or (clean["partial"] or 0):
            reasons.append(COVERAGE_FAILED_TARGETS)
            state = "PARTIAL"
        else:
            state = "COMPLETE"
        observed = clean["collected"] or 0
        fraction = None if expected <= 0 else round(observed / expected, 6)
        if expected <= 0:
            reasons.append(COVERAGE_UNKNOWN)
            state = "UNKNOWN"
            fraction = None

    return {
        "counts": clean,
        "accounted": accounted,
        "unaccounted": unaccounted,
        "state": state,
        "observed_fraction": fraction,
        "observed_note": (
            "fraction of the targets this collector was told to expect; it is not a share "
            "of the bank, and the denominator is the collector's own registered scope"
            if fraction is not None
            else "no expected targets were reported, so no fraction exists"
        ),
        "reasons": reasons,
    }


# --------------------------------------------------------------------------------------
# building
# --------------------------------------------------------------------------------------

def build_manifest(
    *,
    bundle_id: str,
    organization_id: str,
    environment: str,
    scan_id: str,
    collector_version: str,
    scope_revision: str | None,
    created_at: str,
    members: Mapping[str, bytes],
    coverage: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Describe a bundle without signing it. ``members`` maps member path → bytes.

    Refuses an empty bundle: a manifest that covers nothing would let a receiver report
    ``VERIFIED`` for a transfer that carried no evidence at all.
    """
    if not members:
        raise ValueError("a bundle with no members proves nothing; refusing to build one")
    if len(members) > MAX_MEMBERS:
        raise ValueError(f"a bundle carries at most {MAX_MEMBERS} members, got {len(members)}")

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_path, data in members.items():
        path = _safe_path(raw_path)
        if path in seen:
            raise ValueError(f"duplicate member path: {path}")
        seen.add(path)
        payload = bytes(data)
        entries.append(
            {
                "path": path,
                "kind": _kind_of(path),
                "sha256": member_sha256(payload),
                "bytes": len(payload),
            }
        )
    entries.sort(key=lambda entry: entry["path"])

    return {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": str(bundle_id),
        "organization_id": str(organization_id),
        "environment": str(environment),
        "scan_id": str(scan_id),
        "collector_version": str(collector_version),
        "scope_revision": None if scope_revision is None else str(scope_revision),
        "created_at": str(created_at),
        "member_count": len(entries),
        "total_bytes": sum(entry["bytes"] for entry in entries),
        "members": entries,
        "coverage": summarise_coverage(coverage),
        "signature": None,
        "limits": LIMITS,
    }


# --------------------------------------------------------------------------------------
# verifying
# --------------------------------------------------------------------------------------

def _reject(reasons: list[str], **extra: Any) -> dict[str, Any]:
    return {"state": REJECTED, "accepted": False, "reasons": reasons, **extra}


def verify_bundle(
    manifest: Any,
    members: Mapping[str, bytes],
    *,
    trusted_key: Any = None,
) -> dict[str, Any]:
    """Check a bundle against its manifest and report what that proved.

    ``members`` is what the receiver is actually holding (path → bytes). ``trusted_key``
    is the collector key this deployment decided to trust; without one, no bundle can
    reach ``VERIFIED``, because the manifest's own public key is not evidence.
    """
    if not isinstance(manifest, Mapping):
        return _reject([MANIFEST_MALFORMED], detail="the manifest is not a JSON object", limits=LIMITS)
    if manifest.get("schema") != BUNDLE_SCHEMA:
        return _reject(
            [SCHEMA_UNSUPPORTED],
            detail=f"expected schema {BUNDLE_SCHEMA}, got {manifest.get('schema')!r}",
            limits=LIMITS,
        )
    listed = manifest.get("members")
    if not isinstance(listed, list) or not listed:
        return _reject([BUNDLE_EMPTY], detail="the manifest lists no members", limits=LIMITS)
    if len(listed) > MAX_MEMBERS:
        return _reject([TOO_MANY_MEMBERS], detail=f"the manifest lists {len(listed)} members", limits=LIMITS)

    reasons: list[str] = []
    missing: list[str] = []
    mismatched: list[str] = []
    resized: list[str] = []
    checked = 0
    expected_paths: set[str] = set()

    for entry in listed:
        if not isinstance(entry, Mapping):
            reasons.append(MANIFEST_MALFORMED)
            continue
        try:
            path = _safe_path(entry.get("path"))
        except ValueError:
            reasons.append(MEMBER_PATH_REFUSED)
            continue
        expected_paths.add(path)
        held = members.get(path)
        if held is None:
            missing.append(path)
            continue
        payload = bytes(held)
        checked += 1
        if member_sha256(payload) != entry.get("sha256"):
            mismatched.append(path)
            continue
        size = entry.get("bytes")
        if isinstance(size, int) and size != len(payload):
            resized.append(path)

    unlisted = sorted(path for path in members if path not in expected_paths)

    if missing:
        reasons.append(MEMBER_MISSING)
    if mismatched:
        reasons.append(MEMBER_DIGEST_MISMATCH)
    if resized:
        reasons.append(MEMBER_SIZE_MISMATCH)
    if unlisted:
        reasons.append(MEMBER_NOT_IN_MANIFEST)

    signature = release_signature.verify_document(manifest, trusted_key=trusted_key)
    status = signature.get("status")

    coverage = manifest.get("coverage")
    if not isinstance(coverage, Mapping):
        coverage = summarise_coverage(None)

    facts: dict[str, Any] = {
        "members_checked": checked,
        "members_missing": missing,
        "members_mismatched": mismatched,
        "members_unlisted": unlisted,
        "member_count": len(listed),
        "manifest_digest": manifest_digest(manifest),
        "bundle_id": manifest.get("bundle_id"),
        "scan_id": manifest.get("scan_id"),
        "organization_id": manifest.get("organization_id"),
        "environment": manifest.get("environment"),
        "coverage": coverage,
        "signature": signature,
        "limits": LIMITS,
    }

    integrity_failed = bool(missing or mismatched or resized or unlisted)
    if integrity_failed:
        return _reject(
            reasons,
            **facts,
            proves="nothing — the bytes on disk are not the bytes the manifest describes",
            next="reject the transfer and re-collect; do not ingest a bundle that fails its own hashes",
        )

    if status == release_signature.VALID:
        state = VERIFIED
        accepted = True
        proves = (
            "the holder of the trusted collector key signed this manifest, and every member "
            "still matches its recorded sha256"
        )
        nxt = "ingest: normalise, resolve identities, build the estate graph, then project the six BOMs"
    elif status == release_signature.UNSIGNED:
        state = UNSIGNED
        accepted = False
        proves = "the members match the manifest, but nothing says who produced the manifest"
        nxt = "the collector must sign the manifest; an unsigned bundle is not an authorised collection"
    elif status == release_signature.SIGNED_UNVERIFIED:
        state = SIGNATURE_UNCHECKED
        accepted = False
        proves = "the manifest carries a signature; this run has no trusted key to check it against"
        nxt = "configure this deployment's trusted collector key, then re-verify — do not ingest on trust"
    else:
        code = SIGNATURE_INVALID if status == release_signature.INVALID else (
            SIGNATURE_KEY_MISMATCH if status == release_signature.KEY_MISMATCH else SIGNATURE_MALFORMED
        )
        return _reject(
            [code],
            **facts,
            proves="nothing — the signature does not cover these bytes, or cannot be read",
            next="treat the transfer as tampered or mis-keyed and re-collect from the bank side",
        )

    return {"state": state, "accepted": accepted, "reasons": [], "proves": proves, "next": nxt, **facts}


# --------------------------------------------------------------------------------------
# on-disk bundles (the air-gapped path)
# --------------------------------------------------------------------------------------

def write_bundle(directory: str | Path, manifest: Mapping[str, Any], members: Mapping[str, bytes]) -> Path:
    """Write ``manifest.json`` and the members under ``directory``. Returns the root."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    for path, data in members.items():
        target = root / _safe_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bytes(data))
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return root


def read_bundle(directory: str | Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Read a bundle back out of a directory: the manifest and every file it lists.

    Only files the manifest lists are read, so an extra file in the directory is not
    silently pulled into the receiver's memory — :func:`verify_bundle` reports it instead.
    """
    root = Path(directory)
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"{manifest_path} does not exist; this is not a bundle")
    manifest = json.loads(manifest_path.read_text())
    members: dict[str, bytes] = {}
    for entry in manifest.get("members") or []:
        if not isinstance(entry, Mapping):
            continue
        path = _safe_path(entry.get("path"))
        candidate = root / path
        if candidate.is_file():
            members[path] = candidate.read_bytes()
    return manifest, members


def all_paths(directory: str | Path) -> list[str]:
    """Every member-shaped file on disk, including ones the manifest does not list."""
    root = Path(directory)
    found: list[str] = []
    for kind in MEMBER_KINDS:
        base = root / kind
        if not base.is_dir():
            continue
        for candidate in base.rglob("*"):
            if candidate.is_file():
                found.append(candidate.relative_to(root).as_posix())
    for name in BUNDLE_FILES:
        if (root / name).is_file():
            found.append(name)
    return sorted(found)


__all__ = [
    "ACCOUNTING_KEYS",
    "BUNDLE_FILES",
    "BUNDLE_EMPTY",
    "BUNDLE_SCHEMA",
    "COVERAGE_FAILED_TARGETS",
    "COVERAGE_KEYS",
    "COVERAGE_UNACCOUNTED_TARGETS",
    "COVERAGE_UNKNOWN",
    "LIMITS",
    "MANIFEST_MALFORMED",
    "MAX_MEMBERS",
    "MEMBER_DIGEST_MISMATCH",
    "MEMBER_KINDS",
    "MEMBER_MISSING",
    "MEMBER_NOT_IN_MANIFEST",
    "MEMBER_PATH_REFUSED",
    "MEMBER_SIZE_MISMATCH",
    "REJECTED",
    "SCHEMA_UNSUPPORTED",
    "SIGNATURE_INVALID",
    "SIGNATURE_KEY_MISMATCH",
    "SIGNATURE_MALFORMED",
    "SIGNATURE_UNCHECKED",
    "TOO_MANY_MEMBERS",
    "UNSIGNED",
    "VERIFIED",
    "all_paths",
    "build_manifest",
    "manifest_digest",
    "member_sha256",
    "read_bundle",
    "summarise_coverage",
    "verify_bundle",
    "write_bundle",
]
