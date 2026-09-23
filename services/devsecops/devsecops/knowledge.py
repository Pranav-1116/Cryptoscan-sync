"""Installed detection knowledge: signed rule packs an air-gapped box can receive.

A scanner that ships its detections inside the image can only be updated by
updating the image. That is not an update path for a disconnected deployment, and
it is not a path at all for a customer who writes their own rules. So detections
are split in two:

* **built-in rules** — the platform's own, compiled into the release;
* **installed packs** — signed bundles of rule text that arrive on removable media,
  are verified before anything is read out of them, and are then loaded by every
  scan automatically (``installed_rule_files()``).

A pack that cannot be verified, or that does not *load* against the platform's own
rule engine, is refused at install time — with the reasons. A half-installed
ruleset that silently stops matching is the failure mode this module exists to
prevent, so installation is a gate, not a copy.

Everything here is offline: no network, no clock-dependent decisions, and the
signature is an HMAC over the manifest (symmetric — the same key on both sides,
issued the same way the platform's other offline bundles are).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

PACK_FORMAT = "cryptoscan-knowledge-pack-v1"
PACKS_DIRNAME = "packs"
REGISTRY_NAME = "installed.json"
MANIFEST_NAME = "pack.json"
SIGNATURE_NAME = "pack.sig"
RULES_DIRNAME = "rules"
RULE_SUFFIXES = (".yar", ".yara")
SIGN_ALG = "HMAC-SHA256"
#: a pack is rule text and a manifest; anything larger is not what it claims to be
MAX_PACK_BYTES = 32 * 1024 * 1024


class KnowledgeError(ValueError):
    """Raised when a pack is malformed, unverifiable, or unsafe to apply."""


# --------------------------------------------------------------------------- #
# where installed knowledge lives
# --------------------------------------------------------------------------- #

def knowledge_root() -> Path:
    """The directory installed packs live under (env, then storage, then /var/lib)."""
    explicit = os.environ.get("CRYPTOSCAN_KNOWLEDGE_DIR")
    if explicit:
        return Path(explicit).expanduser()
    storage = os.environ.get("SBOM_STORAGE_DIR")
    if storage:
        return Path(storage).expanduser() / "knowledge"
    return Path("/var/lib/cryptoscan/knowledge")


def packs_dir(root: str | Path | None = None) -> Path:
    return Path(root).expanduser() / PACKS_DIRNAME if root else knowledge_root() / PACKS_DIRNAME


def registry_path(root: str | Path | None = None) -> Path:
    base = Path(root).expanduser() if root else knowledge_root()
    return base / REGISTRY_NAME


def load_registry(root: str | Path | None = None) -> dict[str, Any]:
    """What is installed. A missing or unreadable registry is empty, with a note."""
    path = registry_path(root)
    if not path.is_file():
        return {"version": 1, "packs": {}, "note": "no packs installed"}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"version": 1, "packs": {},
                "note": f"registry unreadable ({type(exc).__name__}); installed packs are not "
                        "being applied until it is repaired"}
    return {"version": 1, "packs": dict(raw.get("packs") or {}), "updated_at": raw.get("updated_at"),
            "note": raw.get("note")}


def save_registry(root: str | Path | None, registry: dict[str, Any]) -> None:
    path = registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": 1, "updated_at": datetime.now(timezone.utc).isoformat(),
               "packs": registry.get("packs") or {}}
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def installed_rule_files(root: str | Path | None = None) -> list[Path]:
    """Every rule file from an installed pack, sorted.

    Only packs that are in the registry *and* still on disk count: a pack whose
    files were removed is not silently half-applied, it is simply absent (and the
    registry says so until the next install or uninstall repairs it).
    """
    registry = load_registry(root)
    files: list[Path] = []
    for name, entry in sorted((registry.get("packs") or {}).items()):
        base = packs_dir(root) / str(name) / RULES_DIRNAME
        for row in entry.get("rules") or []:
            candidate = base / str(row.get("name"))
            if candidate.is_file():
                files.append(candidate)
    return sorted(files)


# --------------------------------------------------------------------------- #
# building and signing a pack
# --------------------------------------------------------------------------- #

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(manifest: dict[str, Any]) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: fields that describe the pack rather than its content: excluded so the digest can
#: be recomputed from a manifest that already carries it (and so re-signing a pack
#: does not change which content it identifies)
_DIGEST_EXCLUDED = frozenset({"digest", "signature", "created_at"})


def manifest_digest(manifest: dict[str, Any]) -> str:
    """The digest that identifies a pack's *content* — its files and metadata."""
    body = {k: v for k, v in manifest.items() if k not in _DIGEST_EXCLUDED}
    return _sha256_bytes(_canonical(body))


def build_pack(
    name: str,
    *,
    rules: dict[str, str] | Iterable[str | Path],
    version: str = "1.0.0",
    description: str = "",
    created_by: str = "offline-updater",
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Write a pack directory from rule sources (text or files) — unsigned.

    ``rules`` maps a filename to its text, or is a list of files to copy in.
    Nothing is signed here on purpose: building is a workstation step, signing is
    the keyed step, and separating them keeps the key off the workstation.
    """
    clean = name.strip()
    if not clean or "/" in clean or clean.startswith("."):
        raise KnowledgeError(f"pack name must be a simple name, got {name!r}")
    sources: dict[str, str] = {}
    if isinstance(rules, dict):
        for filename, text in rules.items():
            sources[str(filename)] = str(text)
    else:
        for entry in rules:
            path = Path(entry).expanduser()
            if not path.is_file():
                raise KnowledgeError(f"rule file not found: {path}")
            sources[path.name] = path.read_text(encoding="utf-8", errors="replace")
    if not sources:
        raise KnowledgeError("a pack needs at least one rule file")
    for filename in sources:
        if Path(filename).name != filename or filename.startswith("."):
            raise KnowledgeError(f"{filename}: pack file names are simple names, not paths")
        if not filename.endswith(RULE_SUFFIXES):
            raise KnowledgeError(f"{filename}: packs carry .yar/.yara files")

    root = Path(out_dir).expanduser() if out_dir else Path(tempfile.mkdtemp(prefix="cryptoscan-pack-"))
    pack_dir = root / clean
    (pack_dir / RULES_DIRNAME).mkdir(parents=True, exist_ok=True)
    files: list[dict[str, Any]] = []
    for filename, text in sorted(sources.items()):
        data = text.encode("utf-8")
        (pack_dir / RULES_DIRNAME / filename).write_bytes(data)
        files.append({"name": filename, "sha256": _sha256_bytes(data), "size": len(data)})
    manifest: dict[str, Any] = {
        "format": PACK_FORMAT,
        "name": clean,
        "version": str(version),
        "description": description,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
    }
    manifest["digest"] = manifest_digest(manifest)
    (pack_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8")
    return {"pack_dir": str(pack_dir), "manifest": manifest}


def sign_pack(pack_dir: str | Path, *, secret: str, key_id: str = "default") -> dict[str, Any]:
    """Sign a pack's manifest. Refuses an empty secret rather than writing a fake signature."""
    if not secret:
        raise KnowledgeError("a signing secret is required; an unsigned pack cannot be installed")
    directory = Path(pack_dir).expanduser()
    manifest_file = directory / MANIFEST_NAME
    if not manifest_file.is_file():
        raise KnowledgeError(f"no {MANIFEST_NAME} in {directory}")
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    signature = hmac.new(secret.encode("utf-8"), manifest_file.read_bytes(), hashlib.sha256).hexdigest()
    payload = {"alg": SIGN_ALG, "key_id": key_id, "signed_digest": manifest.get("digest"),
               "signature": signature, "signed_at": datetime.now(timezone.utc).isoformat()}
    (directory / SIGNATURE_NAME).write_text(json.dumps(payload, indent=1, sort_keys=True), encoding="utf-8")
    return payload


def verify_pack(pack_dir: str | Path, *, secret: str | None = None,
                require_signature: bool = True) -> dict[str, Any]:
    """Verify a pack end to end: signature, per-file digests, and that rules load.

    Returns ``{ok, reasons, manifest, files, ruleset}``. ``ok`` is False if anything
    is wrong — a missing file, a modified file, an extra file, a digest that does
    not match the manifest, an absent or invalid signature, or rule text the
    platform's own engine refuses. The reasons are the deliverable; the caller
    decides what to do, but nothing gets installed from a pack that is not ``ok``.
    """
    directory = Path(pack_dir).expanduser()
    reasons: list[str] = []
    result: dict[str, Any] = {"pack_dir": str(directory), "ok": False, "reasons": reasons,
                              "manifest": None, "files": [], "ruleset": None, "signature": None}
    manifest_file = directory / MANIFEST_NAME
    if not manifest_file.is_file():
        reasons.append(f"no {MANIFEST_NAME} in {directory}: this is not a knowledge pack")
        return result
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        reasons.append(f"{MANIFEST_NAME} is not valid JSON: {exc}")
        return result
    result["manifest"] = manifest
    if manifest.get("format") != PACK_FORMAT:
        reasons.append(f"unsupported pack format {manifest.get('format')!r} (expected {PACK_FORMAT})")
    if not str(manifest.get("name") or "").strip():
        reasons.append("the manifest has no pack name")
    if manifest.get("digest") != manifest_digest(manifest):
        reasons.append("the manifest digest does not match its own content "
                       "(the manifest was edited after it was built)")

    signature_file = directory / SIGNATURE_NAME
    if signature_file.is_file():
        try:
            signature = json.loads(signature_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            signature = None
            reasons.append(f"{SIGNATURE_NAME} is not valid JSON: {exc}")
        result["signature"] = signature
        if signature:
            if signature.get("alg") != SIGN_ALG:
                reasons.append(f"unsupported signature algorithm {signature.get('alg')!r}")
            if secret is None:
                reasons.append("a signing secret is required to verify this pack")
            else:
                expected = hmac.new(secret.encode("utf-8"), manifest_file.read_bytes(),
                                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(signature.get("signature") or ""), expected):
                    reasons.append("the signature does not match the manifest "
                                   "(wrong key, or the manifest was modified after signing)")
            if signature.get("signed_digest") != manifest.get("digest"):
                reasons.append("the signature was made for a different pack content")
    elif require_signature:
        reasons.append(f"no {SIGNATURE_NAME}: an unsigned pack is refused "
                       "(sign it with `python -m devsecops.knowledge sign`)")

    listed: set[str] = set()
    rules_dir = directory / RULES_DIRNAME
    for row in manifest.get("files") or []:
        filename = str(row.get("name") or "")
        if not filename:
            reasons.append("a manifest entry has no file name")
            continue
        if Path(filename).name != filename or filename.startswith("."):
            reasons.append(f"{filename}: pack file names are simple names, not paths")
            continue
        listed.add(filename)
        target = rules_dir / filename
        if not target.is_file():
            reasons.append(f"{filename}: listed in the manifest but missing from the pack")
            continue
        data = target.read_bytes()
        digest = _sha256_bytes(data)
        if digest != row.get("sha256"):
            reasons.append(f"{filename}: content does not match the manifest "
                           f"({digest[:12]} != {str(row.get('sha256'))[:12]})")
            continue
        if row.get("size") is not None and int(row["size"]) != len(data):
            reasons.append(f"{filename}: size does not match the manifest")
            continue
        result["files"].append({"name": filename, "sha256": digest, "size": len(data)})
    if rules_dir.is_dir():
        extra = sorted(p.name for p in rules_dir.iterdir()
                       if p.is_file() and p.name not in listed and p.name.endswith(RULE_SUFFIXES))
        if extra:
            reasons.append(f"the pack carries rule files the manifest does not list: {', '.join(extra)}")
    if not result["files"]:
        reasons.append("the pack contains no verifiable rule files")

    # the pack has to *load*, or installing it would quietly change what the scanner
    # matches. This uses the same engine the scans use, so the answer is the same one.
    if not reasons:
        from devsecops.yara_rules import load_rules

        ruleset = load_rules([rules_dir / row["name"] for row in result["files"]], include_builtin=False)
        result["ruleset"] = ruleset
        if ruleset.errors:
            for error in ruleset.errors[:5]:
                source, text = str(error.get("source") or ""), str(error.get("error") or "")
                reasons.append(text if source and source in text else f"{source}: {text}".strip(": "))
        if not ruleset.rules:
            reasons.append("no rules could be loaded from this pack")
        else:
            from devsecops.yara_rules import BUILTIN_RULES, parse_rules

            builtin = {f"{r.meta.get('namespace') or ''}:{r.name}" for r in parse_rules(BUILTIN_RULES, "builtin")}
            clash = sorted({f"{r.meta.get('namespace') or ''}:{r.name}" for r in ruleset.rules} & builtin)
            if clash:
                reasons.append("these rules already exist in the built-in set and would be "
                               f"ignored: {', '.join(clash[:5])}")
    result["ok"] = not reasons
    return result


# --------------------------------------------------------------------------- #
# installing
# --------------------------------------------------------------------------- #

def install_pack(pack_dir: str | Path, *, secret: str | None = None, root: str | Path | None = None,
                 dry_run: bool = False, require_signature: bool = True) -> dict[str, Any]:
    """Verify a pack, then install its rules so every scan loads them.

    Idempotent: the same pack (same digest) is reported as already installed and
    nothing is written. A different digest for the same name *replaces* it, and the
    previous version is reported, because two versions of one pack must never both
    be loaded.
    """
    report = verify_pack(pack_dir, secret=secret, require_signature=require_signature)
    base = {"pack_dir": str(pack_dir), "installed": False, "dry_run": bool(dry_run),
            "reasons": report["reasons"], "manifest": report["manifest"],
            "files": report["files"]}
    if not report["ok"]:
        return {**base, "action": "refused"}
    # the loaded rules ride along so a caller can report what it just installed
    base["ruleset"] = report.get("ruleset")
    manifest = report["manifest"]
    name, digest = str(manifest["name"]), str(manifest["digest"])
    registry = load_registry(root)
    existing = (registry.get("packs") or {}).get(name)

    if existing and existing.get("digest") == digest:
        return {**base, "action": "already-installed", "installed": True,
                "registry_entry": existing, "version": manifest.get("version")}
    if dry_run:
        return {**base, "action": "would-install", "version": manifest.get("version"),
                "replaces": existing}

    destination = packs_dir(root) / name
    # name-based suffixes, not Path.with_suffix: a pack called "acme.fips" must not
    # turn into "acme.installing"
    staging = destination.parent / f"{destination.name}.installing"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    (staging / RULES_DIRNAME).mkdir(parents=True, exist_ok=True)
    shutil.copy2(Path(pack_dir) / MANIFEST_NAME, staging / MANIFEST_NAME)
    signature_file = Path(pack_dir) / SIGNATURE_NAME
    if signature_file.is_file():
        shutil.copy2(signature_file, staging / SIGNATURE_NAME)
    for row in report["files"]:
        shutil.copy2(Path(pack_dir) / RULES_DIRNAME / row["name"], staging / RULES_DIRNAME / row["name"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    # a replace is two atomic renames with the new copy already complete in between:
    # the destination is never missing, so an interrupted update leaves either the
    # old version or the new one — never a pack that is half there
    replaced_dir = destination.parent / f"{destination.name}.replaced"
    if replaced_dir.exists():
        shutil.rmtree(replaced_dir, ignore_errors=True)
    if destination.exists():
        os.replace(destination, replaced_dir)
    os.replace(staging, destination)
    shutil.rmtree(replaced_dir, ignore_errors=True)

    entry = {"version": manifest.get("version"), "digest": digest,
             "description": manifest.get("description"),
             "installed_at": datetime.now(timezone.utc).isoformat(),
             "signed_by": (report.get("signature") or {}).get("key_id"),
             "rules": [{"name": row["name"], "sha256": row["sha256"]} for row in report["files"]],
             "rule_names": sorted(rule.name for rule in (report["ruleset"].rules if report["ruleset"] else []))}
    packs = dict(registry.get("packs") or {})
    packs[name] = entry
    save_registry(root, {"packs": packs})
    return {**base, "action": "installed", "installed": True, "version": manifest.get("version"),
            "registry_entry": entry, "replaced": existing,
            "rules_dir": str(destination / RULES_DIRNAME)}


def uninstall_pack(name: str, *, root: str | Path | None = None) -> dict[str, Any]:
    """Remove a pack so its rules stop being loaded. Says whether it was there."""
    clean = str(name).strip()
    registry = load_registry(root)
    packs = dict(registry.get("packs") or {})
    entry = packs.pop(clean, None)
    destination = packs_dir(root) / clean
    if entry is None and not destination.exists():
        return {"action": "not-installed", "pack": clean, "removed": False}
    shutil.rmtree(destination, ignore_errors=True)
    save_registry(root, {"packs": packs})
    return {"action": "uninstalled", "pack": clean, "removed": True, "removed_entry": entry}


def knowledge_state(root: str | Path | None = None) -> dict[str, Any]:
    """What the scanner will load: built-in rules plus every installed pack."""
    from devsecops.yara_rules import BUILTIN_RULES, load_rules, parse_rules

    registry = load_registry(root)
    builtin = parse_rules(BUILTIN_RULES, "builtin:devsecops.yar")
    installed = installed_rule_files(root)
    try:
        combined = load_rules(installed) if installed else load_rules()
    except Exception as exc:  # noqa: BLE001 — a broken pack must be visible, not fatal
        return {"builtin": {"rules": len(builtin), "digest": _sha256_bytes(BUILTIN_RULES.encode())},
                "installed": registry.get("packs") or {}, "rules_dir": str(packs_dir(root)),
                "registry_note": registry.get("note"), "error": f"{type(exc).__name__}: {exc}",
                "note": "the rule set could not be loaded; scans will refuse rather than run "
                        "without the rules they claim to apply"}
    return {
        "builtin": {"rules": len(builtin), "digest": _sha256_bytes(BUILTIN_RULES.encode("utf-8")),
                    "private_rules": sum(1 for r in builtin if r.private)},
        "installed": registry.get("packs") or {},
        "installed_rule_files": [str(path) for path in installed],
        "rules_dir": str(packs_dir(root)),
        "ruleset": {"rules": len(combined.rules), "private_rules": sum(1 for r in combined.rules if r.private),
                    "digest": combined.digest, "errors": combined.errors[:10],
                    "error_count": len(combined.errors)},
        "registry_note": registry.get("note"),
        "note": ("built-in rules always run; installed packs add to them. Every scan reports the "
                 "digest of the set it actually used."),
    }


# --------------------------------------------------------------------------- #
# moving a pack across the gap
# --------------------------------------------------------------------------- #

def export_bundle(pack_dir: str | Path, out_path: str | Path | None = None) -> dict[str, Any]:
    """Pack a signed pack directory into one .tar.gz for removable media."""
    directory = Path(pack_dir).expanduser()
    if not (directory / MANIFEST_NAME).is_file():
        raise KnowledgeError(f"no {MANIFEST_NAME} in {directory}")
    name = directory.name
    target = Path(out_path).expanduser() if out_path else directory.parent / f"{name}.tar.gz"
    with tarfile.open(target, "w:gz") as archive:
        for relative in [MANIFEST_NAME, SIGNATURE_NAME, RULES_DIRNAME]:
            candidate = directory / relative
            if candidate.exists():
                archive.add(candidate, arcname=f"{name}/{relative}")
    return {"bundle": str(target), "bytes": target.stat().st_size, "pack": name}


def extract_bundle(bundle: str | Path, dest: str | Path) -> dict[str, Any]:
    """Unpack a bundle safely: no absolute paths, no ``..``, no links, no surprises.

    A bundle crosses an air gap on removable media, which is exactly the kind of
    input that should never be able to write outside the directory it is unpacked
    into.
    """
    path = Path(bundle).expanduser()
    if not path.is_file():
        raise KnowledgeError(f"bundle not found: {path}")
    if path.stat().st_size > MAX_PACK_BYTES:
        raise KnowledgeError(f"bundle is larger than {MAX_PACK_BYTES} bytes; refusing to unpack it")
    destination = Path(dest).expanduser()
    destination.mkdir(parents=True, exist_ok=True)
    members: list[str] = []
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.islnk() or member.issym():
                raise KnowledgeError(f"{member.name}: bundles do not carry links")
            if not (member.isreg() or member.isdir()):
                raise KnowledgeError(f"{member.name}: only regular files and directories are allowed")
            name = member.name[2:] if member.name.startswith("./") else member.name
            if not name or name.startswith("/") or "\\" in name or ".." in Path(name).parts:
                raise KnowledgeError(f"{member.name}: refusing a path outside the destination")
            members.append(name)
    # every member was checked above; on 3.12+ the stdlib data filter is a second
    # opinion (older interpreters have no such filter, hence the version gate)
    extract_kwargs = {"filter": "data"} if sys.version_info >= (3, 12) else {}
    with tarfile.open(path, "r:gz") as archive:
        archive.extractall(destination, **extract_kwargs)
    return {"dest": str(destination), "members": sorted(members)}


def resolve_secret(explicit: str | None = None, *, key_id: str = "default") -> tuple[str | None, str]:
    """The signing key for packs: explicit, then the environment, then nothing.

    The platform's own signing chain (vault, settings, HKDF) needs a database
    session and lives in the artifact store; a pack is built and signed on a
    workstation and installed on an appliance, so this reads the environment and
    refuses rather than inventing a key.
    """
    if explicit:
        return explicit, key_id
    for env_name in ("CRYPTOSCAN_BUNDLE_SECRET", "SECRET_KEY"):
        value = os.environ.get(env_name)
        if value:
            return value, f"env:{env_name}"
    return None, "unsigned"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _parse_args(argv: list[str] | None) -> Any:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m devsecops.knowledge",
        description="Detection knowledge packs: build, sign, verify, install. Everything "
                    "offline; a pack that does not verify or does not load is refused.",
    )
    parser.add_argument("action", choices=("list", "build", "sign", "verify", "install", "uninstall", "export", "extract"))
    parser.add_argument("target", nargs="?", help="pack directory, bundle, or pack name")
    parser.add_argument("--rules", action="append", default=[], help="rule file to include (repeatable)")
    parser.add_argument("--name", default=None, help="pack name (default: the output directory name)")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--description", default="")
    parser.add_argument("--created-by", default="offline-updater")
    parser.add_argument("--out", default=None, help="output directory (build) or file (export/extract)")
    parser.add_argument("--secret", default=None, help="signing secret (default: CRYPTOSCAN_BUNDLE_SECRET/SECRET_KEY)")
    parser.add_argument("--key-id", default="default")
    parser.add_argument("--root", default=None, help="knowledge root (default: CRYPTOSCAN_KNOWLEDGE_DIR)")
    parser.add_argument("--dry-run", action="store_true", help="verify and say what would happen")
    parser.add_argument("--allow-unsigned", action="store_true",
                        help="accept a pack with no signature (recorded as such)")
    parser.add_argument("--json", default=None, help="write the result here ('-' for stdout)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Exit 0 = done; 2 = refused (reasons on stderr); 4 = bad input."""
    args = _parse_args(argv)
    secret, key_id = resolve_secret(args.secret, key_id=args.key_id)
    result: dict[str, Any]
    try:
        if args.action == "list":
            result = knowledge_state(args.root)
        elif args.action == "build":
            if not args.rules:
                print("build needs at least one --rules FILE", file=sys.stderr)
                return 4
            out = args.out or "."
            name = args.name or args.target or "pack"
            result = build_pack(name, rules=args.rules, version=args.version,
                                description=args.description, created_by=args.created_by,
                                out_dir=out)
        elif args.action == "sign":
            if not args.target:
                print("sign needs a pack directory", file=sys.stderr)
                return 4
            if not secret:
                print("signing needs --secret, CRYPTOSCAN_BUNDLE_SECRET or SECRET_KEY",
                      file=sys.stderr)
                return 4
            result = {"pack_dir": args.target, "signature": sign_pack(args.target, secret=secret, key_id=key_id)}
        elif args.action == "verify":
            if not args.target:
                print("verify needs a pack directory or bundle", file=sys.stderr)
                return 4
            target = args.target
            if str(target).endswith((".tar.gz", ".tgz")):
                unpacked = extract_bundle(target, args.out or tempfile.mkdtemp(prefix="cryptoscan-unpack-"))
                sub = sorted(Path(unpacked["dest"]).iterdir())
                target = str(sub[0]) if len(sub) == 1 and sub[0].is_dir() else unpacked["dest"]
            result = verify_pack(target, secret=secret, require_signature=not args.allow_unsigned)
        elif args.action == "install":
            if not args.target:
                print("install needs a pack directory or bundle", file=sys.stderr)
                return 4
            target = args.target
            if str(target).endswith((".tar.gz", ".tgz")):
                unpacked = extract_bundle(target, args.out or tempfile.mkdtemp(prefix="cryptoscan-unpack-"))
                sub = sorted(Path(unpacked["dest"]).iterdir())
                target = str(sub[0]) if len(sub) == 1 and sub[0].is_dir() else unpacked["dest"]
            result = install_pack(target, secret=secret, root=args.root, dry_run=args.dry_run,
                                  require_signature=not args.allow_unsigned)
        elif args.action == "uninstall":
            if not args.target:
                print("uninstall needs a pack name", file=sys.stderr)
                return 4
            result = uninstall_pack(args.target, root=args.root)
        elif args.action == "export":
            if not args.target:
                print("export needs a pack directory", file=sys.stderr)
                return 4
            result = export_bundle(args.target, args.out)
        else:  # extract
            if not args.target or not args.out:
                print("extract needs a bundle and --out DIR", file=sys.stderr)
                return 4
            result = extract_bundle(args.target, args.out)
    except KnowledgeError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    refused = result.get("action") == "refused" or result.get("ok") is False
    if args.json == "-":
        print(json.dumps(result, indent=2))
    elif args.json:
        Path(args.json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    else:
        _print_result(args.action, result)
    if refused:
        for reason in result.get("reasons") or ["the pack was refused"]:
            print(f"  refused: {reason}", file=sys.stderr)
        return 2
    return 0


def _print_result(action: str, result: dict[str, Any]) -> None:
    if action == "list":
        builtin = result.get("builtin") or {}
        print(f"built-in: {builtin.get('rules')} rules, digest {str(builtin.get('digest'))[:16]}")
        packs = result.get("installed") or {}
        print(f"installed packs: {len(packs)} (under {result.get('rules_dir')})")
        for name, entry in sorted(packs.items()):
            print(f"  {name} v{entry.get('version')} · digest {str(entry.get('digest'))[:12]} · "
                  f"{len(entry.get('rules') or [])} file(s) · installed {str(entry.get('installed_at'))[:19]}")
        if result.get("registry_note"):
            print(f"  note: {result['registry_note']}")
        ruleset = result.get("ruleset") or {}
        print(f"what a scan will load: {ruleset.get('rules')} rules, digest "
              f"{str(ruleset.get('digest'))[:16]}, {ruleset.get('error_count')} error(s)")
        return
    if action == "build":
        manifest = result["manifest"]
        print(f"built {manifest['name']} v{manifest['version']} at {result['pack_dir']} "
              f"({len(manifest['files'])} rule file(s), digest {manifest['digest'][:16]})")
        print("  next: sign it (python -m devsecops.knowledge sign <dir> --secret …) — an "
              "unsigned pack will not install")
        return
    if action == "sign":
        print(f"signed {result['pack_dir']} with key {result['signature']['key_id']} "
              f"({result['signature']['alg']})")
        return
    if action in ("verify", "install"):
        manifest = result.get("manifest") or {}
        print(f"{result.get('action', 'verify')}: {manifest.get('name')} v{manifest.get('version')} "
              f"({len(result.get('files') or [])} rule file(s))")
        if result.get("replaced"):
            print(f"  replaced {result['replaced'].get('version')} "
                  f"({str(result['replaced'].get('digest'))[:12]})")
        if result.get("rules_dir"):
            print(f"  rules installed under {result['rules_dir']}")
        return
    print(json.dumps(result, indent=1))


if __name__ == "__main__":  # pragma: no cover — CLI entry point
    raise SystemExit(main())
