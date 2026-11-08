#!/usr/bin/env python3
"""Offline operator package: exact-file signed inventory, pinned site manifests,
compatibility contract and explicit preflight. No signing or deployment mutation.

Build from reviewed SITE manifests (not unmodified reference templates). External
PostgreSQL, Redis/TLS, ingress/CA and dedicated worker isolation runtime must be
provisioned by the operator. Cryptographic validation is not site qualification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
import yaml
from pin_release_images import validate, validate_registry
from verify_release_attestation import verify_attestation

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "kubernetes-external-services/local-source-v1"
MIGRATION_HEAD = "0138"  # 0137 cryptolog tables, 0138 performance tables
IMAGE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]*@sha256:[0-9a-f]{64}$")
EXAMPLE_NAMES = {"15-secret.example.yaml"}
DOCS = ["docs/readiness-evidence/launch-engineering-2026-10-22.md", "docs/runbooks/launch-assurance-handoff.md",
        "docs/bank-environment/56-independent-security-assurance.md",
        "docs/bank-environment/57-operational-ownership-and-demonstrated-service.md",
        "docs/bank-environment/58-focused-payments-customer-pilot.md",
        "docs/templates/launch/README.md", "docs/templates/launch/engagement.json",
        "docs/templates/launch/assessment-report.json", "docs/templates/launch/operating-assignment.json",
        "docs/templates/launch/operating-exercise.json", "docs/templates/launch/payments-pilot.json",
        "docs/templates/launch/review.json", "docs/templates/launch/finding-plan.json",
        "docs/templates/launch/finding-completion.json", "scripts/independent_report.py", "docs/runbooks/operator-install-upgrade-recover.md", "docs/runbooks/controlled-execution-upgrade.md",
        "docs/runbooks/evidence-assurance-upgrade.md", "docs/dev/scanner-isolation.md",
        "docs/readiness-evidence/operator-workload-mixed-2026-10-21-run1.json",
        "docs/readiness-evidence/operator-workload-mixed-2026-10-21-run2.json"]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    result = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise ValueError("Package symlinks are forbidden")
        if p.is_file() and p != root / "release-image-lock.json":
            result[p.relative_to(root).as_posix()] = sha(p)
    return result


class UniqueLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    result = {}
    for k, v in node.value:
        key = loader.construct_object(k, deep=deep)
        if key in result:
            raise ValueError("Duplicate manifest key")
        result[key] = loader.construct_object(v, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def manifests(root):
    all_paths = list(root.rglob("*"))
    if any(p.is_symlink() for p in all_paths):
        raise ValueError("Site symlinks are forbidden")
    paths = sorted(p for p in all_paths if p.is_file())
    if not paths or len(paths) > 100 or sum(p.stat().st_size for p in paths) > 5 * 1048576:
        raise ValueError("Site manifests require 1..100 files, at most 5 MiB")
    docs = []
    for p in paths:
        if p.is_symlink() or p.suffix not in {".yaml", ".yml", ".json"} or p.name in EXAMPLE_NAMES:
            raise ValueError("Site input must contain only real regular Kubernetes YAML/JSON, no examples/secrets/symlinks")
        raw = p.read_text()
        if any(isinstance(e, yaml.events.AliasEvent) for e in yaml.parse(raw)):
            raise ValueError("Manifest aliases are forbidden")
        for doc in yaml.load_all(raw, Loader=UniqueLoader):
            if not isinstance(doc, dict) or not doc.get("apiVersion") or not doc.get("kind"):
                raise ValueError("Every manifest needs Kubernetes apiVersion/kind")
            if "REPLACE_" in str(doc):
                raise ValueError("Unresolved site template value")
            if doc["kind"] in {"Secret", "List"}:
                raise ValueError("Secrets and opaque Lists are not package inputs; provision secrets separately")
            docs.append(doc)
    return docs


def walk(value):
    if isinstance(value, dict):
        yield value
        for x in value.values():
            yield from walk(x)
    elif isinstance(value, list):
        for x in value:
            yield from walk(x)


def validate_site(root, parser_image, expected=None):
    docs = manifests(root)
    images = set()
    roles = {}
    for doc in docs:
        if doc["kind"] in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}:
            role = doc.get("metadata", {}).get("name")
            if role in roles:
                raise ValueError("Duplicate workload name")
            roles[role] = doc
        for node in walk(doc):
            if "image" in node:
                if not isinstance(node["image"], str) or not IMAGE.fullmatch(node["image"]):
                    raise ValueError("Every image (including init/sidecar) must be digest pinned")
                images.add(node["image"])
            if "name" in node and "value" in node and re.search(r"PASSWORD|TOKEN|SECRET|DATABASE_URL|REDIS_URL", str(node["name"])):
                raise ValueError("Credential-bearing environment must use secret references, not literal values")
            if "data" in node and isinstance(node["data"], dict):
                if any(re.search(r"PASSWORD|TOKEN|SECRET|DATABASE_URL|REDIS_URL", k) for k in node["data"]):
                    raise ValueError("ConfigMap must not contain credential-bearing settings")
    if "cryptoscan-frontend" not in roles:
        raise ValueError("Missing cryptoscan-frontend operator console workload")
    for role in ("cryptoscan-api", "cryptoscan-worker"):
        if role not in roles:
            raise ValueError(f"Missing site workload {role}")
        workload = roles[role]
        nodes = list(walk(workload))
        if not any("secretRef" in x or "secretKeyRef" in x for x in nodes):
            raise ValueError(f"{role} requires externally provisioned secret references")
        if not any("secret" in x and isinstance(x["secret"], dict) for x in nodes):
            raise ValueError(f"{role} requires an explicit read-only CA/secret volume mount")
        mounts = [m for n in nodes for m in n.get("volumeMounts", [])]
        secret_names = {v["name"] for n in nodes for v in n.get("volumes", []) if "secret" in v}
        if not any(m.get("readOnly") is True and m.get("name") in secret_names for m in mounts):
            raise ValueError(f"{role} requires read-only certificate mounting")
        containers = workload["spec"]["template"]["spec"]["containers"]
        main = next((c for c in containers if c.get("name") == ("api" if role.endswith("api") else "worker")), None)
        if not main or not main.get("image"):
            raise ValueError(f"Missing main {role} container")
        effective = {n.get("name"): n.get("value") for n in main.get("env", [])}
        if (effective.get("ENVIRONMENT") != "production" or effective.get("CRYPTOSCAN_EXECUTION_CONTROLS") != "true"
                or effective.get("CRYPTOSCAN_DEPLOYMENT_PROFILE") != PROFILE):
            raise ValueError(f"{role} must explicitly pin production/controlled settings after secret envFrom")
        if role.endswith("worker") and effective.get("WORKSPACE_BASE_PATH") != "/tmp/cryptoscan-workspaces":
            raise ValueError("Supported profile requires the documented identical host/worker staging path")
        if expected:
            label = "api" if role.endswith("api") else "worker"
            if main["image"] != f"{expected['registry']}/cryptoscan-{label}@sha256:{expected['digests'][label]}":
                raise ValueError(f"{role} image disagrees with signed release lock")
    worker_nodes = list(walk(roles["cryptoscan-worker"]))
    if not any(n.get("name") == "CRYPTOSCAN_SCANNER_IMAGE" and n.get("value") == parser_image for n in worker_nodes):
        raise ValueError("Worker must explicitly bind approved parser image; a lock entry alone is insufficient")
    if not IMAGE.fullmatch(parser_image):
        raise ValueError("Parser must be digest pinned")
    return sorted(images | {parser_image})


DEPENDENCY_INPUTS = ("requirements.txt", "requirements.lock.txt", "frontend/package.json", "frontend/package-lock.json")
PROVENANCE_SCHEMA = "cryptoscan.operator-source-binding/1"


def source_binding():
    """Bind the actual tracked worktree, not just a possibly dirty HEAD label.

    This is a source assertion for an external signer, NOT an OCI build
    attestation. Untracked inputs/dirty state explicitly prevent a clean claim.
    """
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, timeout=20)
    paths = git("ls-files", "-z").decode().strip("\0").split("\0")
    tracked = {}
    for name in paths:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Tracked source input must be a regular available file")
        tracked[name] = sha(path)
    dirty = bool(git("status", "--porcelain", "--untracked-files=normal").strip())
    required = sorted(set(DEPENDENCY_INPUTS) | {p for p in paths if p.startswith("services/database/migrations/")})
    return {"schema": PROVENANCE_SCHEMA, "git_commit": git("rev-parse", "HEAD").decode().strip(),
        "git_tree": git("rev-parse", "HEAD^{tree}").decode().strip(), "source_dirty": dirty,
        "tracked_files_sha256": tracked,
        "tracked_snapshot_sha256": hashlib.sha256(json.dumps(tracked, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "migration_head": MIGRATION_HEAD, "files_sha256": {p: tracked[p] for p in required},
        "limit": "Tracked worktree binding only; dirty/untracked inputs are not a clean revision. OCI contents, test execution, CI and independent review require external evidence."}


def verify_source_binding(root, contract, lock, expected_source_commit=None):
    provenance = json.loads((root / "source-provenance.json").read_text())
    if provenance.get("schema") != PROVENANCE_SCHEMA or provenance.get("migration_head") != MIGRATION_HEAD:
        raise ValueError("Unsupported source/schema binding")
    for key in ("git_commit", "git_tree"):
        if not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get(key, ""))):
            raise ValueError("Invalid source provenance revision")
    if expected_source_commit and provenance["git_commit"] != expected_source_commit:
        raise ValueError("Source provenance does not match expected source commit")
    if expected_source_commit and provenance.get("source_dirty") is not False:
        raise ValueError("Expected source revision requires a clean tracked source snapshot")
    if not isinstance(provenance.get("source_dirty"), bool):
        raise ValueError("Source provenance must disclose dirty state")
    tracked, files = provenance.get("tracked_files_sha256"), provenance.get("files_sha256")
    if not isinstance(tracked, dict) or not isinstance(files, dict) or not set(DEPENDENCY_INPUTS) <= files.keys():
        raise ValueError("Missing dependency/source provenance binding")
    if not any(Path(name).name.startswith(MIGRATION_HEAD) for name in files):
        raise ValueError("Missing schema migration source binding")
    for name, digest in files.items():
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise ValueError("Invalid source provenance path/digest")
        if tracked.get(name) != digest or sha(root / path) != digest:
            raise ValueError("Packaged dependency/schema disagrees with source provenance binding")
    snapshot = hashlib.sha256(json.dumps(tracked, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if snapshot != provenance.get("tracked_snapshot_sha256"):
        raise ValueError("Source snapshot provenance digest mismatch")
    if contract.get("source_provenance_sha256") != sha(root / "source-provenance.json") or contract.get("release") != lock.get("release"):
        raise ValueError("Package source binding/release mismatch")
    return provenance


def build(source, out, registry, digests, parser_image, release):
    source, out = source.resolve(), out.resolve()
    if not source.is_dir() or out.exists() or source == out or source in out.parents or out in source.parents:
        raise ValueError("Source must exist; output must be new and disjoint (never overwrite a release)")
    registry = validate_registry(registry)
    digests = {name: validate(name, digests[name]) for name in ("api", "worker", "neo4j")}
    if not re.fullmatch(r"[a-zA-Z0-9._-]{1,80}", release):
        raise ValueError("Release identifier must be a bounded path-free label")
    provenance = source_binding()
    lock = {"schema": "cryptoscan.immutable-image-release/1", "registry": registry, "digests": digests}
    images = validate_site(source, parser_image, lock)
    out.parent.mkdir(parents=True, exist_ok=True)
    # Stage fully before publication; no partial output is mistaken for a release.
    with tempfile.TemporaryDirectory(dir=out.parent, prefix=".operator-release-") as tmp:
        stage = Path(tmp) / "package"
        shutil.copytree(source, stage / "manifests")
        if validate_site(stage / "manifests", parser_image, lock) != images:
            raise ValueError("Source changed during package build")
        docs = [str(p.relative_to(ROOT)) for p in sorted((ROOT / "docs").rglob("*.md"))]
        # Include the documentation library, reference site input and dispatcher
        # build recipe so the primary runbook has no missing deployment links.
        for name in sorted(set(DOCS + docs + ["PRODUCTION-READINESS.md", "deploy/operator-profile/site.example.yaml",
                ".docker/worker-runtime/Dockerfile", "scripts/operator_release.py", "scripts/verify_release_attestation.py", "scripts/pin_release_images.py"])):
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        for name, digest in provenance["files_sha256"].items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
            if sha(target) != digest:
                raise ValueError("Source dependency/schema changed during package build")
        (stage / "source-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
        contract = {"schema": "cryptoscan.operator-package/2", "source_provenance_sha256": sha(stage / "source-provenance.json"), "release": release, "profile": PROFILE,
            "migration_head": MIGRATION_HEAD, "producer_worker_policy": "QUIESCE_AND_REPLACE_TOGETHER_NO_MIXED_VERSIONS",
            "legacy_jobs": "READ_ONLY_UNPINNED_JOBS_REQUIRE_APPROVED_NEW_SUBMISSION",
            "replay": "GAPS_RESET_FULL_SQL_RECONCILIATION_NO_CURSOR_REWRITE",
            "parser_image": parser_image, "images": images,
            "external_prerequisites": ["Regional PostgreSQL with verified TLS and rehearsed encrypted backup restore",
                "Regional Redis with verified TLS, role ACLs and witnessed recovery measurements",
                "Dedicated reviewed worker Docker runtime, CLI and identical host/container staging paths",
                "Externally provisioned secret and CA mounts, HTTPS ingress and trusted human session bootstrap"],
            "qualification": "REFERENCE_PACKAGE_NOT_SITE_ACCEPTANCE", "bank_capacity_qualified": False}
        (stage / "operator-package.json").write_text(json.dumps(contract, indent=2) + "\n")
        if source_binding() != provenance:
            raise ValueError("Source worktree changed during package build")
        lock.update(release=release, profile=PROFILE, rendered_at=datetime.now(timezone.utc).isoformat(),
                    files_sha256=inventory(stage), parser_image=parser_image)
        (stage / "release-image-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        os.rename(stage, out)
    return {"package": str(out), "lock_sha256": sha(out / "release-image-lock.json"), "signature_required": True}


def verify(root, public_key, attestation, expected_source_commit=None):
    if root.is_symlink():
        raise ValueError("Package root symlink forbidden")
    root = root.resolve()
    if root.is_symlink() or not root.is_dir() or (root / "release-image-lock.json").is_symlink():
        raise ValueError("Package and lock must be real, regular paths")
    # Existing external Ed25519 trust boundary signs the exact lock bytes,
    # including the complete package inventory. No private keys handled here.
    report = verify_attestation(root, public_key, attestation)
    lock = json.loads((root / "release-image-lock.json").read_text())
    if lock.get("profile") != PROFILE or not isinstance(lock.get("files_sha256"), dict):
        raise ValueError("Missing supported profile or signed full-file inventory")
    actual_inventory = inventory(root)
    if actual_inventory != lock["files_sha256"]:
        raise ValueError("Package inventory mismatch: changed, missing or extra files")
    contract = json.loads((root / "operator-package.json").read_text())
    if contract.get("schema") not in {"cryptoscan.operator-package/1", "cryptoscan.operator-package/2"} or contract.get("migration_head") != MIGRATION_HEAD or contract.get("profile") != PROFILE:
        raise ValueError("Unsupported package/schema/migration profile")
    if contract.get("release") != lock.get("release"):
        raise ValueError("Contract and lock release identifiers disagree")
    provenance = None
    if contract["schema"] == "cryptoscan.operator-package/2":
        provenance = verify_source_binding(root, contract, lock, expected_source_commit)
    elif expected_source_commit:
        raise ValueError("Legacy package has no source provenance binding")
    images = validate_site(root / "manifests", lock["parser_image"], lock)
    if contract.get("images") != images or contract.get("parser_image") != lock["parser_image"]:
        raise ValueError("Contract/image inventory disagrees with signed manifests")
    return {**report, "package_inventory": "PASS", "profile": PROFILE, "files": len(lock["files_sha256"]),
            "source_dependency_schema_binding": "PASS" if provenance else "LEGACY_UNBOUND_NOT_CANDIDATE",
            "source_commit": provenance["git_commit"] if provenance else None,
            "source_dirty": provenance["source_dirty"] if provenance else None,
            "image_build_provenance": "NOT_ESTABLISHED", "required_test_results": "NOT_ESTABLISHED",
            "separate_review": "NOT_ESTABLISHED", "ci_release_decision": "NOT_ESTABLISHED",
            "release_candidate_approved": False,
            "site_preflight": "NOT_RUN", "site_qualified": False}


def cluster_preflight(root):
    # Explicit opt-in only. Dry-run performs admission but creates no resources.
    if not shutil.which("kubectl"):
        raise ValueError("kubectl missing; cluster preflight not performed")
    result = subprocess.run(["kubectl", "apply", "--dry-run=server", "--validate=strict", "-R", "-f", str(root / "manifests")],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise ValueError("Cluster admission preflight failed; inspect kubectl locally (output may contain site metadata)")
    return {"server_dry_run": "PASS", "runtime_secret_ca_backup_qualification": "NOT_ESTABLISHED"}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("build")
    b.add_argument("--source", type=Path, required=True); b.add_argument("--out", type=Path, required=True)
    b.add_argument("--registry", required=True); b.add_argument("--release", required=True)
    for name in ("api", "worker", "neo4j"):
        b.add_argument(f"--{name}-digest", required=True)
    b.add_argument("--parser-image", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--package", type=Path, required=True); v.add_argument("--public-key", type=Path, required=True)
    v.add_argument("--attestation", type=Path, required=True); v.add_argument("--cluster-preflight", action="store_true")
    v.add_argument("--expected-source-commit", help="Require an exact source revision binding; rejects legacy unbound packages")
    args = ap.parse_args(argv)
    try:
        if args.mode == "build":
            report = build(args.source, args.out, args.registry, {n: getattr(args, n + "_digest") for n in ("api", "worker", "neo4j")}, args.parser_image, args.release)
        else:
            report = verify(args.package, args.public_key, args.attestation, args.expected_source_commit)
            if args.cluster_preflight:
                report["preflight"] = cluster_preflight(args.package)
        print(json.dumps(report, indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError, yaml.YAMLError, subprocess.TimeoutExpired) as exc:
        print(f"Operator release: FAIL ({type(exc).__name__}): {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
