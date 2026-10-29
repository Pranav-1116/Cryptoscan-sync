"""Package tamper/airgap contract, synthetic keys/digests, no site qualification."""
import base64
import hashlib
import json
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "scripts"))
import operator_release as release  # noqa: E402


@pytest.fixture
def site(tmp_path):
    source = tmp_path / "site"; source.mkdir()
    text = (ROOT / "deploy/operator-profile/site.example.yaml").read_text()
    values = {"REGISTRY": "registry.example/bank", "ACTUAL_API_DIGEST": "a" * 64,
        "ACTUAL_WORKER_DIGEST": "b" * 64, "ACTUAL_PARSER_DIGEST": "d" * 64,
        "ACTUAL_FRONTEND_DIGEST": "e" * 64, "REGION": "in-south", "DESTINATION": "regional-sql",
        "DOCKER_SOCKET_GID": "999", "CONSOLE_HOST": "console.example", "INGRESS_CLASS": "nginx"}
    for key, val in values.items():
        text = text.replace("REPLACE_" + key, val)
    # Remove input-template comments mentioning REPLACE_* before strict validation.
    text = "\n".join(line for line in text.splitlines() if "REPLACE_" not in line) + "\n"
    (source / "site.yaml").write_text(text)
    return source


def package(site, out):
    release.build(site, out, "registry.example/bank", {"api": "a" * 64, "worker": "b" * 64, "neo4j": "c" * 64},
                  "registry.example/bank/cryptoscan-scanner@sha256:" + "d" * 64, "test-release")
    return out


def sign(root, tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    private = Ed25519PrivateKey.generate()  # Test fixture only; release tool never signs.
    public = tmp_path / "trusted.pub"
    public.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    data = (root / "release-image-lock.json").read_bytes()
    att = tmp_path / "attestation.json"
    att.write_text(json.dumps({"schema": "cryptoscan.release-attestation/1", "algorithm": "Ed25519",
        "signed_file": "release-image-lock.json", "key_id": "test-only", "lock_sha256": hashlib.sha256(data).hexdigest(),
        "signature": base64.b64encode(private.sign(data)).decode()}))
    return public, att


def test_package_migration_contract_matches_alembic_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(ROOT / "services/database/migrations/alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "services/database/migrations"))
    assert release.MIGRATION_HEAD == ScriptDirectory.from_config(config).get_current_head()


def test_offline_full_inventory_verified_without_claiming_site_ready(site, tmp_path):
    root = package(site, tmp_path / "package")
    public, att = sign(root, tmp_path)
    result = release.verify(root, public, att)
    assert result["package_inventory"] == "PASS" and result["site_qualified"] is False
    assert result["site_preflight"] == "NOT_RUN"
    assert (root / "docs/runbooks/operator-install-upgrade-recover.md").is_file()
    assert (root / "docs/runbooks/launch-assurance-handoff.md").is_file()
    assert (root / "scripts/independent_report.py").is_file()
    assert (root / "docs/templates/launch/assessment-report.json").is_file()
    assert len(json.loads((root / "operator-package.json").read_text())["images"]) == 4


@pytest.mark.parametrize("case", ["manifest", "runbook", "launch-template", "signing-tool", "missing", "extra", "nested_lock", "symlink", "lock"])
def test_any_tamper_fails(site, tmp_path, case):
    root = package(site, tmp_path / "package")
    public, att = sign(root, tmp_path)
    if case == "manifest":
        path = root / "manifests/site.yaml"; path.write_text(path.read_text().replace("replicas: 1", "replicas: 2"))
    elif case == "runbook":
        (root / "docs/runbooks/operator-install-upgrade-recover.md").write_text("invented approval")
    elif case == "launch-template":
        (root / "docs/templates/launch/assessment-report.json").write_text("invented PASS")
    elif case == "signing-tool":
        (root / "scripts/independent_report.py").write_text("signature bypass")
    elif case == "missing":
        (root / "operator-package.json").unlink()
    elif case == "extra":
        (root / "unexpected.txt").write_text("extra")
    elif case == "nested_lock":
        (root / "docs/release-image-lock.json").write_text("untracked")
    elif case == "symlink":
        (root / "external").symlink_to(public)
    else:
        (root / "release-image-lock.json").write_text("{}")
    with pytest.raises(ValueError):
        release.verify(root, public, att)


@pytest.mark.parametrize("case", ["tag", "secret", "placeholder", "duplicate", "no_ca", "wrong_parser", "wrong_api", "symlink"])
def test_invalid_site_refused_before_publication(site, tmp_path, case):
    path = site / "site.yaml"
    text = path.read_text()
    if case == "tag": text = text.replace("registry.example/bank/cryptoscan-api@sha256:" + "a" * 64, "api:latest")
    elif case == "secret": text += "\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: forbidden}\nstringData: {PASSWORD: forbidden}\n"
    elif case == "placeholder": text = text.replace("in-south", "REPLACE_REGION")
    elif case == "duplicate": text = text.replace("replicas: 1", "replicas: 1\n  replicas: 2", 1)
    elif case == "no_ca": text = text.replace("readOnly: true", "readOnly: false")
    elif case == "wrong_parser": text = text.replace("CRYPTOSCAN_SCANNER_IMAGE", "NOT_SCANNER_IMAGE")
    elif case == "wrong_api": text = text.replace("a" * 64, "f" * 64)
    elif case == "symlink": (site / "external.yaml").symlink_to(path)
    path.write_text(text)
    out = tmp_path / "package"
    with pytest.raises(ValueError): package(site, out)
    assert not out.exists()


def test_output_never_overwrites_or_contains_source(site, tmp_path):
    with pytest.raises(ValueError): package(site, site / "output")
    out = package(site, tmp_path / "package")
    with pytest.raises(ValueError): package(site, out)
    assert release.main(["verify", "--package", str(out), "--public-key", str(tmp_path / "absent"), "--attestation", str(tmp_path / "absent")]) == 1


def refresh_inventory_and_sign(root, tmp_path):
    """A valid signature must not bypass cross-file consistency checks."""
    lock_path = root / "release-image-lock.json"
    lock = json.loads(lock_path.read_text())
    lock["files_sha256"] = release.inventory(root)
    lock_path.write_text(json.dumps(lock))
    return sign(root, tmp_path)


def test_signed_package_cannot_mix_contract_and_lock_release_id(site, tmp_path):
    root = package(site, tmp_path / "package")
    path = root / "operator-package.json"
    contract = json.loads(path.read_text()); contract["release"] = "another-coordinated-release"
    path.write_text(json.dumps(contract))
    public, att = refresh_inventory_and_sign(root, tmp_path)
    with pytest.raises(ValueError, match="release"):
        release.verify(root, public, att)


def test_package_retains_source_dependency_and_schema_bindings_without_claiming_image_provenance(site, tmp_path):
    root = package(site, tmp_path / "package")
    assert (root / "source-provenance.json").is_file(), "Signed byte inventory alone does not bind source/dependencies/schema"
    provenance = json.loads((root / "source-provenance.json").read_text())
    assert len(provenance["git_commit"]) == 40
    assert len(provenance["git_tree"]) == 40
    assert provenance["migration_head"] == release.MIGRATION_HEAD
    for name in ["requirements.txt", "requirements.lock.txt", "frontend/package.json", "frontend/package-lock.json"]:
        assert provenance["files_sha256"][name] == hashlib.sha256((root / name).read_bytes()).hexdigest()
    assert any(Path(name).name.startswith(release.MIGRATION_HEAD) for name in provenance["files_sha256"])
    for name, digest in provenance["files_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest

    public, att = sign(root, tmp_path)
    result = release.verify(root, public, att)
    assert result["source_dependency_schema_binding"] == "PASS"
    assert result["image_build_provenance"] == "NOT_ESTABLISHED"
    assert result["release_candidate_approved"] is False


@pytest.mark.parametrize("name", ["requirements.lock.txt", "frontend/package-lock.json"])
def test_even_resigned_dependency_change_must_match_source_binding(site, tmp_path, name):
    root = package(site, tmp_path / "package")
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("changed-dependency-input")
    public, att = refresh_inventory_and_sign(root, tmp_path)
    with pytest.raises(ValueError, match="provenance|binding"):
        release.verify(root, public, att)


def test_expected_source_revision_requires_clean_snapshot(site, tmp_path, monkeypatch):
    original = release.source_binding
    monkeypatch.setattr(release, "source_binding", lambda: {**original(), "source_dirty": True})
    root = package(site, tmp_path / "package")
    public, att = sign(root, tmp_path)
    revision = json.loads((root / "source-provenance.json").read_text())["git_commit"]
    with pytest.raises(ValueError, match="clean"):
        release.verify(root, public, att, expected_source_commit=revision)


def test_legacy_inventory_verification_is_not_a_source_bound_candidate(site, tmp_path):
    root = package(site, tmp_path / "package")
    path = root / "operator-package.json"
    contract = json.loads(path.read_text()); contract["schema"] = "cryptoscan.operator-package/1"
    contract.pop("source_provenance_sha256")
    path.write_text(json.dumps(contract)); (root / "source-provenance.json").unlink()
    public, att = refresh_inventory_and_sign(root, tmp_path)
    result = release.verify(root, public, att)
    assert result["source_dependency_schema_binding"] == "LEGACY_UNBOUND_NOT_CANDIDATE"
    assert result["release_candidate_approved"] is False
    with pytest.raises(ValueError, match="Legacy"):
        release.verify(root, public, att, expected_source_commit="a" * 40)


def test_source_change_during_build_never_publishes_package(site, tmp_path, monkeypatch):
    original = release.source_binding
    calls = 0

    def changing_snapshot():
        nonlocal calls
        calls += 1
        result = original()
        if calls == 2:
            result["tracked_snapshot_sha256"] = "0" * 64
        return result

    monkeypatch.setattr(release, "source_binding", changing_snapshot)
    out = tmp_path / "package"
    with pytest.raises(ValueError, match="changed during package build"):
        package(site, out)
    assert calls == 2
    assert not out.exists()
    assert not list(tmp_path.glob(".operator-release-*"))
