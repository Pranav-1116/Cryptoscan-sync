from container_scanner.analyzers.analyzer_coordinator import AnalyzerCoordinator
from container_scanner.analyzers.binary.magic_bytes_identifier import identify_magic, is_binary
from container_scanner.analyzers.package_manager.crypto_package_filter import is_crypto_package
from container_scanner.analyzers.package_manager.dpkg_analyzer import DpkgAnalyzer
from container_scanner.analyzers.package_manager.rpm_analyzer import RpmAnalyzer
from container_scanner.cve.nvd_client import NvdClient
from container_scanner.cve.osv_client import OsvClient
from container_scanner.fingerprint_db.fingerprint_database import FingerprintDatabase
from container_scanner.image.image_metadata_parser import parse_docker_manifest
from container_scanner.models.library_finding import LibraryFinding


def test_dpkg_analyzer_and_crypto_filter(tmp_path):
    status = tmp_path / "var" / "lib" / "dpkg" / "status"
    status.parent.mkdir(parents=True)
    status.write_text("Package: libssl3\nStatus: install ok installed\nVersion: 3.0.2\n")
    pkgs = DpkgAnalyzer().parse(status)
    assert any(item["name"] == "openssl" for item in pkgs)
    assert is_crypto_package("libssl3")
    assert is_crypto_package("cryptography")
    assert not is_crypto_package("curl")


def test_coordinator_discovers_composer_and_rpm(tmp_path):
    (tmp_path / "composer.json").write_text('{"require": {"php": ">=8", "openssl": "^1.0"}}')
    (tmp_path / "rpm-packages.txt").write_text("openssl-3.0.7-1.el9\n")
    (tmp_path / "Cargo.toml").write_text('[dependencies]\nring = "0.17"\n')
    packages = AnalyzerCoordinator().discover_packages(tmp_path)
    names = {pkg["name"] for pkg in packages}
    assert "openssl" in names
    assert "ring" in names
    rpm = RpmAnalyzer()
    assert rpm.matches(tmp_path / "rpm-packages.txt")


def test_named_cve_clients_and_fingerprint_db():
    assert NvdClient(api_key="").enabled is False
    assert NvdClient(api_key="").lookup({"name": "openssl"}) == []
    assert OsvClient()._query_body({"name": "cryptography", "manager": "pip"})["package"]["ecosystem"] == "PyPI"
    db = FingerprintDatabase()
    assert db.canonical("libssl3") == "openssl"
    finding = LibraryFinding.from_dict({"name": "openssl", "algorithms": ["AES"]})
    assert finding.to_dict()["name"] == "openssl"


def test_magic_bytes_and_manifest(tmp_path):
    elf = tmp_path / "libcrypto.so"
    elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 8)
    assert identify_magic(elf) == "elf"
    assert is_binary(elf)
    manifest = tmp_path / "manifest.json"
    manifest.write_text('[{"RepoTags": ["app:latest"], "Layers": ["abc/layer.tar"], "Config": "cfg.json"}]')
    meta = parse_docker_manifest(manifest)
    assert meta["format"] == "docker-archive"
    assert meta["tags"] == ["app:latest"]
