from pathlib import Path

from container_scanner.core.scanner import ContainerScanner
from container_scanner.image.layer_extractor import extract_layers
from container_scanner.registry.acr_handler import parse_acr_event
from container_scanner.registry.dockerhub_handler import parse_dockerhub_event
from container_scanner.registry.ecr_handler import parse_ecr_event
from container_scanner.registry.gcr_handler import parse_gcr_event
from container_scanner.registry.harbor_handler import parse_harbor_event

from test_image_archive import make_docker_save


def test_binary_sha256_lookup(tmp_path: Path):
    blob = tmp_path / "libcrypto.so.3"
    blob.write_bytes(b"openssl-fingerprint-test")
    scanner = ContainerScanner()
    digest = __import__("hashlib").sha256(b"openssl-fingerprint-test").hexdigest()
    scanner.catalog._hashes[digest] = {
        "library": "OpenSSL",
        "version": "3.0.2",
        "algorithms": ["AES", "RSA"],
    }
    result = scanner.scan_filesystem(tmp_path)
    hit = next(item for item in result["binaries"] if item["path"].endswith("libcrypto.so.3"))
    assert hit["sha256"] == digest
    assert hit["detection_method"] == "BINARY_FINGERPRINT"
    assert hit["version"] == "3.0.2"
    assert hit["confidence"] == "HIGH"


def test_layer_extractor_alias(tmp_path: Path):
    archive = make_docker_save(tmp_path / "src")
    extracted = extract_layers(archive, tmp_path / "out")
    assert extracted.root.exists()


def test_registry_webhook_parsers():
    ecr = parse_ecr_event(
        {
            "account": "123",
            "region": "us-east-1",
            "detail": {"repository-name": "payments", "image-tag": "1.2"},
        }
    )
    assert ecr["registry"] == "ecr"
    assert ecr["reference"].endswith("payments:1.2")
    acr = parse_acr_event(
        {"request": {"host": "my.azurecr.io"}, "target": {"repository": "app", "tag": "dev"}}
    )
    assert acr["image"] == "my.azurecr.io/app"
    hub = parse_dockerhub_event(
        {"repository": {"repo_name": "acme/app"}, "push_data": {"tag": "latest"}}
    )
    assert hub["reference"] == "acme/app:latest"
    harbor = parse_harbor_event(
        {"event_data": {"resources": [{"resource_url": "harbor.local/app:1", "tag": "1"}]}}
    )
    assert harbor["image"]
    gcr = parse_gcr_event({"tag": "gcr.io/proj/app:v1", "action": "INSERT"})
    assert gcr["source"] == "gcr"
