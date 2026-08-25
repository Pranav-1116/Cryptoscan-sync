from api.github.acr_webhook_handler import handle_acr_event
from api.github.ecr_webhook_handler import handle_ecr_event
from api.github.gcr_webhook_handler import handle_gcr_event
from api.routers import cloud_scans, container_scans, network_scans, vulnerability
from api.routers.certificates import list_certificates
from api.schemas.asset_schemas import AssetListResponse
from api.schemas.cbom_schemas import CustomCbomRequest
from api.schemas.system_schemas import SystemCreateRequest
from api.schemas.vulnerability_schemas import VulnerabilityListResponse


def test_alias_routers_exist():
    assert cloud_scans.router.prefix == "/cloud-scans"
    assert network_scans.router.prefix == "/network-scans"
    assert container_scans.router.prefix == "/container-scans"
    assert vulnerability.router.prefix == "/vulnerabilities"
    assert callable(list_certificates)


def test_registry_webhook_handlers_and_schemas():
    ecr = handle_ecr_event({"detail": {"repository-name": "payment-api", "image-tag": "v1"}})
    assert ecr["registry"] == "ecr"
    assert ecr["accepted"] is True
    acr = handle_acr_event({"target": {"repository": "app", "tag": "latest"}, "request": {"host": "my.azurecr.io"}})
    assert acr["registry"] == "acr"
    gcr = handle_gcr_event({"tag": "gcr.io/proj/app:dev"})
    assert gcr["registry"] == "gcr"
    assert AssetListResponse(assets=[], total_count=0, page=1, page_size=50).total_count == 0
    assert CustomCbomRequest(asset_ids=["a"]).include_vulnerabilities is True
    assert SystemCreateRequest(name="payments").name == "payments"
    assert VulnerabilityListResponse(vulnerabilities=[], total_count=0, page=1, page_size=50).page == 1
