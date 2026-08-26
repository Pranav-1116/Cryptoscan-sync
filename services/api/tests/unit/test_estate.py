from api.schemas.job_schemas import TriggerScanRequest
from cloud_scanner.estate import plan_campaign


def test_trigger_accepts_cloud_url():
    body = TriggerScanRequest(repo_url="cloud://aws/111122223333")
    assert body.repo_url.startswith("cloud://")


def test_estate_router_mounted():
    from api.routers import estate

    paths = [getattr(route, "path", "") for route in estate.router.routes]
    assert any(path.endswith("/campaigns") for path in paths)


def test_cloud_inventory_routes_exist():
    from api.routers import cloud

    paths = [getattr(route, "path", "") for route in cloud.router.routes]
    assert any("/inventory" in path for path in paths)
    assert any("/accounts/{account_id}/inventory" in path for path in paths)


def test_plan_campaign_respects_limit():
    systems = [
        {"id": f"g{i}", "name": f"svc-{i}", "scan_target": f"https://git/bank/svc-{i}.git"}
        for i in range(80)
    ]
    planned = plan_campaign(systems, limit=25)
    assert len(planned) == 25
    assert all(item["job_type"] == "SYSTEM" for item in planned)
