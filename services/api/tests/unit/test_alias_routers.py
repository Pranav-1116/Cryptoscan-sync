from api.routers import cloud_scans, network_scans
from api.routers.certificates import list_certificates


def test_alias_routers_exist():
    assert cloud_scans.router.prefix == "/cloud-scans"
    assert network_scans.router.prefix == "/network-scans"
    assert callable(list_certificates)
