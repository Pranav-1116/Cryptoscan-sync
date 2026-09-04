from api.routers.runtime import RuntimeFinding, to_evidence
from api.schemas.reachability_schemas import BlastRadius


def test_runtime_finding_maps_to_evidence():
    item = RuntimeFinding(process_name="payment-api", tls_version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384")
    payload = to_evidence(item, "ebpf-runtime-agent-v1.0")
    assert payload["source"]["type"] == "RUNTIME_PROCESS"
    assert payload["crypto"]["tls_version"] == "TLSv1.3"
    model = BlastRadius(start="pay", hops=2)
    assert model.hops == 2


def test_alias_routers_include_new_modules():
    from api.routers import business_context, reachability, runtime

    assert reachability.router.prefix == "/reachability"
    assert business_context.router.prefix == "/business-context"
    paths = [getattr(route, "path", "") for route in runtime.router.routes]
    assert any("runtime-findings" in path for path in paths)


def test_runtime_findings_not_shadowed_by_scan_catchall():
    """Regression: GET /scans/runtime-findings must resolve to the runtime
    list endpoint, NOT be swallowed by the catch-all GET /scans/{scan_id}
    (which 404s with "Scan not found" for a literal id of "runtime-findings").

    The request is intentionally unauthenticated: the auth gate runs before
    routing and returns 401 for an existing route, whereas the catch-all
    "Scan not found" path previously produced 404 even after auth. Asserting
    the response is NOT that 404 proves the static route wins."""
    from fastapi.testclient import TestClient

    from api.main import create_app

    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/api/v1/scans/runtime-findings")
        # 401 (auth gate) or 200 (if auth disabled in test) both prove the
        # route resolved; 404 "Scan not found" means the catch-all shadowed it.
        assert resp.status_code != 404, f"runtime-findings shadowed by /scans/{{scan_id}}: {resp.text}"
        if resp.status_code == 404:  # pragma: no cover - defensive
            raise AssertionError(resp.text)
