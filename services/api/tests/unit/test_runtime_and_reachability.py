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
