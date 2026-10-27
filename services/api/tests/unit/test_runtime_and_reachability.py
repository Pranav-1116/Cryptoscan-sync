from api.routers.runtime import RuntimeFinding, RuntimeFindingsBody, _verdict_rows, to_evidence
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


def test_a_bare_crypto_call_is_judged_by_its_own_algorithm():
    """The LD_PRELOAD tracer (ADR-012) reports algorithms, not TLS suites."""
    body = RuntimeFindingsBody(scanner_id="ld-preload-agent-v1.0", findings=[
        RuntimeFinding(process_name="sample.elf", pid=7, algorithm="AES-128-CBC", key_size=16,
                       observation_count=4, extra={"kind": "binary-dynamic", "source": "ld-preload"}),
        RuntimeFinding(process_name="sample.elf", pid=7, algorithm="MD5",
                       extra={"kind": "binary-dynamic"}),
    ])
    rows = _verdict_rows(body)
    assert rows[0]["algorithm"] == "AES", "the registry judged the observed cipher, not a TLS default"
    assert rows[0]["status"] == "ALLOWED" and rows[0]["key_size"] == 16
    assert rows[0]["observation_count"] == 4
    assert rows[1]["status"] == "DISALLOWED" and rows[1]["weak_tls"] is True


def test_two_algorithms_from_one_process_are_two_rows():
    """Without the algorithm in the key they would collide and one would vanish."""
    from db.repositories.runtime_finding_repository import dedup_key_for

    first = {"scanner_id": "ld-preload-agent-v1.0", "hostname": None, "process_name": "sample.elf",
             "pid": 7, "tls_version": None, "cipher_suite": None, "algorithm": "AES-128-CBC",
             "extra": {"mode": "CBC"}}
    second = {**first, "algorithm": "MD5", "extra": {"mode": "CBC"}}
    third = {**first, "extra": {"mode": "GCM"}}
    assert dedup_key_for(first) != dedup_key_for(second)
    assert dedup_key_for(first) != dedup_key_for(third), "the mode is part of the identity too"


def test_a_real_tls_suite_still_resolves_to_its_bulk_cipher():
    body = RuntimeFindingsBody(findings=[RuntimeFinding(
        process_name="payment-api", tls_version="TLSv1.0",
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA", extra={})])
    row = _verdict_rows(body)[0]
    assert row["algorithm"] == "AES" and row["weak_tls"] is True
    assert row["status"] == "RESTRICTED"
