"""Live Kubernetes plane + the ``cryptoscan`` CLI (spec 93 §13, §18).

Two "real system" properties are under test here:

* the Kubernetes collector talks to a cluster API and turns what it can read into
  estate evidence — every fact ``CONFIGURED`` (an Ingress TLS block is a
  declaration, not a handshake), secrets never read, and an RBAC 403 reported as
  ``PARTIAL`` instead of "there are no pods";
* the CLI runs the *same* job against the *same* database as the API, so an
  operator can actually run ``cryptoscan scan --scope production``.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from api import estate_discovery, estate_kubernetes
from db.connection.session import Base

API = "https://10.0.0.1:443"


def _cluster_payloads() -> dict[str, dict]:
    return {
        "/api/v1/namespaces": {"items": [
            {"metadata": {"name": "payments", "labels": {"team": "payments"}}},
            {"metadata": {"name": "kube-system"}},
        ]},
        "/api/v1/services": {"items": [
            {"metadata": {"name": "payments-api", "namespace": "payments"},
             "spec": {"type": "ClusterIP", "ports": [{"port": 8080, "targetPort": 8080, "protocol": "TCP"}]}},
            {"metadata": {"name": "payments-lb", "namespace": "payments",
                          "annotations": {"service.beta.kubernetes.io/aws-load-balancer-ssl-cert": "arn:cert"}},
             "spec": {"type": "LoadBalancer", "ports": [{"port": 443, "targetPort": 8080}]}},
        ]},
        "/api/v1/pods": {"items": [
            {"metadata": {"name": "payments-api-7d9f", "namespace": "payments"},
             "spec": {"containers": [
                 {"name": "api", "image": "registry.bank/payments-api:1.4.2"},
                 {"name": "istio-proxy", "image": "docker.io/istio/proxyv2:1.20"},
             ]}},
        ]},
        "/apis/networking.k8s.io/v1/ingresses": {"items": [
            {"metadata": {"name": "payments-ingress", "namespace": "payments",
                          "annotations": {"nginx.ingress.kubernetes.io/ssl-redirect": "true",
                                          "nginx.ingress.kubernetes.io/auth-tls-verify-client": "on"}},
             "spec": {
                 "tls": [{"hosts": ["payments.bank.example"], "secretName": "payments-tls"}],
                 "rules": [{"host": "payments.bank.example",
                            "http": {"paths": [{"path": "/", "backend": {"service": {"name": "payments-api"}}}]}}],
             }},
            {"metadata": {"name": "plain-ingress", "namespace": "payments"},
             "spec": {"rules": [{"host": "plain.bank.example",
                                 "http": {"paths": [{"path": "/", "backend": {"service": {"name": "payments-api"}}}]}}]}},
        ]},
    }


def _transport(payloads: dict[str, dict] | None = None, forbidden: set[str] | None = None, seen: list[str] | None = None):
    payloads = payloads if payloads is not None else _cluster_payloads()
    forbidden = forbidden or set()

    def transport(url: str, headers: dict, timeout: float) -> tuple[int, bytes]:
        if seen is not None:
            seen.append(url)
        path = url.split(API, 1)[-1]
        if path in forbidden:
            return 403, b'{"kind":"Status","reason":"Forbidden"}'
        if path not in payloads:
            return 404, b"{}"
        return 200, json.dumps(payloads[path]).encode("utf-8")

    return transport


def _config() -> dict:
    return {"api_url": API, "token": "test-token", "source": "INJECTED"}


# --------------------------------------------------------------------------- #
# live collector
# --------------------------------------------------------------------------- #
def test_collector_builds_assets_and_configured_evidence():
    result = estate_kubernetes.collect_kubernetes(None, transport=_transport(), config=_config())
    types = {asset["type"] for asset in result["assets"]}
    assert {"CLUSTER", "NAMESPACE", "POD", "CONTAINER", "IMAGE", "API_GATEWAY", "SERVICE"} <= types
    assert "LOAD_BALANCER" in types
    assert all(record["evidence_type"] == "CONFIGURED" for record in result["evidence"])
    ingress = next(record for record in result["evidence"]
                   if (record.get("facts") or {}).get("termination") == "TERMINATION_DECLARED")
    assert ingress["facts"]["tls_secret_ref"] == ["payments-tls"]
    assert ingress["facts"]["mtls_configured"] is True
    assert ingress["layer"] == "NETWORK_TRANSPORT"
    assert "CONFIGURED" in ingress["facts"]["claim"]


def test_collector_never_reads_secrets():
    seen: list[str] = []
    estate_kubernetes.collect_kubernetes(None, transport=_transport(seen=seen), config=_config())
    assert seen, "the collector must actually call the API"
    assert not [url for url in seen if "/secrets" in url], "secrets must never be requested"


def test_relationships_carry_a_basis_and_are_marked_configured():
    result = estate_kubernetes.collect_kubernetes(None, transport=_transport(), config=_config())
    predicates = {edge["predicate"] for edge in result["relationships"]}
    assert {"contains", "runs_on", "terminates_tls_for"} <= predicates
    for edge in result["relationships"]:
        assert edge["basis"] == "DEPLOYMENT_CONFIG"
        assert edge["evidence_ids"]
        assert edge["attributes"]["claim"] == "CONFIGURED"
        assert edge["attributes"]["observed"] is False


def test_ingress_without_a_tls_block_asserts_no_termination():
    result = estate_kubernetes.collect_kubernetes(None, transport=_transport(), config=_config())
    gateways = [asset for asset in result["assets"] if asset["type"] == "API_GATEWAY"]
    gateway_names = {asset["name"] for asset in gateways}
    assert {"payments/plain-ingress", "payments/payments-ingress"} <= gateway_names
    plain = next(asset for asset in gateways if asset["name"] == "payments/plain-ingress")
    edges = [edge for edge in result["relationships"]
             if edge["subject"] == plain["asset_id"] and edge["predicate"] == "terminates_tls_for"]
    assert edges == [], "an Ingress without a TLS block must not produce a termination claim"


def test_sidecar_crypto_is_labelled_platform_not_application():
    result = estate_kubernetes.collect_kubernetes(None, transport=_transport(), config=_config())
    sidecar = next(asset for asset in result["assets"]
                   if asset["type"] == "CONTAINER" and asset["attributes"].get("sidecar"))
    assert "istio" in sidecar["name"]
    record = next(item for item in result["evidence"] if item["target"] == sidecar["asset_id"])
    assert record["facts"]["sidecar"] is True
    assert "platform crypto" in record["facts"]["layer_note"]


def test_rbac_forbidden_is_partial_not_empty():
    result = estate_kubernetes.collect_kubernetes(
        None, transport=_transport(forbidden={"/api/v1/pods"}), config=_config())
    assert result["collected"] == 3 and result["expected"] == 4
    assert result["blocked"]
    assert any("NOT_OBSERVED, not empty" in note for note in result["limitations"])
    outcome = estate_discovery._collect("KUBERNETES", lambda _db, **_: result, None)
    assert outcome["status"] == "PARTIAL"
    assert "NOT_OBSERVED" in outcome["impact"]


def test_missing_credentials_is_not_attempted():
    with pytest.raises(estate_kubernetes.PlaneNotConfigured):
        estate_kubernetes.cluster_config({})

    def boom(_db, **_kwargs):
        raise estate_kubernetes.PlaneNotConfigured("no cluster credentials")

    report = estate_discovery.run(None, persist=False, collectors={"KUBERNETES": boom})
    kubernetes = next(item for item in report["collectors"] if item["plane"] == "KUBERNETES")
    assert kubernetes["status"] == "NOT_ATTEMPTED"
    assert "NOT_OBSERVED" in kubernetes["impact"]


def test_in_cluster_and_explicit_credentials_resolve(monkeypatch):
    monkeypatch.setattr(estate_kubernetes, "_read_file",
                        lambda path: "sa-token" if path and path.endswith("/token") else None)
    in_cluster = estate_kubernetes.cluster_config({"KUBERNETES_SERVICE_HOST": "10.0.0.1",
                                                   "KUBERNETES_SERVICE_PORT": "443"})
    assert in_cluster["source"] == "IN_CLUSTER_SERVICE_ACCOUNT"
    assert in_cluster["api_url"] == "https://10.0.0.1:443"

    explicit = estate_kubernetes.cluster_config({
        "KUBERNETES_API_URL": "https://api.cluster.internal",
        "KUBERNETES_TOKEN": "token",
        "KUBERNETES_CA_FILE": "/etc/ca.crt",
    })
    assert explicit["source"] == "ENVIRONMENT"
    assert explicit["ca_file"] == "/etc/ca.crt"


def test_json_kubeconfig_is_supported(tmp_path):
    kubeconfig = {
        "current-context": "bank",
        "contexts": [{"name": "bank", "context": {"cluster": "prod", "user": "ci"}}],
        "clusters": [{"name": "prod", "cluster": {"server": "https://k8s.bank.internal:6443"}}],
        "users": [{"name": "ci", "user": {"token": "kube-token"}}],
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(kubeconfig))
    config = estate_kubernetes.cluster_config({"KUBECONFIG": str(path)})
    assert config["api_url"] == "https://k8s.bank.internal:6443"
    assert config["token"] == "kube-token"
    assert config["source"] == "KUBECONFIG"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@pytest.fixture()
def cli_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()


def test_cli_scan_prints_the_coverage_matrix(cli_session, capsys):
    from api.cli import main

    code = main(["scan", "--scope", "production", "--estate", "bank-a"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code in {0, 2}
    assert "estate     bank-a (scope production)" in out
    assert "coverage" in out
    for plane in estate_discovery.PLANES:
        assert plane in out


def test_cli_json_carries_bom_counts_and_limitations(cli_session, capsys):
    from api.cli import main

    code = main(["scan", "--scope", "production", "--json", "--no-persist"],
                session_factory=lambda: cli_session)
    payload = json.loads(capsys.readouterr().out)
    assert code in {0, 2}
    assert payload["model"] == "cryptoscan.estate-discovery-job/1"
    assert set(payload["bom_counts"]) == {"SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"}
    assert payload["limitations"]


def test_cli_exits_two_when_a_plane_failed_unless_allowed(cli_session, capsys, monkeypatch):
    from api import cli

    def boom(_db, **_kwargs):
        raise RuntimeError("collector exploded")

    monkeypatch.setitem(estate_discovery.DEFAULT_COLLECTORS, "STATIC", boom)
    code = cli.main(["scan", "--no-persist"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_INCOMPLETE
    assert "STATIC" in out

    code = cli.main(["scan", "--no-persist", "--allow-partial"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code == cli.EXIT_OK
    assert "--allow-partial" in out


def test_cli_boms_reads_the_persisted_run_back(cli_session, capsys):
    from api.cli import main

    main(["scan", "--estate", "bank-b"], session_factory=lambda: cli_session)
    capsys.readouterr()
    code = main(["boms"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code == 0
    assert "projection" in out
    for kind in ("SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"):
        assert kind in out


def test_cli_coverage_without_a_stored_run_tells_the_operator_what_to_do(cli_session, capsys):
    from api.cli import main

    code = main(["coverage"], session_factory=lambda: cli_session)
    out = capsys.readouterr().out
    assert code == 2
    assert "cryptoscan scan --scope production" in out
