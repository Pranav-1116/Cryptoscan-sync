"""Gateway/load-balancer config invariants.

Configs drift silently — a YAML comment promises one thing and a month
later the file says another. These tests read the deployed gateway (Envoy)
and HA load balancer (nginx) configs and pin the promises the platform
depends on: TLS material is never embedded, every cluster is bounded,
retries cannot replay a verdict, and request identity survives the hop.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
ENVOY = ROOT / "deploy" / "stack" / "envoy" / "envoy.yaml"
NGINX_HA = ROOT / "deploy" / "ha" / "nginx.conf"


def _envoy() -> dict:
    return yaml.safe_load(ENVOY.read_text())


def _http_connection_managers(config: dict) -> list[dict]:
    managers = []
    for listener in config["static_resources"]["listeners"]:
        for chain in listener.get("filter_chains", []):
            for filt in chain.get("filters", []):
                typed = filt.get("typed_config", {})
                if "HttpConnectionManager" in str(typed.get("@type", "")):
                    managers.append(typed)
    return managers


class TestEnvoyGateway:

    def test_tls_material_is_named_never_embedded(self):
        text = ENVOY.read_text()
        assert "/run/secrets/" in text, "cert paths come from the secret mount"
        assert "PRIVATE KEY" not in text
        assert "BEGIN CERTIFICATE" not in text

    def test_every_cluster_is_bounded(self):
        for cluster in _envoy()["static_resources"]["clusters"]:
            assert cluster.get("connect_timeout"), \
                f"cluster {cluster['name']} has no connect timeout"
            thresholds = cluster.get("circuit_breakers", {}).get("thresholds", [])
            assert thresholds, \
                f"cluster {cluster['name']} has no circuit breakers — an " \
                "unbounded cluster is how one outage becomes the outage"
            budget = thresholds[0]
            for field in ("max_connections", "max_pending_requests", "max_requests"):
                assert budget.get(field), f"{cluster['name']}.{field} is unbounded"

    def test_api_retries_cannot_replay_a_verdict(self):
        routes = []
        for manager in _http_connection_managers(_envoy()):
            for vhost in manager.get("route_config", {}).get("virtual_hosts", []):
                routes.extend(vhost.get("routes", []))
        api = next(r for r in routes if r["match"].get("prefix") == "/api/")
        policy = api["route"]["retry_policy"]
        assert policy["retry_on"] == "connect-failure", (
            "retries run only when the request never reached the app; a "
            "response — even a 5xx — is the app's verdict to relay")
        assert policy["num_retries"] <= 3, "retries are bounded"
        assert policy.get("per_try_timeout"), "each try is time-bounded"
        assert api["route"].get("timeout"), "the route is time-bounded"

    def test_request_identity_survives_the_gateway(self):
        for manager in _http_connection_managers(_envoy()):
            if manager.get("stat_prefix") == "ingress":
                assert manager.get("generate_request_id") is True
                assert manager.get("preserve_external_request_id") is True

    def test_plain_http_only_redirects(self):
        for manager in _http_connection_managers(_envoy()):
            for vhost in manager.get("route_config", {}).get("virtual_hosts", []):
                for route in vhost.get("routes", []):
                    if "redirect" in route:
                        assert route["redirect"].get("https_redirect") is True

    def test_the_admin_interface_is_local_only(self):
        admin = _envoy()["admin"]["address"]["socket_address"]
        assert admin["address"] in ("127.0.0.1", "localhost")


class TestHaNginx:

    def test_api_upstreams_carry_passive_health_checks(self):
        text = NGINX_HA.read_text()
        assert "max_fails=" in text, (
            "an upstream without passive health checks keeps routing to a "
            "dead replica for the whole fail_timeout window")
        assert "fail_timeout=" in text
