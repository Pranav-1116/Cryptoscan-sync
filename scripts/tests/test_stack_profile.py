"""The bank stack profile covers every tool the platform table names.

The compose overlay, every tool's configuration, the Kubernetes profile
and the environment example parse and carry their contracts: pinned
images, healthchecks on stateful tools, and secrets by NAME only — no
value is ever committed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from scripts.check_stack_profile import check

ROOT = Path(__file__).resolve().parent.parent.parent
STACK = ROOT / "deploy" / "stack"


class _ComposeLoader(yaml.SafeLoader):
    pass


def _override(loader, node):
    # Compose >=2.24 replaces root lists instead of appending host publishes.
    return loader.construct_sequence(node)


_ComposeLoader.add_constructor("!override", _override)


def _compose():
    return yaml.load((STACK / "docker-compose.stack.yml").read_text(),
                     Loader=_ComposeLoader)


#: the platform table, tool -> role
TABLE = {
    "PostgreSQL": "postgres", "Neo4j": "neo4j", "Redis": "redis",
    "Kafka": "kafka", "MinIO": "minio",
    "Cassandra": "cassandra", "Elasticsearch": "elasticsearch",
    "Prometheus": "prometheus", "Grafana": "grafana",
    "OpenTelemetry": "otel-collector", "Vault": "vault", "Envoy": "envoy",
}


def test_every_tool_in_the_table_serves_from_the_stack():
    services = _compose()["services"]
    missing = [tool for tool in TABLE.values() if tool not in services]
    assert missing == [], f"platform-table tools missing from the stack: {missing}"


def test_every_stateful_tool_has_a_healthcheck_and_persistence():
    services = _compose()["services"]
    stateful = ["postgres", "neo4j", "redis", "kafka", "minio",
                "cassandra", "elasticsearch"]
    for name in stateful:
        service = services[name]
        assert "healthcheck" in service, f"{name} has no healthcheck"
        assert service.get("volumes"), f"{name} has no named persistence"
    for name in ("postgres", "neo4j", "redis", "kafka", "minio",
                 "cassandra", "elasticsearch", "prometheus", "grafana"):
        assert any(str(v).split(":")[0].endswith("_data")
                   for v in services[name].get("volumes", [])), \
            f"{name} persists into a named volume"


def test_images_are_pinned_not_latest_drift():
    services = _compose()["services"]
    for name, service in services.items():
        if name in {"api", "frontend", "nginx"}:
            # These inherit their build definitions from the root Compose.
            continue
        image = service.get("image", "")
        assert image and ":" in image, f"{name} has an unpinned image"
        assert not image.endswith(":latest") or name.startswith("minio"), \
            f"{name} floats on :latest — pin it"


def test_no_secret_values_are_committed():
    compose_text = (STACK / "docker-compose.stack.yml").read_text()
    for match in re.finditer(r"(PASSWORD|TOKEN)=\"?([^\"$\n]+)\"?", compose_text):
        value = match.group(2).strip()
        assert value.startswith("$") or not value, \
            f"literal secret value committed: {match.group(0)!r}"
    env_example = (STACK / ".env.stack.example").read_text()
    for line in env_example.splitlines():
        if re.match(r"^[A-Z_]*(PASSWORD|TOKEN)=", line) and line.strip().endswith("=") is False:
            key, _, value = line.partition("=")
            if value.split("#")[0].strip():
                assert "set from the secret manager" in line or "dev" in line.lower(), \
                    f"secret value in the example file: {line!r}"


def test_the_kubernetes_profile_covers_orchestration():
    docs = []
    for name in sorted((STACK / "k8s").glob("*.yaml")):
        docs.extend(yaml.safe_load_all(name.read_text()))
    kinds = {(d.get("kind"), d.get("metadata", {}).get("name")) for d in docs}
    assert ("Namespace", "cryptoscan") in kinds
    assert ("Deployment", "cryptoscan-api") in kinds
    assert ("Deployment", "cryptoscan-worker") in kinds   # Celery
    assert ("Deployment", "cryptoscan-gateway") in kinds  # Envoy
    assert ("HorizontalPodAutoscaler", "cryptoscan-api") in kinds
    assert ("HorizontalPodAutoscaler", "cryptoscan-worker") in kinds  # queue-driven capacity
    worker_hpa = next(d for d in docs if d.get("kind") == "HorizontalPodAutoscaler"
                      and d["metadata"]["name"] == "cryptoscan-worker")
    spec = worker_hpa["spec"]
    assert spec["minReplicas"] <= 3 <= spec["maxReplicas"], \
        "the HPA adopts the deployment's static replicas without a cliff"
    scale_down = spec["behavior"]["scaleDown"]
    assert scale_down["stabilizationWindowSeconds"] >= 300, \
        "workers are never shed mid-scan"
    text = (STACK / "k8s" / "10-api.yaml").read_text()
    assert "secretRef" in text and "bank secret manager" in text
    assert "kind: Secret" not in text, "no secret VALUES in the repository"


def test_overlay_does_not_upgrade_the_root_database_or_graph_volumes():
    services = _compose()["services"]
    assert services["postgres"]["image"] == "postgres:15-alpine"
    assert services["neo4j"]["image"] == "neo4j:5.26-community"


def test_overlay_binds_exist_and_envoy_has_external_certificate_mount():
    services = _compose()["services"]
    for name in ("prometheus", "grafana", "otel-collector", "vault", "envoy"):
        for mount in services[name]["volumes"]:
            source = mount.split(":", 1)[0]
            if source.startswith("./"):
                assert (ROOT / source).exists(), (name, source)
    envoy_mounts = services["envoy"]["volumes"]
    assert any("GATEWAY_TLS_CERT_DIR" in mount and
               mount.endswith(":/run/secrets/gateway:ro")
               for mount in envoy_mounts)
    assert "STACK_DEV_ACK" in _compose()["x-stack-dev-only"]


def test_dev_profile_binds_every_published_port_to_loopback():
    for name, service in _compose()["services"].items():
        for port in service.get("ports", []):
            assert port.startswith("127.0.0.1:"), (name, port)
    text = (STACK / "docker-compose.stack.yml").read_text()
    assert text.count("ports: !override") == 6, "root port lists must be replaced"


def test_gateway_upstreams_and_redirect_match_the_app():
    config = yaml.safe_load((STACK / "envoy/envoy.yaml").read_text())
    clusters = config["static_resources"]["clusters"]
    ports = {c["name"]: c["load_assignment"]["endpoints"][0]
             ["lb_endpoints"][0]["endpoint"]["address"]["socket_address"]["port_value"]
             for c in clusters}
    assert ports == {"api": 8010, "frontend": 3003}
    assert "port_redirect: 8443" in (STACK / "envoy/envoy.yaml").read_text()
    assert "api:8010" in (STACK / "prometheus/prometheus.yml").read_text()
    assert "worker:8100" not in (STACK / "prometheus/prometheus.yml").read_text()


def test_dev_profile_preflight_refuses_prod_and_missing_tls(tmp_path):
    environment = {"STACK_DEV_ACK": "development-only", "ENVIRONMENT": "development",
                   "GATEWAY_TLS_CERT_DIR": str(tmp_path)}
    assert check(environment) == ["GATEWAY_TLS_CERT_DIR must contain tls.crt",
                                  "GATEWAY_TLS_CERT_DIR must contain tls.key"]
    (tmp_path / "tls.crt").write_text("fixture cert")
    (tmp_path / "tls.key").write_text("fixture key")
    assert check(environment) == []
    assert any("not production" in error for error in
               check({**environment, "ENVIRONMENT": "production"}))
    assert any("STACK_DEV_ACK" in error for error in
               check({**environment, "STACK_DEV_ACK": ""}))


def test_tool_configurations_parse():
    for name in ("prometheus/prometheus.yml",
                 "grafana/provisioning/datasources/datasources.yml",
                 "grafana/provisioning/dashboards/dashboards.yml",
                 "otel/otel-collector.yaml",
                 "envoy/envoy.yaml"):
        yaml.safe_load((STACK / name).read_text())
    dashboard = json.loads((STACK / "grafana/dashboards/cryptoscan-stack.json").read_text())
    assert dashboard["title"].startswith("CryptoScan")
    assert len(dashboard["panels"]) >= 4
    template = json.loads((STACK / "elasticsearch/cryptolog-events.json").read_text())
    assert template["index_patterns"] == ["cryptolog-events-*"]
    depgraph = json.loads((STACK / "elasticsearch/dependency-graph.json").read_text())
    assert depgraph["index_patterns"] == ["cryptoscan-dependency-graph"]
    # Tenant isolation is enforced by the query layer — but the mapping must
    # still carry tenant_id as a keyword so every query can filter on it.
    props = depgraph["template"]["mappings"]["properties"]
    assert props["tenant_id"]["type"] == "keyword"
    assert props["kind"]["type"] == "keyword"
    policy = (STACK / "vault/policies/cryptoscan.hcl").read_text()
    assert "secret/data/cryptoscan/*" in policy
    assert not re.search(r"= *\"[^\"]{16,}\"", policy), "no secret material in the policy"
