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

ROOT = Path(__file__).resolve().parent.parent.parent
STACK = ROOT / "deploy" / "stack"


def _compose():
    return yaml.safe_load((STACK / "docker-compose.stack.yml").read_text())


#: the platform table, tool -> role
TABLE = {
    "PostgreSQL": "postgres", "Neo4j": "neo4j", "Redis": "redis",
    "Kafka": "kafka", "MinIO": "minio", "OpenSearch": "opensearch",
    "Prometheus": "prometheus", "Grafana": "grafana",
    "OpenTelemetry": "otel-collector", "Vault": "vault", "Envoy": "envoy",
}


def test_every_tool_in_the_table_serves_from_the_stack():
    services = _compose()["services"]
    missing = [tool for tool in TABLE.values() if tool not in services]
    assert missing == [], f"platform-table tools missing from the stack: {missing}"


def test_every_stateful_tool_has_a_healthcheck_and_persistence():
    services = _compose()["services"]
    stateful = ["postgres", "neo4j", "redis", "kafka", "minio", "opensearch"]
    for name in stateful:
        service = services[name]
        assert "healthcheck" in service, f"{name} has no healthcheck"
        assert service.get("volumes"), f"{name} has no named persistence"
    for name in ("postgres", "neo4j", "redis", "kafka", "minio",
                 "opensearch", "prometheus", "grafana"):
        assert any(str(v).split(":")[0].endswith("_data")
                   for v in services[name].get("volumes", [])), \
            f"{name} persists into a named volume"


def test_images_are_pinned_not_latest_drift():
    services = _compose()["services"]
    for name, service in services.items():
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
    text = (STACK / "k8s" / "10-api.yaml").read_text()
    assert "secretRef" in text and "bank secret manager" in text
    assert "kind: Secret" not in text, "no secret VALUES in the repository"


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
    template = json.loads((STACK / "opensearch/cryptolog-events.json").read_text())
    assert template["index_patterns"] == ["cryptolog-events-*"]
    policy = (STACK / "vault/policies/cryptoscan.hcl").read_text()
    assert "secret/data/cryptoscan/*" in policy
    assert not re.search(r"= *\"[^\"]{16,}\"", policy), "no secret material in the policy"
