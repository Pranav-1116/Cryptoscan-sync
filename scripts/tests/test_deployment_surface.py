"""The deployment surface the product actually ships, checked as code.

Three failures this file exists to prevent, each of which was real:

1. The reference Kubernetes manifests could not boot in production. The API
   refuses to start without an explicit ``TRUSTED_HOSTS``/``CORS_ORIGINS`` and
   a realtime ``REDIS_URL``; the ConfigMap declared none of the first two, so
   ``kubectl apply`` produced CrashLoopBackOff with a gate message that looked
   like the operator's fault.
2. ``uvicorn --proxy-headers --forwarded-allow-ips "*"`` let *any* peer rewrite
   the client address. The API resolves the client IP once, against
   ``TRUSTED_PROXY_COUNT``/``TRUSTED_PROXY_CIDRS`` (api/security/client_ip.py);
   the uvicorn flags silently substituted the client's claim for the socket
   peer that check reads, so an API-key IP allowlist or a login rate limit was
   satisfied by sending a header.
3. A two-replica Deployment had no PodDisruptionBudget and no NetworkPolicy:
   one node drain took the API down, and any pod in the cluster could reach the
   API directly instead of through the TLS-terminating ingress.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
K8S = ROOT / "k8s" / "app"


def load(name: str) -> dict:
    return yaml.safe_load((K8S / name).read_text(encoding="utf-8"))


def all_docs() -> list[dict]:
    docs = []
    for path in sorted(K8S.glob("*.yaml")):
        docs.extend(doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc)
    return docs


def by_kind(kind: str, name: str | None = None) -> list[dict]:
    return [
        doc for doc in all_docs()
        if doc.get("kind") == kind and (name is None or doc["metadata"]["name"] == name)
    ]


# --------------------------------------------------------------------- configmap


def test_the_shipped_configmap_satisfies_the_production_gate():
    """Assemble the manifest's ConfigMap + a plausible Secret and boot the gate.

    This is the check that would have caught the unbootable reference
    deployment: the gate is the same function the app calls at startup.
    """
    sys.path.insert(0, str(ROOT / "services" / "api"))
    sys.path.insert(0, str(ROOT / "services" / "database"))
    from api.config.settings import APISettings, validate_runtime_settings

    config = {k: str(v) for k, v in load("10-configmap.yaml")["data"].items()}
    # Secrets come from 15-secret.example.yaml; values are irrelevant to the
    # gate as long as they are strong, which is what the example demands.
    secrets = {
        "SECRET_KEY": "s" * 40,
        "ADMIN_PASSWORD_HASH": "pbkdf2_sha256$600000$c2FsdA==$aGFzaA==",
        "GITHUB_WEBHOOK_SECRET": "g" * 32,
        "METRICS_TOKEN": "m" * 32,
        "ALERTMANAGER_WEBHOOK_TOKEN": "a" * 32,
        "DATABASE_URL": "postgresql+psycopg2://cryptoscan:pw@postgres:5432/cryptoscan",
        "REDIS_URL": "rediss://cryptoscan:pw@redis:6379/0",
        "REGISTRY_WEBHOOK_SECRET": "w" * 32,
        "CBOM_SIGNING_SECRET": "c" * 32,
        "STREAM_SECRET": "t" * 32,
        "AUDITOR_API_KEY": "k" * 32,
    }
    settings = APISettings.model_construct(**{**config, **secrets})
    validate_runtime_settings(settings)


def test_the_configmap_declares_the_proxy_boundary():
    data = load("10-configmap.yaml")["data"]
    assert int(data["TRUSTED_PROXY_COUNT"]) >= 1
    assert data["TRUSTED_PROXY_CIDRS"].strip(), "a hop count with no proxy network trusts any peer"
    assert data["TRUSTED_HOSTS"] != '["*"]'
    assert data["CORS_ORIGINS"] != "*"


# ------------------------------------------------------------------- deployments


def test_no_workload_declares_a_mutable_image_in_the_template():
    for doc in by_kind("Deployment") + by_kind("StatefulSet"):
        containers = doc["spec"]["template"]["spec"].get("containers", [])
        for container in containers:
            image = container["image"]
            assert not image.endswith(":latest"), f"{doc['metadata']['name']} pins :latest"


def test_workloads_cannot_reach_the_api_server_and_have_a_read_only_root():
    for doc in by_kind("Deployment"):
        pod = doc["spec"]["template"]["spec"]
        assert pod.get("automountServiceAccountToken") is False, doc["metadata"]["name"]
        for container in pod["containers"]:
            assert container["securityContext"].get("readOnlyRootFilesystem") is True, (
                f"{doc['metadata']['name']}/{container['name']} writes to the image layer"
            )
            assert container["securityContext"]["allowPrivilegeEscalation"] is False
            assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_the_api_rollout_never_drops_below_the_replica_count():
    spec = load("20-api-deployment.yaml")["spec"]
    rolling = spec["strategy"]["rollingUpdate"]
    assert rolling["maxUnavailable"] == 0
    assert int(rolling["maxSurge"]) >= 1


def test_a_pod_disruption_budget_protects_the_api():
    budgets = {doc["metadata"]["name"]: doc for doc in by_kind("PodDisruptionBudget")}
    assert budgets, "no PodDisruptionBudget: a node drain takes the whole API down"
    api = budgets["cryptoscan-api"]
    assert int(api["spec"]["minAvailable"]) >= 1
    assert api["spec"]["selector"]["matchLabels"] == {"app": "cryptoscan-api"}


def test_the_api_is_not_reachable_from_every_pod_in_the_cluster():
    policies = by_kind("NetworkPolicy")
    assert policies, "no NetworkPolicy: any pod may talk to the API directly"
    api = next(doc for doc in policies if doc["metadata"]["name"] == "cryptoscan-api-ingress")
    assert "Ingress" in api["spec"]["policyTypes"]
    for rule in api["spec"]["ingress"]:
        assert rule["from"], "a rule with no source allows every peer"


# ------------------------------------------------------------------------ ingress


def test_tls_is_terminated_with_a_redirect_and_hsts():
    ingress = load("40-ingress.yaml")
    annotations = ingress["metadata"]["annotations"]
    assert annotations["nginx.ingress.kubernetes.io/ssl-redirect"] == "true"
    assert annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"] == "true"
    assert annotations["nginx.ingress.kubernetes.io/hsts"] == "true"
    protocols = annotations["nginx.ingress.kubernetes.io/ssl-protocols"]
    assert "TLSv1.0" not in protocols and "TLSv1.1" not in protocols
    assert ingress["spec"]["tls"], "an ingress without a TLS block serves plaintext"
    assert ingress["spec"]["tls"][0]["secretName"]
    assert ingress["spec"]["rules"][0]["http"]["paths"][0]["pathType"] == "Prefix"


# ------------------------------------------------------- the client-IP authority


FORBIDDEN_FLAGS = ("--proxy-headers", "--forwarded-allow-ips")


def test_no_launch_path_lets_a_peer_rewrite_the_client_ip():
    """api.security.client_ip is the single authority for the client address.

    uvicorn's --proxy-headers would rewrite ``scope["client"]`` from
    X-Forwarded-For for any peer, which defeats TRUSTED_PROXY_CIDRS: the CIDR
    check would then be inspecting a client-supplied string. Nothing that
    starts the API may pass those flags.
    """
    offenders: list[str] = []
    roots = [
        ROOT / "docker-compose.yml",
        ROOT / "docker-compose.prod.yml",
        ROOT / ".docker",
        ROOT / "deploy",
        ROOT / "k8s",
        ROOT / "scripts",
    ]
    for root in roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for path in files:
            try:
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, IsADirectoryError):
                continue
            for flag in FORBIDDEN_FLAGS:
                if re.search(rf"{re.escape(flag)}\s*[\"']?\s*(\*|0\.0\.0\.0/0)\b", text) or (
                    flag in text and "TRUSTED_PROXY" not in text and path.suffix != ".py"
                    and not _is_comment_only(path, flag)
                ):
                    offenders.append(f"{path.relative_to(ROOT)}: {flag}")
    assert not offenders, "uvicorn may not rewrite the client address: " + ", ".join(offenders)


def _is_comment_only(path: Path, flag: str) -> bool:
    """A line that only *mentions* the flag (in a comment) is documentation."""
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if flag in line and not stripped.startswith(("#", "//", "--")):
            if not stripped.startswith("#"):
                return False
    return True

# ------------------------------------------------------- operator site template


OPS_PROFILE = ROOT / "deploy" / "operator-profile" / "site.example.yaml"


def ops_docs() -> list[dict]:
    return [d for d in yaml.safe_load_all(OPS_PROFILE.read_text(encoding="utf-8")) if d]


def ops(kind: str) -> list[dict]:
    return [d for d in ops_docs() if d.get("kind") == kind]


def test_the_operator_site_template_parses_and_pins_images_by_digest():
    docs = ops_docs()
    assert docs, "the operator site template is empty"
    deployments = ops("Deployment")
    assert {d["metadata"]["name"] for d in deployments} >= {
        "cryptoscan-api", "cryptoscan-worker", "cryptoscan-frontend"
    }
    for deployment in deployments:
        for container in deployment["spec"]["template"]["spec"]["containers"]:
            assert "@sha256:" in container["image"], container["image"]


def test_the_operator_site_template_runs_ha_for_the_serving_tiers():
    for name in ("cryptoscan-api", "cryptoscan-frontend"):
        deployment = next(d for d in ops("Deployment") if d["metadata"]["name"] == name)
        assert deployment["spec"]["replicas"] >= 2, f"{name} has a single replica"
        rolling = deployment["spec"]["strategy"]["rollingUpdate"]
        assert rolling["maxUnavailable"] == 0
        budgets = {d["metadata"]["name"] for d in ops("PodDisruptionBudget")}
        assert name in budgets, f"{name} has no PodDisruptionBudget"


def test_the_operator_site_template_denies_service_account_tokens():
    for deployment in ops("Deployment"):
        pod = deployment["spec"]["template"]["spec"]
        assert pod.get("automountServiceAccountToken") is False, deployment["metadata"]["name"]


def test_the_operator_site_template_describes_the_proxy_boundary():
    configmap = next(d for d in ops("ConfigMap") if d["metadata"]["name"] == "cryptoscan-profile")
    data = configmap["data"]
    assert int(data["TRUSTED_PROXY_COUNT"]) >= 1
    assert data["TRUSTED_PROXY_CIDRS"].strip()
    # The single-organisation default must be the read-only role.
    assert data["ONPREM_SINGLE_ORG"] == "true"
    assert data["ONPREM_AUTO_MEMBERSHIP_ROLE"] == "viewer"


def test_the_operator_site_template_restricts_console_access():
    policies = {d["metadata"]["name"]: d for d in ops("NetworkPolicy")}
    assert "cryptoscan-frontend-ingress" in policies
    rule_sources = [rule["from"] for rule in policies["cryptoscan-frontend-ingress"]["spec"]["ingress"]]
    assert all(sources for sources in rule_sources), "a rule with no source allows every peer"


def test_the_operator_site_template_terminates_tls_with_a_redirect_and_hsts():
    ingress = ops("Ingress")[0]
    annotations = ingress["metadata"]["annotations"]
    assert annotations["nginx.ingress.kubernetes.io/force-ssl-redirect"] == "true"
    assert annotations["nginx.ingress.kubernetes.io/hsts"] == "true"
    assert ingress["spec"]["tls"]
