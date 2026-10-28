"""Live Kubernetes discovery plane (spec 67 §17, §20; spec 93 §13).

Until now Kubernetes correlation accepted manifests the caller supplied, and the
spec called that out as open. This module is the real read-only collector: it
talks to the cluster's API server with the service account this process already
has, enumerates namespaces, ingresses, services and pods, and turns the *TLS
configuration* it can see into estate evidence.

What it reads (and what it refuses to read)
-------------------------------------------
Reads: ``namespaces``, ``networking.k8s.io/v1 ingresses``, ``v1 services``,
``v1 pods``. Never ``secrets`` — a TLS secret reference is recorded as a
*reference* (``tls_secret_ref``), because reading key material is out of scope by
policy and the pods' crypto cannot be inferred from a secret's contents anyway.

Every crypto fact this collector produces is ``CONFIGURED``, never observed:
an Ingress with a TLS block is *configured* to terminate TLS; whether it does, at
which version, with which cipher, is a network observation (`/network/crypto-probe`)
and stays a separate layer. Sidecars are labelled as platform crypto, not
application crypto.

RBAC honesty: a forbidden list call (403) does not fail the whole plane. The
plane reports ``PARTIAL`` and names the blocked resource, so "we have no
permission to list pods" can never be read as "there are no pods".

Credentials (first match wins):

* in-cluster service account: ``KUBERNETES_SERVICE_HOST``/``PORT`` plus
  ``/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt}``;
* explicit: ``KUBERNETES_API_URL`` + ``KUBERNETES_TOKEN`` (or ``KUBERNETES_TOKEN_FILE``)
  + ``KUBERNETES_CA_FILE`` (or ``KUBERNETES_INSECURE=true`` for lab clusters only);
* kubeconfig: ``KUBECONFIG`` (token / tokenFile based; client-certificate auth is
  reported as unsupported rather than silently unauthenticated).

If none is available the plane raises :class:`PlaneNotConfigured`, and the estate
job reports it ``NOT_ATTEMPTED`` — a cluster we could not ask about is
``NOT_OBSERVED``, not empty.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping

from api.estate_planes import PlaneNotConfigured
from shared_models.estate_graph import make_evidence, normalize_asset

SCHEMA = "cryptoscan.estate-kubernetes/1"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

#: Containers that are platform plumbing, not the application's own crypto.
SIDECAR_MARKERS = ("istio-proxy", "istio/proxyv2", "proxyv2", "envoy", "linkerd-proxy", "linkerd2-proxy",
                   "consul-dataplane", "nginx-gateway", "airlock-microgateway")

#: Ingress annotations that change what TLS actually means on that route.
TLS_ANNOTATIONS = (
    "nginx.ingress.kubernetes.io/ssl-redirect",
    "nginx.ingress.kubernetes.io/ssl-passthrough",
    "nginx.ingress.kubernetes.io/backend-protocol",
    "nginx.ingress.kubernetes.io/auth-tls-secret",
    "nginx.ingress.kubernetes.io/auth-tls-verify-client",
    "nginx.ingress.kubernetes.io/auth-tls-verify-depth",
    "nginx.ingress.kubernetes.io/ssl-ciphers",
    "nginx.ingress.kubernetes.io/ssl-protocols",
    "traefik.ingress.kubernetes.io/router.tls",
    "alb.ingress.kubernetes.io/listen-ports",
    "alb.ingress.kubernetes.io/ssl-policy",
)

Transport = Callable[[str, Mapping[str, str], float], tuple[int, bytes]]


class KubernetesReadError(RuntimeError):
    """The API answered, but not with data we can use."""


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def _read_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return None


def _from_kubeconfig(path: str) -> dict[str, Any] | None:
    raw = _read_file(path)
    if not raw:
        return None
    try:
        document = json.loads(raw)
    except ValueError:
        return None  # YAML kubeconfigs are reported, not silently mis-parsed
    clusters = {item.get("name"): item.get("cluster") or {} for item in document.get("clusters") or []}
    users = {item.get("name"): item.get("user") or {} for item in document.get("users") or []}
    context = next(
        (item for item in document.get("contexts") or []
         if item.get("name") == (document.get("current-context") or "")),
        None,
    )
    if context is None and document.get("contexts"):
        context = document["contexts"][0]
    if context is None:
        return None
    context_body = context.get("context") or {}
    cluster = clusters.get(context_body.get("cluster")) or {}
    user = users.get(context_body.get("user")) or {}
    server = cluster.get("server")
    token = user.get("token") or _read_file(user.get("tokenFile"))
    if not server or not token:
        return None
    config: dict[str, Any] = {"api_url": str(server).rstrip("/"), "token": token, "source": "KUBECONFIG"}
    if cluster.get("certificate-authority-data"):
        try:
            config["ca_pem"] = base64.b64decode(cluster["certificate-authority-data"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            config["insecure"] = False
    elif cluster.get("certificate-authority"):
        config["ca_file"] = str(cluster["certificate-authority"])
    if cluster.get("insecure-skip-tls-verify"):
        config["insecure"] = True
    return config


def cluster_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve cluster credentials, or raise :class:`PlaneNotConfigured`."""
    env = dict(os.environ if environ is None else environ)

    api_url = (env.get("KUBERNETES_API_URL") or "").strip().rstrip("/")
    token = (env.get("KUBERNETES_TOKEN") or "").strip() or (_read_file(env.get("KUBERNETES_TOKEN_FILE")) or "")
    if api_url and token:
        return {
            "api_url": api_url,
            "token": token,
            "ca_file": env.get("KUBERNETES_CA_FILE") or None,
            "insecure": str(env.get("KUBERNETES_INSECURE", "")).lower() in {"1", "true", "yes"},
            "source": "ENVIRONMENT",
        }

    host = (env.get("KUBERNETES_SERVICE_HOST") or "").strip()
    if host:
        port = (env.get("KUBERNETES_SERVICE_PORT") or "443").strip()
        service_token = _read_file(f"{SA_DIR}/token")
        if service_token:
            return {
                "api_url": f"https://{host}:{port}",
                "token": service_token,
                "ca_file": f"{SA_DIR}/ca.crt",
                "insecure": False,
                "source": "IN_CLUSTER_SERVICE_ACCOUNT",
            }

    kubeconfig = _from_kubeconfig(env.get("KUBECONFIG") or "")
    if kubeconfig:
        return kubeconfig

    raise PlaneNotConfigured(
        "no Kubernetes API is reachable from this process: set KUBERNETES_API_URL + KUBERNETES_TOKEN, run "
        "inside a cluster with a service account, or point KUBECONFIG at a JSON kubeconfig with a token"
    )


def _ssl_context(config: Mapping[str, Any]) -> ssl.SSLContext:
    if config.get("insecure"):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    ca_pem = config.get("ca_pem")
    if ca_pem:
        context = ssl.create_default_context(cadata=ca_pem)
        return context
    return ssl.create_default_context(cafile=config.get("ca_file") or None)


def _default_transport(config: Mapping[str, Any], timeout: float = 10.0) -> Transport:
    context = _ssl_context(config)

    def transport(url: str, headers: Mapping[str, str], request_timeout: float) -> tuple[int, bytes]:
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=request_timeout, context=context) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as exc:  # 403/404 are answers, not crashes
            return int(exc.code), exc.read() or b""

    return transport


# --------------------------------------------------------------------------- #
# collection
# --------------------------------------------------------------------------- #
LIST_PATHS = {
    "namespaces": "/api/v1/namespaces",
    "services": "/api/v1/services",
    "pods": "/api/v1/pods",
    "ingresses": "/apis/networking.k8s.io/v1/ingresses",
}


def _fetch(config: Mapping[str, Any], path: str, transport: Transport, timeout: float) -> dict[str, Any]:
    url = f"{config['api_url']}{path}"
    status, body = transport(url, {"Authorization": f"Bearer {config['token']}",
                                   "Accept": "application/json"}, timeout)
    if status == 403:
        raise PermissionError(f"RBAC forbids GET {path} (403)")
    if status == 404:
        return {"items": [], "absent": True}
    if status >= 400:
        raise KubernetesReadError(f"GET {path} returned HTTP {status}")
    try:
        return json.loads(body or b"{}")
    except ValueError as exc:
        raise KubernetesReadError(f"GET {path} returned a non-JSON body") from exc


def _is_sidecar(container_name: str, image: str) -> bool:
    """A sidecar is recognised by its container name *or* its image reference."""
    haystack = f"{container_name or ''} {image or ''}".lower()
    return any(marker in haystack for marker in SIDECAR_MARKERS)


def collect_kubernetes(
    _db: Any = None,
    *,
    transport: Transport | None = None,
    config: Mapping[str, Any] | None = None,
    timeout: float = 10.0,
    max_pods: int = 5000,
) -> dict[str, Any]:
    """Enumerate the cluster's TLS configuration into estate assets and evidence."""
    resolved = dict(config) if config else cluster_config()
    resolved.setdefault("source", "INJECTED")
    fetcher = transport or _default_transport(resolved)

    limitations: list[str] = []
    blocked: list[str] = []
    objects: dict[str, list[dict[str, Any]]] = {}
    collected = 0
    for name, path in LIST_PATHS.items():
        try:
            payload = _fetch(resolved, path, fetcher, timeout)
        except PermissionError as exc:
            blocked.append(str(exc))
            objects[name] = []
            limitations.append(f"{name}: {exc} — this resource is NOT_OBSERVED, not empty")
            continue
        except (KubernetesReadError, OSError) as exc:
            blocked.append(f"{name}: {exc}")
            objects[name] = []
            limitations.append(f"{name}: {exc}")
            continue
        collected += 1
        objects[name] = list(payload.get("items") or [])

    api_host = str(resolved.get("api_url") or "").split("://")[-1].split(":")[0] or "cluster"
    cluster_asset = normalize_asset("CLUSTER", api_host, identity={"cluster": api_host},
                                    source="kubernetes", attributes={"api_url": resolved.get("api_url"),
                                                                     "credential_source": resolved.get("source")})
    assets: list[dict[str, Any]] = [cluster_asset]
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    seen: set[str] = {cluster_asset["asset_id"]}

    def add_asset(kind: str, name: str, identity: Mapping[str, Any], attributes: Mapping[str, Any] | None = None) -> str:
        asset = normalize_asset(kind, name, identity=dict(identity), source="kubernetes",
                                attributes=dict(attributes or {}))
        if asset["asset_id"] not in seen:
            seen.add(asset["asset_id"])
            assets.append(asset)
        return asset["asset_id"]

    namespaces: list[str] = []
    for namespace in objects.get("namespaces") or []:
        name = str((namespace.get("metadata") or {}).get("name") or "")
        if not name:
            continue
        namespaces.append(name)
        namespace_id = add_asset("NAMESPACE", name, {"namespace": name})
        evidence.append(make_evidence(
            source="kubernetes", evidence_type="CONFIGURED", target=namespace_id, layer="PLATFORM",
            collector="kubernetes:namespaces",
            facts={"namespace": name, "labels": len((namespace.get("metadata") or {}).get("labels") or {})},
        ))

    services: dict[tuple[str, str], str] = {}
    for service in objects.get("services") or []:
        metadata = service.get("metadata") or {}
        name = str(metadata.get("name") or "")
        namespace = str(metadata.get("namespace") or "")
        if not name:
            continue
        spec = service.get("spec") or {}
        service_type = str(spec.get("type") or "ClusterIP")
        kind = "LOAD_BALANCER" if service_type in {"LoadBalancer", "NodePort"} else "SERVICE"
        service_id = add_asset(kind, f"{namespace}/{name}", {"namespace": namespace, "name": name},
                               {"service_type": service_type})
        services[(namespace, name)] = service_id
        concept = {
            "service_type": service_type,
            "ports": [{"port": port.get("port"), "target_port": port.get("targetPort"),
                       "protocol": port.get("protocol")} for port in spec.get("ports") or []],
            "load_balancer_class": spec.get("loadBalancerClass"),
            "external_traffic_policy": spec.get("externalTrafficPolicy"),
        }
        evidence.append(make_evidence(
            source="kubernetes", evidence_type="CONFIGURED", target=service_id, layer="NETWORK_TRANSPORT",
            collector="kubernetes:services", facts=concept,
        ))
        if service_type in {"LoadBalancer", "NodePort"}:
            annotations = {k: v for k, v in (metadata.get("annotations") or {}).items()
                           if "ssl" in k.lower() or "tls" in k.lower() or "listen" in k.lower()}
            if annotations:
                evidence.append(make_evidence(
                    source="kubernetes", evidence_type="CONFIGURED", target=service_id,
                    layer="NETWORK_TRANSPORT", collector="kubernetes:services",
                    facts={"tls_annotations": annotations,
                           "claim": "CONFIGURED — an annotation is a declaration, not an observed handshake"},
                ))

    pods = (objects.get("pods") or [])[:max_pods]
    if len(objects.get("pods") or []) > max_pods:
        limitations.append(
            f"pods: read the first {max_pods} of {len(objects.get('pods') or [])} — the rest are NOT_OBSERVED")
    for pod in pods:
        metadata = pod.get("metadata") or {}
        name = str(metadata.get("name") or "")
        namespace = str(metadata.get("namespace") or "")
        if not name:
            continue
        pod_id = add_asset("POD", f"{namespace}/{name}", {"namespace": namespace, "name": name})
        containers = ((pod.get("spec") or {}).get("containers") or [])
        sidecars = [container for container in containers
                    if _is_sidecar(str(container.get("name") or ""), str(container.get("image") or ""))]
        pod_record = make_evidence(
            source="kubernetes", evidence_type="CONFIGURED", target=pod_id, layer="PLATFORM",
            collector="kubernetes:pods",
            facts={"namespace": namespace, "containers": len(containers),
                   "sidecars": [str(container.get("name")) for container in sidecars],
                   "sidecar_note": (
                       "sidecar crypto is platform crypto, not the application's own crypto"
                       if sidecars else None
                   )},
        )
        evidence.append(pod_record)
        pod_evidence_id = pod_record["evidence_id"]
        namespace_id = add_asset("NAMESPACE", namespace, {"namespace": namespace}) if namespace else None
        if namespace_id:
            relationships.append({
                "subject": namespace_id, "predicate": "contains", "object": pod_id,
                "basis": "DEPLOYMENT_CONFIG", "evidence_ids": [pod_evidence_id],
                "attributes": {"claim": "CONFIGURED", "observed": False},
            })
        relationships.append({
            "subject": cluster_asset["asset_id"], "predicate": "contains", "object": pod_id,
            "basis": "DEPLOYMENT_CONFIG", "evidence_ids": [pod_evidence_id],
            "attributes": {"claim": "CONFIGURED", "observed": False},
        })
        for container in containers:
            cname = str(container.get("name") or "")
            if not cname:
                continue
            image = str(container.get("image") or "")
            container_kind = "CONTAINER"
            container_id = add_asset(container_kind, f"{namespace}/{name}/{cname}",
                                     {"namespace": namespace, "pod": name, "container": cname},
                                     {"image": image,
                                      "sidecar": _is_sidecar(cname, image)})
            container_record = make_evidence(
                source="kubernetes", evidence_type="CONFIGURED", target=container_id, layer="PLATFORM",
                collector="kubernetes:pods",
                facts={"image": image, "sidecar": _is_sidecar(cname, image),
                       "layer_note": "a sidecar's TLS is platform crypto; the application's own crypto is a "
                                     "runtime observation"},
            )
            evidence.append(container_record)
            container_evidence_id = container_record["evidence_id"]
            relationships.append({
                "subject": pod_id, "predicate": "contains", "object": container_id,
                "basis": "DEPLOYMENT_CONFIG", "evidence_ids": [container_evidence_id],
                "attributes": {"claim": "CONFIGURED", "observed": False},
            })
            if image:
                image_ref = image.rsplit("/", 1)[-1]
                image_id = add_asset("IMAGE", image_ref, {"image": image}, {"reference": image})
                image_record = make_evidence(
                    source="kubernetes", evidence_type="CONFIGURED", target=image_id, layer="PLATFORM",
                    collector="kubernetes:pods", facts={"image": image, "digest_pinned": "@sha256:" in image},
                )
                evidence.append(image_record)
                image_evidence_id = image_record["evidence_id"]
                relationships.append({
                    "subject": container_id, "predicate": "runs_on", "object": image_id,
                    "basis": "DEPLOYMENT_CONFIG", "evidence_ids": [image_evidence_id],
                    "attributes": {"claim": "CONFIGURED", "observed": False},
                })

    for ingress in objects.get("ingresses") or []:
        metadata = ingress.get("metadata") or {}
        name = str(metadata.get("name") or "")
        namespace = str(metadata.get("namespace") or "")
        if not name:
            continue
        spec = ingress.get("spec") or {}
        annotations = {key: (metadata.get("annotations") or {}).get(key)
                       for key in TLS_ANNOTATIONS if (metadata.get("annotations") or {}).get(key)}
        tls_blocks = spec.get("tls") or []
        hosts = sorted({host for block in tls_blocks for host in (block.get("hosts") or [])})
        secret_names = sorted({str(block.get("secretName")) for block in tls_blocks if block.get("secretName")})
        passthrough = str(annotations.get("nginx.ingress.kubernetes.io/ssl-passthrough", "")).lower() == "true"
        redirect = str(annotations.get("nginx.ingress.kubernetes.io/ssl-redirect", "")).lower() in {"true", "false"}
        mtls_configured = any("auth-tls" in key for key in annotations)
        gateway_id = add_asset("API_GATEWAY", f"{namespace}/{name}", {"namespace": namespace, "name": name},
                               {"kind": "Ingress"})
        ingress_record = make_evidence(
            source="kubernetes", evidence_type="CONFIGURED", target=gateway_id, layer="NETWORK_TRANSPORT",
            collector="kubernetes:ingresses",
            facts={
                "tls_hosts": hosts,
                # a reference only: the secret's contents are never read
                "tls_secret_ref": secret_names,
                "tls_configured": bool(tls_blocks),
                "termination": (
                    "PASSTHROUGH_DECLARED" if passthrough else
                    "TERMINATION_DECLARED" if tls_blocks else "NO_TLS_BLOCK"
                ),
                "ssl_redirect": annotations.get("nginx.ingress.kubernetes.io/ssl-redirect") if redirect else None,
                "mtls_configured": mtls_configured,
                "annotations": annotations,
                "claim": "CONFIGURED — whether this route really negotiates TLS is a network observation",
                "layer_note": "TRANSPORT configuration only; application crypto is a runtime observation",
            },
        )
        evidence.append(ingress_record)
        ingress_evidence_id = ingress_record["evidence_id"]
        # configured edge only: the config names a backend service, it does not prove a handshake
        for rule in spec.get("rules") or []:
            for path in ((rule.get("http") or {}).get("paths") or []):
                backend = ((path.get("backend") or {}).get("service") or {})
                backend_name = str(backend.get("name") or "")
                service_id = services.get((namespace, backend_name))
                if service_id and secret_names:
                    relationships.append({
                        "subject": gateway_id, "predicate": "terminates_tls_for", "object": service_id,
                        "basis": "DEPLOYMENT_CONFIG", "evidence_ids": [ingress_evidence_id],
                        "attributes": {"claim": "CONFIGURED", "observed": False,
                                       "note": "an Ingress with a TLS block is configured to terminate TLS; "
                                               "the handshake itself is unobserved here"},
                    })

    expected = len(LIST_PATHS)
    status_blocked = bool(blocked)
    return {
        "schema": SCHEMA,
        "plane": "KUBERNETES",
        "expected": expected,
        "collected": collected,
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "blocked": blocked,
        "namespaces": len(namespaces) or len({asset["name"] for asset in assets if asset["type"] == "NAMESPACE"}),
        "credential_source": resolved.get("source"),
        "note": (
            f"{len(blocked)} of {expected} list call(s) were blocked or failed — those resources are NOT_OBSERVED"
            if status_blocked else None
        ),
        "limitations": limitations + [
            "read-only: no object is created, patched or deleted",
            "secrets are never read; only secret *references* appear in the evidence",
            "all crypto here is CONFIGURED — observed negotiation comes from the network plane",
            "workload crypto inside containers needs the runtime plane, not this collector",
        ],
    }
