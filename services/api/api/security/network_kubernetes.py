"""Kubernetes network correlation (spec 67 §20).

A Kubernetes manifest is a *declaration*: it says an Ingress terminates TLS with
a named secret for a host, not that the handshake on the wire looks like that.
This module turns manifests into declared endpoints, then annotates them with
whatever CryptoScan actually observed for the same host/port.

    Ingress host:port → declared TLS (secret name, hosts)
                      → observed TLS (version, cipher, certificate) if any
    Service           → internal endpoint (cluster IP / port)
    Pod / container   → image reference + sidecar marker

Nothing is promoted: a declared ingress TLS version stays ``NETWORK_CONFIGURED``
and a hop nobody observed stays ``UNKNOWN`` (§23, §29). Sidecars are marked so a
mesh proxy's TLS is never read as the application's own crypto (§17, §27).
"""

from __future__ import annotations

from typing import Any, Iterable


MODEL = "cryptoscan.kubernetes-correlation/1"

#: container name fragments that identify a mesh sidecar / proxy
SIDECAR_TOKENS = ("istio-proxy", "envoy", "linkerd-proxy", "sidecar", "consul-agent", "nginx-mesh")


def _meta(manifest: dict[str, Any]) -> tuple[str, str, str]:
    metadata = manifest.get("metadata") or {}
    return (
        str(manifest.get("kind") or ""),
        str(metadata.get("namespace") or "default"),
        str(metadata.get("name") or ""),
    )


def _is_sidecar(name: str) -> bool:
    lowered = str(name or "").lower()
    return any(token in lowered for token in SIDECAR_TOKENS)


def _observed_index(evidence: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for record in evidence:
        target = record.get("target") or {}
        for key in (target.get("endpoint"), target.get("host")):
            if key and str(key) not in index:
                index[str(key)] = record
    return index


def correlate(
    manifests: Iterable[dict[str, Any]],
    evidence: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Correlate Kubernetes objects with observed network crypto."""
    observed = _observed_index(evidence)
    ingresses: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    pods: list[dict[str, Any]] = []
    declared_endpoints: list[dict[str, Any]] = []
    unsupported: list[dict[str, Any]] = []

    for manifest in manifests:
        if not isinstance(manifest, dict):
            continue
        kind, namespace, name = _meta(manifest)
        spec = manifest.get("spec") or {}
        if kind == "Ingress":
            tls_specs = spec.get("tls") or []
            hosts: list[str] = []
            for rule in spec.get("rules") or []:
                host = (rule or {}).get("host")
                if host:
                    hosts.append(str(host))
            for tls in tls_specs:
                for host in tls.get("hosts") or hosts:
                    endpoint = f"{host}:443"
                    record = observed.get(endpoint) or observed.get(str(host))
                    declared_endpoints.append(
                        {
                            "endpoint": endpoint,
                            "kind": "INGRESS_TLS",
                            "namespace": namespace,
                            "name": name,
                            "declared": {
                                "host": str(host),
                                "secret_name": tls.get("secretName"),
                                "source": "KUBERNETES_INGRESS_SPEC",
                            },
                            "observed": bool(record),
                            "evidence_type": (record or {}).get("evidence_type") or "UNKNOWN",
                            "evidence_id": (record or {}).get("evidence_id"),
                            "tls_version": (record or {}).get("tls_version"),
                            "cipher_suite": (record or {}).get("cipher_suite"),
                            "mutual_tls": (record or {}).get("mutual_tls"),
                            "note": None
                            if record
                            else "ingress TLS is declared in the manifest — the handshake is NOT_OBSERVED",
                        }
                    )
            ingresses.append(
                {
                    "namespace": namespace,
                    "name": name,
                    "hosts": hosts,
                    "tls_hosts": [host for tls in tls_specs for host in (tls.get("hosts") or [])],
                    "secret_names": [tls.get("secretName") for tls in tls_specs if tls.get("secretName")],
                    "ingress_class": spec.get("ingressClassName"),
                    "backends": [
                        {
                            "service": ((rule.get("http") or {}).get("paths") or [{}])[0].get("backend", {}).get("service", {}).get("name")
                            if rule.get("http")
                            else None,
                            "path": ((rule.get("http") or {}).get("paths") or [{}])[0].get("path"),
                        }
                        for rule in spec.get("rules") or []
                    ],
                }
            )
        elif kind == "Service":
            for port in spec.get("ports") or []:
                endpoint = f"{spec.get('clusterIP') or name}:{port.get('port')}"
                record = observed.get(endpoint)
                declared_endpoints.append(
                    {
                        "endpoint": endpoint,
                        "kind": "SERVICE_PORT",
                        "namespace": namespace,
                        "name": name,
                        "declared": {
                            "port": port.get("port"),
                            "target_port": port.get("targetPort"),
                            "type": spec.get("type"),
                            "source": "KUBERNETES_SERVICE_SPEC",
                        },
                        "observed": bool(record),
                        "evidence_type": (record or {}).get("evidence_type") or "UNKNOWN",
                        "evidence_id": (record or {}).get("evidence_id"),
                        "tls_version": (record or {}).get("tls_version"),
                        "cipher_suite": (record or {}).get("cipher_suite"),
                        "mutual_tls": (record or {}).get("mutual_tls"),
                        "note": None
                        if record
                        else "service port is declared — its transport crypto is NOT_OBSERVED",
                    }
                )
            services.append(
                {
                    "namespace": namespace,
                    "name": name,
                    "type": spec.get("type"),
                    "ports": [port.get("port") for port in spec.get("ports") or []],
                    "selector": spec.get("selector") or {},
                    "external_ips": spec.get("externalIPs") or [],
                }
            )
        elif kind == "Pod":
            containers = []
            for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
                containers.append(
                    {
                        "name": container.get("name"),
                        "image": container.get("image"),
                        "sidecar": _is_sidecar(container.get("name")),
                    }
                )
            pods.append(
                {
                    "namespace": namespace,
                    "name": name,
                    "labels": (manifest.get("metadata") or {}).get("labels") or {},
                    "containers": containers,
                    "image_digest_pinned": all(
                        "@sha256:" in str(container.get("image") or "") for container in containers
                    )
                    if containers
                    else None,
                }
            )
        else:
            unsupported.append({"kind": kind, "namespace": namespace, "name": name})

    # Service → Pod links via selector match, kept as declared topology
    links: list[dict[str, Any]] = []
    for service in services:
        selector = service["selector"]
        if not selector:
            continue
        for pod in pods:
            if pod["namespace"] != service["namespace"]:
                continue
            if all(str(pod["labels"].get(key)) == str(value) for key, value in selector.items()):
                links.append(
                    {
                        "from": f"service/{service['namespace']}/{service['name']}",
                        "to": f"pod/{pod['namespace']}/{pod['name']}",
                        "kind": "SELECTOR_MATCH",
                        "source": "KUBERNETES_MANIFEST",
                        "sidecar_only": all(container["sidecar"] for container in pod["containers"]),
                    }
                )

    observed_endpoints = [item for item in declared_endpoints if item["observed"]]
    sidecars = [
        {"pod": f"{pod['namespace']}/{pod['name']}", "containers": [c["name"] for c in pod["containers"] if c["sidecar"]]}
        for pod in pods
        if any(container["sidecar"] for container in pod["containers"])
    ]
    return {
        "model": MODEL,
        "ingresses": ingresses,
        "services": services,
        "pods": pods,
        "links": links,
        "endpoints": declared_endpoints,
        "sidecars": sidecars,
        "unsupported_kinds": unsupported,
        "summary": {
            "manifests": len(ingresses) + len(services) + len(pods),
            "ingresses": len(ingresses),
            "services": len(services),
            "pods": len(pods),
            "declared_endpoints": len(declared_endpoints),
            "observed_endpoints": len(observed_endpoints),
            "unobserved_endpoints": len(declared_endpoints) - len(observed_endpoints),
            "sidecar_pods": len(sidecars),
        },
        "limitations": [
            "a manifest is a declaration — declared TLS is NETWORK_CONFIGURED, never AN observed handshake",
            "pod images are references, not evidence about the crypto a container actually executes",
            "a sidecar proxy's TLS protects the mesh hop; it is not the application's own crypto (§17, §27)",
            "network policies, service-mesh authorization and secrets are not inspected",
        ],
        "boundary": "Kubernetes declares topology and TLS intent; only matched network evidence is observed",
    }
