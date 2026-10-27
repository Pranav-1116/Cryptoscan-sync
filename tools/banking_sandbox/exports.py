"""Inert Kubernetes/cloud/network exports: no credentials, no apply action."""


def kubernetes(bank, apps):
    items = []
    environments = ["dev", "test", "staging", "production", "dr"]
    for env in environments:
        items.extend(
            [
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": env, "labels": {"synthetic": "true"}}},
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "SYNTHETIC-metadata-only", "namespace": env},
                    "type": "Opaque",
                },
                {
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {"name": "SYNTHETIC-mesh", "namespace": env},
                    "data": {"mtls": "STRICT", "label": "SYNTHETIC LAB"},
                },
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "NetworkPolicy",
                    "metadata": {"name": "LAB-default-deny", "namespace": env},
                    "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "LAB-read-only", "namespace": env},
                    "rules": [{"apiGroups": [""], "resources": ["pods", "services"], "verbs": ["get", "list"]}],
                },
            ]
        )
    for i, a in enumerate(apps[:20]):
        env = a["environment"]
        name = a["app_id"]
        meta = {"name": name, "namespace": env, "labels": {"synthetic": "true"}}
        pod = {
            "containers": [
                {"name": "application", "image": "lab.invalid/" + name + "@" + a["image_digest"]},
                {"name": "mesh-sidecar", "image": "lab.invalid/SYNTHETIC-mesh:1"},
            ]
        }
        kind = ["Deployment", "StatefulSet", "DaemonSet"][i % 3]
        spec = {
            "selector": {"matchLabels": {"app": name}},
            "template": {"metadata": {"labels": {"app": name}}, "spec": pod},
        }
        if kind != "DaemonSet":
            spec["replicas"] = 2
        if kind == "StatefulSet":
            spec["serviceName"] = name
        items.extend(
            [
                {"apiVersion": "apps/v1", "kind": kind, "metadata": meta, "spec": spec},
                {"apiVersion": "v1", "kind": "Pod", "metadata": meta, "spec": pod},
                {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": meta,
                    "spec": {"selector": {"app": name}, "ports": [{"port": 443, "targetPort": 8443}]},
                },
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": meta,
                    "spec": {"tls": [{"hosts": [name + ".lab.invalid"], "secretName": "SYNTHETIC-metadata-only"}]},
                },
                {
                    "apiVersion": "gateway.networking.k8s.io/v1",
                    "kind": "Gateway",
                    "metadata": meta,
                    "spec": {
                        "gatewayClassName": "SYNTHETIC-LAB",
                        "listeners": [{"name": "https", "protocol": "HTTPS", "port": 443}],
                    },
                },
            ]
        )
    return {"apiVersion": "v1", "kind": "List", "items": items, "synthetic": True, "apply_authorized": False}
