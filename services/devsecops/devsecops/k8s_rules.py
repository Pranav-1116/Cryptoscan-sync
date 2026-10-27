"""Kubernetes manifest misconfiguration rules (deterministic policy checks).

Parses YAML manifests (multi-document) and flags a fixed set of high-signal
misconfigurations. No model — each finding maps to a rule id with a stable
severity. Covers:

  K8S-PRIVILEGED      securityContext.privileged: true
  K8S-HOSTPID         hostPID/hostNetwork/hostIPC: true
  K8S-HOSTPATH        hostPath volume (host filesystem access)
  K8S-CAP-ALL         capabilities.add: ["ALL"] / SYS_ADMIN
  K8S-NO-LIMITS       container without resources.limits (cpu/memory)
  K8S-NO-REQUESTS     container without resources.requests
  K8S-RUN-AS-ROOT     runAsNonRoot absent/false without USER non-root guarantee
  K8S-PRIV-ESC        allowPrivilegeEscalation not explicitly false
  K8S-ROOTFS-WRITE    readOnlyRootFilesystem not set true
  K8S-RBAC-WILDCARD   RBAC grants verbs/resources ["*"] (cluster-admin-ish)
  K8S-HOSTPORT        container binds hostPort
  K8S-DEFAULT-SA      pod uses the default service account
  K8S-LATEST-IMAGE    image uses :latest / missing tag
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


@dataclass
class K8sFinding:
    code: str
    severity: str
    kind: str
    name: str
    location: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "kind": self.kind,
                "name": self.name, "location": self.location, "detail": self.detail}


SEV = {
    "K8S-PRIVILEGED": "CRITICAL", "K8S-RBAC-WILDCARD": "HIGH", "K8S-CAP-ALL": "HIGH",
    "K8S-HOSTPID": "HIGH", "K8S-HOSTPATH": "HIGH", "K8S-HOSTPORT": "MEDIUM",
    "K8S-PRIV-ESC": "MEDIUM", "K8S-RUN-AS-ROOT": "MEDIUM", "K8S-NO-LIMITS": "LOW",
    "K8S-NO-REQUESTS": "LOW", "K8S-ROOTFS-WRITE": "LOW", "K8S-DEFAULT-SA": "LOW",
    "K8S-LATEST-IMAGE": "LOW",
}


def load_manifests(text: str) -> list[dict[str, Any]]:
    if yaml is None:
        raise RuntimeError("PyYAML is required to parse Kubernetes manifests")
    docs = []
    for doc in yaml.safe_load_all(text):
        if isinstance(doc, dict):
            docs.append(doc)
    return docs


def _pod_security_context(pod: dict) -> dict:
    return pod.get("spec", {}).get("securityContext", {}) or {}


def _containers(pod_spec: dict) -> list[tuple[str, dict]]:
    out = []
    for key in ("containers", "initContainers"):
        for c in pod_spec.get(key, []) or []:
            out.append((key, c))
    return out


def _check_pod(doc: dict) -> list[K8sFinding]:
    kind = doc.get("kind", "?")
    meta = doc.get("metadata", {}) or {}
    name = meta.get("name", "?")
    spec = doc.get("spec", {}) or {}
    # For workload controllers the pod spec lives under spec.template.spec;
    # CronJob nests one more level (spec.jobTemplate.spec.template.spec).
    if kind == "CronJob":
        pod_spec = (spec.get("jobTemplate", {}).get("spec", {})
                    .get("template", {}).get("spec", {}) or {})
    elif kind != "Pod" and "template" in spec:
        pod_spec = spec.get("template", {}).get("spec", {}) or {}
    else:
        pod_spec = spec
    f: list[K8sFinding] = []

    def add(code, loc, detail):
        f.append(K8sFinding(code, SEV[code], kind, name, loc, detail))

    psc = pod_spec.get("securityContext", {}) or {}

    # pod-level host namespaces
    for ns in ("hostPID", "hostNetwork", "hostIPC"):
        if pod_spec.get(ns) is True:
            add("K8S-HOSTPID", f"spec.{ns}", f"{ns}=true shares the host namespace")

    # hostPath volumes
    for vol in pod_spec.get("volumes", []) or []:
        if isinstance(vol, dict) and "hostPath" in vol:
            add("K8S-HOSTPATH", f"spec.volumes[{vol.get('name','?')}]",
                f"hostPath {vol['hostPath'].get('path','?')} mounts the node filesystem")

    # RBAC wildcards (ClusterRole/Role carry `rules` at top level, not under spec)
    rbac_rules = spec.get("rules") if spec.get("rules") else doc.get("rules", [])
    if kind in ("ClusterRole", "Role"):
        for rule in rbac_rules or []:
            verbs = rule.get("verbs", []) or []
            resources = rule.get("resources", []) or []
            if "*" in verbs or "*" in resources:
                add("K8S-RBAC-WILDCARD", "rules",
                    f"role grants wildcard verbs={verbs} resources={resources}")

    # pod-level security context
    if psc.get("runAsNonRoot") is not True and kind in ("Pod", "Deployment", "StatefulSet",
                                                        "DaemonSet", "Job", "CronJob"):
        add("K8S-RUN-AS-ROOT", "spec.securityContext",
            "runAsNonRoot not set to true at pod level")

    # default service account
    if not pod_spec.get("serviceAccountName") and kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet"):
        add("K8S-DEFAULT-SA", "spec.serviceAccountName",
            "workload uses the default service account")

    # container-level checks
    for ckey, c in _containers(pod_spec):
        cname = c.get("name", "?")
        loc = f"{ckey}[{cname}]"
        csc = c.get("securityContext", {}) or {}
        if csc.get("privileged") is True:
            add("K8S-PRIVILEGED", f"{loc}.securityContext", "privileged container")
        caps = (csc.get("capabilities", {}) or {})
        add_caps = caps.get("add", []) or []
        if "ALL" in add_caps or "SYS_ADMIN" in add_caps:
            add("K8S-CAP-ALL", f"{loc}.capabilities", f"adds dangerous capabilities {add_caps}")
        if csc.get("allowPrivilegeEscalation") is not False:
            add("K8S-PRIV-ESC", f"{loc}.securityContext",
                "allowPrivilegeEscalation not explicitly false")
        if csc.get("readOnlyRootFilesystem") is not True:
            add("K8S-ROOTFS-WRITE", f"{loc}.securityContext",
                "readOnlyRootFilesystem not set true")
        res = c.get("resources", {}) or {}
        if not res.get("limits"):
            add("K8S-NO-LIMITS", f"{loc}.resources", "no cpu/memory limits set")
        if not res.get("requests"):
            add("K8S-NO-REQUESTS", f"{loc}.resources", "no cpu/memory requests set")
        for hp in c.get("ports", []) or []:
            if isinstance(hp, dict) and hp.get("hostPort"):
                add("K8S-HOSTPORT", f"{loc}.ports", f"binds hostPort {hp['hostPort']}")
        img = c.get("image", "")
        if img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
            add("K8S-LATEST-IMAGE", f"{loc}.image", f"image not pinned to a tag: {img}")
    return f


def scan_manifests(text: str) -> dict[str, Any]:
    docs = load_manifests(text)
    findings: list[K8sFinding] = []
    for doc in docs:
        findings.extend(_check_pod(doc))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {
        "manifests_scanned": len(docs),
        "total_findings": len(findings),
        "by_severity": by_sev,
        "findings": [f.to_dict() for f in findings],
    }


def scan_manifest_docs(docs: Iterable[dict]) -> dict[str, Any]:
    findings: list[K8sFinding] = []
    docs = list(docs)
    for doc in docs:
        findings.extend(_check_pod(doc))
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    return {"manifests_scanned": len(docs), "total_findings": len(findings),
            "by_severity": by_sev, "findings": [f.to_dict() for f in findings]}
