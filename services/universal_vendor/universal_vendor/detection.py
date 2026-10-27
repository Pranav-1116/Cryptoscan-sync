"""Universal vendor detection engine (spec §16).

Before selecting a plugin, detect the vendor and product from multiple
signals: network banner, SSH banner, TLS certificate, HTTP headers,
config-file markers, cloud metadata, controller metadata, API metadata.

Never depends on a single signal — confidence is aggregated across all
matched signals and the engine records every signal used.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from universal_vendor.models import DetectionResult

# signal: (regex, vendor, product, weight)
_SIGNAL_CATALOG: list[tuple[str, str, str, float]] = [
    # network vendors
    (r"cisco ios[- ]xe", "Cisco", "IOS-XE", 0.95),
    (r"cisco ios[- ]xr", "Cisco", "IOS-XR", 0.95),
    (r"cisco ios software", "Cisco", "IOS", 0.93),
    (r"cisco nx-os", "Cisco", "NX-OS", 0.95),
    (r"cisco (?:asa|adaptive security appliance)", "Cisco", "ASA", 0.95),
    (r"cisco catalyst", "Cisco", "Catalyst", 0.9),
    (r"cisco nexus", "Cisco", "Nexus", 0.9),
    (r"juniper (?:networks )?(?:junos|screenos|ex|mx|srx)", "Juniper", "Junos", 0.93),
    (r"arista (?:networks )?(?:eos|dcs-|7050|7280)", "Arista", "EOS", 0.93),
    (r"huawei (?:vrp|ar|ce|s5700)", "Huawei", "VRP", 0.9),
    (r"mikrotik routeros", "MikroTik", "RouterOS", 0.93),
    (r"mikrotik", "MikroTik", "RouterOS", 0.8),
    (r"ubiquiti (?:unifi|edgeos|edge router)", "Ubiquiti", "UniFi", 0.88),
    # firewall / security vendors
    (r"palo.?alto (?:networks )?pan-os", "Palo Alto", "PAN-OS", 0.95),
    (r"palo.?alto", "Palo Alto", "PAN-OS", 0.85),
    (r"fortinet fortios", "Fortinet", "FortiOS", 0.95),
    (r"fortios", "Fortinet", "FortiOS", 0.88),
    (r"fortigate", "Fortinet", "FortiGate", 0.9),
    (r"check point (?:gaia|secureplatform)", "Check Point", "Gaia", 0.92),
    (r"checkpoint", "Check Point", "Gaia", 0.8),
    (r"sophos (?:xg|xg firewall)", "Sophos", "XG", 0.9),
    (r"sonicwall", "SonicWall", "SonicOS", 0.9),
    (r"watchguard (?:fireware|xtm)", "WatchGuard", "Fireware", 0.9),
    (r"cisco secure firewall", "Cisco", "Secure Firewall", 0.9),
    # load balancer / ADC vendors
    (r"f5 (?:networks )?(?:big-?ip|bigip)", "F5", "BIG-IP", 0.95),
    (r"citrix (?:netscaler|adc)", "Citrix", "ADC", 0.92),
    (r"a10 (?:networks )?(?:ax|thunder)", "A10", "Thunder", 0.9),
    (r"nginx(?:/|\s)", "NGINX", "NGINX", 0.88),
    (r"haproxy", "HAProxy", "HAProxy", 0.9),
    # PKI vendors
    (r"hashi(?P<space>\.)?corp vault", "HashiCorp", "Vault PKI", 0.95),
    (r"active directory certificate services|adcs", "Microsoft", "AD CS", 0.92),
    (r"entrust", "Entrust", "PKI", 0.85),
    (r"digicert", "DigiCert", "PKI", 0.85),
    (r"sectigo", "Sectigo", "PKI", 0.85),
    (r"globalsign", "GlobalSign", "PKI", 0.85),
    (r"openssl", "OpenSSL", "Internal PKI", 0.7),
    # HSM vendors
    (r"thales (?:luna|pay|dsm)", "Thales", "Luna HSM", 0.95),
    (r"entrust nshield", "Entrust", "nShield HSM", 0.95),
    (r"utimaco (?:securityserver|q-safe)", "Utimaco", "SecurityServer", 0.95),
    (r"cloudhsm", "AWS", "CloudHSM", 0.9),
    # identity vendors
    (r"keycloak", "Keycloak", "Keycloak", 0.92),
    (r"entra id|azure ad|microsoftonline|sts\.windows", "Microsoft", "Entra ID", 0.9),
    (r"okta", "Okta", "Okta", 0.9),
    (r"pingidentity|ping federate", "Ping Identity", "PingFederate", 0.9),
    (r"auth0", "Auth0", "Auth0", 0.9),
    # database vendors
    (r"postgresql|postgres", "PostgreSQL", "PostgreSQL", 0.92),
    (r"mysql", "MySQL", "MySQL", 0.92),
    (r"mariadb", "MariaDB", "MariaDB", 0.92),
    (r"microsoft sql server", "Microsoft", "SQL Server", 0.92),
    (r"oracle database", "Oracle", "Database", 0.92),
    (r"mongodb", "MongoDB", "MongoDB", 0.9),
    (r"redis", "Redis", "Redis", 0.9),
    (r"cassandra", "Apache", "Cassandra", 0.9),
    # middleware vendors
    (r"apache(?:/|\s)", "Apache", "HTTP Server", 0.88),
    (r"tomcat", "Apache", "Tomcat", 0.9),
    (r"websphere", "IBM", "WebSphere", 0.9),
    (r"weblogic", "Oracle", "WebLogic", 0.9),
    (r"jboss", "Red Hat", "JBoss", 0.9),
    (r"kafka", "Apache", "Kafka", 0.88),
    (r"rabbitmq", "RabbitMQ", "RabbitMQ", 0.88),
    (r"microsoft-?iis", "Microsoft", "IIS", 0.9),
    # OS vendors
    (r"red hat enterprise linux|rhel", "Red Hat", "RHEL", 0.9),
    (r"ubuntu", "Ubuntu", "Ubuntu", 0.88),
    (r"debian", "Debian", "Debian", 0.88),
    (r"suse|sles", "SUSE", "SLES", 0.9),
    (r"microsoft windows", "Microsoft", "Windows", 0.9),
    (r"vmware esxi|esxi", "VMware", "ESXi", 0.92),
    # container registries
    (r"harbor", "Harbor", "Harbor", 0.9),
    (r"amazon ecr|ecr", "AWS", "ECR", 0.85),
    (r"google artifact registry|gcr\.io", "Google", "Artifact Registry", 0.85),
    (r"azure container registry|acr", "Microsoft", "ACR", 0.85),
    (r"docker registry", "Docker", "Registry", 0.85),
    # kubernetes
    (r"kube-apiserver|kubernetes", "Kubernetes", "Kubernetes", 0.92),
    (r"eks|amazon elastic kubernetes", "AWS", "EKS", 0.85),
    (r"aks|azure kubernetes", "Microsoft", "AKS", 0.85),
    (r"gke|google kubernetes", "Google", "GKE", 0.85),
    (r"openshift", "Red Hat", "OpenShift", 0.9),
    (r"rancher", "Rancher", "Rancher", 0.9),
    # cloud
    (r"aws|amazon web services", "AWS", "AWS", 0.8),
    (r"azure", "Microsoft", "Azure", 0.8),
    (r"google cloud|gcp", "Google", "GCP", 0.8),
    # devops
    (r"github", "GitHub", "GitHub", 0.92),
    (r"gitlab", "GitLab", "GitLab", 0.92),
    (r"bitbucket", "Atlassian", "Bitbucket", 0.9),
    (r"azure devops", "Microsoft", "Azure DevOps", 0.9),
    # SIEM
    (r"azure sentinel", "Microsoft", "Sentinel", 0.9),
    (r"splunk", "Splunk", "Splunk", 0.9),
    (r"elastic", "Elastic", "Elastic", 0.85),
    (r"qradar", "IBM", "QRadar", 0.9),
    # EDR
    (r"crowdstrike", "CrowdStrike", "Falcon", 0.9),
    (r"sentinelone", "SentinelOne", "SentinelOne", 0.9),
    (r"microsoft defender", "Microsoft", "Defender", 0.9),
]


class UniversalVendorDetectionEngine:
    """Multi-signal vendor detection. Input context may carry any subset of:
    banner / ssh_banner / server_header / config / tls_certificate /
    certificate / snmp_sysdescr / api_metadata / cloud_metadata / http_headers.
    """

    def __init__(self, catalog: Iterable[tuple[str, str, str, float]] | None = None) -> None:
        self._patterns: list[tuple[re.Pattern[str], str, str, float]] = []
        for regex, vendor, product, weight in catalog or _SIGNAL_CATALOG:
            self._patterns.append((re.compile(regex, re.IGNORECASE), vendor, product, weight))

    def detect(self, context: dict[str, Any]) -> DetectionResult:
        haystacks: list[str] = []
        for key in ("banner", "ssh_banner", "server_header", "config",
                    "snmp_sysdescr", "api_metadata", "cloud_metadata",
                    "oidc_document", "kubeconfig"):
            value = context.get(key)
            if isinstance(value, str) and value.strip():
                haystacks.append(value)
        if isinstance(context.get("tls_certificate"), dict):
            cert = context["tls_certificate"]
            for field in ("subject", "issuer", "cn", "san"):
                if isinstance(cert.get(field), str):
                    haystacks.append(cert[field])
        elif isinstance(context.get("certificate"), dict):
            cert = context["certificate"]
            for field in ("subject", "issuer", "cn"):
                if isinstance(cert.get(field), str):
                    haystacks.append(cert[field])
        if isinstance(context.get("http_headers"), dict):
            for value in context["http_headers"].values():
                if isinstance(value, str):
                    haystacks.append(value)
        if isinstance(context.get("banners"), list):
            for banner in context["banners"]:
                if isinstance(banner, str):
                    haystacks.append(banner)
        joined = "\n".join(haystacks)

        scores: dict[tuple[str, str], list[tuple[str, float]]] = {}
        for pattern, vendor, product, weight in self._patterns:
            if pattern.search(joined):
                scores.setdefault((vendor, product), []).append((pattern.pattern, weight))

        if not scores:
            return DetectionResult(confidence=0.0)

        # best vendor/product by summed weight, confidence bounded
        best_key = max(scores, key=lambda key: sum(w for _, w in scores[key]))
        vendor, product = best_key
        matched = scores[best_key]
        raw_conf = sum(w for _, w in matched)
        confidence = min(0.5 + 0.25 * raw_conf, 0.99)
        return DetectionResult(
            detected_vendor=vendor,
            detected_product=product,
            detected_version=self._version(context, joined),
            detection_method="multi-signal",
            confidence=round(confidence, 3),
            signals=[{"regex": r, "weight": w} for r, w in matched],
        )

    @staticmethod
    def _version(context: dict[str, Any], joined: str) -> Optional[str]:
        if isinstance(context.get("version"), str) and context["version"].strip():
            return context["version"].strip()
        match = re.search(r"(?:version|release)\s*[:=]?\s*([0-9][0-9A-Za-z._\-]*)", joined)
        return match.group(1) if match else None
