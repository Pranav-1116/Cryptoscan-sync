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
    (r"\bcheckpoint\b", "Check Point", "Gaia", 0.8),
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
    (r"\bopenssl\b", "OpenSSL", "Internal PKI", 0.7),
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
    (r"\b(?:postgresql|postgres)\b", "PostgreSQL", "PostgreSQL", 0.92),
    (r"\bmysql\b", "MySQL", "MySQL", 0.92),
    (r"\bmariadb\b", "MariaDB", "MariaDB", 0.92),
    (r"microsoft sql server", "Microsoft", "SQL Server", 0.92),
    (r"oracle database", "Oracle", "Database", 0.92),
    (r"\bmongodb\b", "MongoDB", "MongoDB", 0.9),
    (r"\bredis\b", "Redis", "Redis", 0.9),
    (r"\bcassandra\b", "Apache", "Cassandra", 0.9),
    # middleware vendors
    (r"apache(?:/|\s)", "Apache", "HTTP Server", 0.88),
    (r"\btomcat\b", "Apache", "Tomcat", 0.9),
    (r"\bwebsphere\b", "IBM", "WebSphere", 0.9),
    (r"\bweblogic\b", "Oracle", "WebLogic", 0.9),
    (r"\bjboss\b", "Red Hat", "JBoss", 0.9),
    (r"\bkafka\b", "Apache", "Kafka", 0.88),
    (r"\brabbitmq\b", "RabbitMQ", "RabbitMQ", 0.88),
    (r"microsoft-?iis", "Microsoft", "IIS", 0.9),
    # OS vendors
    (r"red hat enterprise linux|rhel", "Red Hat", "RHEL", 0.9),
    (r"ubuntu", "Ubuntu", "Ubuntu", 0.88),
    (r"debian", "Debian", "Debian", 0.88),
    (r"suse|sles", "SUSE", "SLES", 0.9),
    (r"microsoft windows", "Microsoft", "Windows", 0.9),
    (r"vmware esxi|esxi", "VMware", "ESXi", 0.92),
    # container registries
    (r"\bharbor\b", "Harbor", "Harbor", 0.9),
    (r"amazon ecr|\becr\b", "AWS", "ECR", 0.85),
    (r"google artifact registry|gcr\.io", "Google", "Artifact Registry", 0.85),
    (r"azure container registry|\bacr\b", "Microsoft", "ACR", 0.85),
    (r"docker registry", "Docker", "Registry", 0.85),
    # kubernetes
    (r"kube-apiserver|kubernetes", "Kubernetes", "Kubernetes", 0.92),
    (r"\beks\b|amazon elastic kubernetes", "AWS", "EKS", 0.85),
    (r"\baks\b|azure kubernetes", "Microsoft", "AKS", 0.85),
    (r"\bgke\b|google kubernetes", "Google", "GKE", 0.85),
    (r"openshift", "Red Hat", "OpenShift", 0.9),
    (r"rancher", "Rancher", "Rancher", 0.9),
    # cloud
    (r"\baws\b|amazon web services", "AWS", "AWS", 0.8),
    (r"\bazure\b", "Microsoft", "Azure", 0.8),
    (r"google cloud|\bgcp\b", "Google", "GCP", 0.8),
    # devops
    (r"github", "GitHub", "GitHub", 0.92),
    (r"gitlab", "GitLab", "GitLab", 0.92),
    (r"bitbucket", "Atlassian", "Bitbucket", 0.9),
    (r"azure devops", "Microsoft", "Azure DevOps", 0.9),
    # SIEM
    (r"azure sentinel", "Microsoft", "Sentinel", 0.9),
    (r"splunk", "Splunk", "Splunk", 0.9),
    (r"\belastic(?: stack|search)?\b", "Elastic", "Elastic", 0.85),
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

    @staticmethod
    def _flatten(value: Any, *, path: str = "") -> list[tuple[str, str]]:
        """Flatten metadata into source-labelled text without losing structure."""
        if isinstance(value, str):
            return [(path or "context", value)] if value.strip() else []
        if isinstance(value, dict):
            rows: list[tuple[str, str]] = []
            for key in sorted(value, key=str):
                child = f"{path}.{key}" if path else str(key)
                rows.extend(UniversalVendorDetectionEngine._flatten(value[key], path=child))
            return rows
        if isinstance(value, set):
            value = sorted(value, key=str)
        if isinstance(value, (list, tuple)):
            rows = []
            for index, item in enumerate(value):
                rows.extend(UniversalVendorDetectionEngine._flatten(
                    item, path=f"{path}[{index}]" if path else f"[{index}]"))
            return rows
        if value is None:
            return []
        return [(path or "context", str(value))]

    @classmethod
    def _haystacks(cls, context: dict[str, Any]) -> list[tuple[str, str]]:
        fields = (
            "banner", "ssh_banner", "server_header", "config", "snmp_sysdescr",
            "api_metadata", "cloud_metadata", "oidc_document", "kubeconfig",
            "vendor", "product", "manufacturer", "model", "version",
        )
        rows: list[tuple[str, str]] = []
        for key in fields:
            rows.extend(cls._flatten(context.get(key), path=key))
        for key in ("tls_certificate", "certificate", "http_headers", "banners"):
            rows.extend(cls._flatten(context.get(key), path=key))
        return rows

    def detect(self, context: dict[str, Any]) -> DetectionResult:
        haystacks = self._haystacks(context)
        joined = "\n".join(value for _source, value in haystacks)

        # Count one match per pattern and evidence source. Repeating the same
        # banner value in two fields must not manufacture confidence, while an
        # independent certificate/API/header signal may corroborate it.
        scores: dict[tuple[str, str], list[tuple[str, float, str]]] = {}
        for pattern, vendor, product, weight in self._patterns:
            matched_sources = sorted({
                source for source, value in haystacks if pattern.search(value)
            })
            for source in matched_sources:
                scores.setdefault((vendor, product), []).append(
                    (pattern.pattern, weight, source))

        if not scores:
            return DetectionResult(confidence=0.0)

        # Deterministic tie-breaking prevents dictionary/input ordering from
        # changing the selected vendor when unrelated signals collide.
        best_key = sorted(
            scores,
            key=lambda key: (-sum(weight for _regex, weight, _source in scores[key]),
                             key[0].lower(), key[1].lower()),
        )[0]
        vendor, product = best_key
        matched = scores[best_key]
        raw_conf = sum(weight for _regex, weight, _source in matched)
        confidence = min(0.5 + 0.25 * raw_conf, 0.99)
        return DetectionResult(
            detected_vendor=vendor,
            detected_product=product,
            detected_version=self._version(context, joined),
            detection_method="multi-signal",
            confidence=round(confidence, 3),
            signals=[{"regex": regex, "weight": weight, "source": source}
                     for regex, weight, source in matched],
        )

    @staticmethod
    def _version(context: dict[str, Any], joined: str) -> Optional[str]:
        if isinstance(context.get("version"), str) and context["version"].strip():
            return context["version"].strip()
        match = re.search(r"(?:version|release)\s*[:=]?\s*([0-9][0-9A-Za-z._\-]*)", joined)
        return match.group(1) if match else None
