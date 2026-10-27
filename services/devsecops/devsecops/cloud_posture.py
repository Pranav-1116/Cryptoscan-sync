"""Deterministic CIS-style cloud posture checks (AWS / Azure / GCP).

Evaluates normalized resource records against a fixed benchmark of high-signal
rules. Records are plain dicts (resource type + attributes) produced by a
collector or submitted by an operator, so the checks are fully testable
offline and reproducible. Each finding references a stable rule id and a
benchmark-style control.

Resource shapes (provider-specific but normalized):
- AWS IAM:   {"provider":"aws","type":"iam_user|iam_role|iam_policy", "name":..., "policy": {...|json}, "mfa_active":bool, "access_keys":[...]}
- AWS bucket:{"provider":"aws","type":"s3_bucket","name":..., "acl":"private|public-read|...",
              "public_access_block":{...}, "encryption":None|{...}, "versioning":bool, "logging":bool}
- AWS SG:    {"provider":"aws","type":"security_group","name":..., "ingress":[{cidr,from_port,to_port,protocol}]}
- Azure:     {"provider":"azure","type":"storage_account|nsg|role_assignment|sql_server", ...}
- GCP:       {"provider":"gcp","type":"bucket|firewall|iam_binding|instance", ...}
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

WORLD_CIDRS = {"0.0.0.0/0", "::/0", "*"}


@dataclass
class PostureFinding:
    rule_id: str
    severity: str
    provider: str
    resource_type: str
    resource: str
    control: str
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, "severity": self.severity,
                "provider": self.provider, "resource_type": self.resource_type,
                "resource": self.resource, "control": self.control, "detail": self.detail}


SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _add(f: list, rule_id, severity, provider, rtype, name, control, detail):
    f.append(PostureFinding(rule_id, severity, provider, rtype, name, control, detail))


def _as_policy(policy: Any) -> dict:
    if isinstance(policy, str):
        try:
            return json.loads(policy)
        except Exception:
            return {}
    return policy if isinstance(policy, dict) else {}


def _policy_allows_admin(policy: dict) -> bool:
    """True if an IAM policy grants wildcard actions/resources to a public principal."""
    for stmt in (policy.get("Statement") or policy.get("statements") or []):
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect", "Allow")).lower() != "allow":
            continue
        actions = stmt.get("Action") or stmt.get("action")
        actions = actions if isinstance(actions, list) else [actions]
        resources = stmt.get("Resource") or stmt.get("resource")
        resources = resources if isinstance(resources, list) else [resources]
        principal = stmt.get("Principal") or stmt.get("principal") or {}
        public = False
        if isinstance(principal, dict):
            aws = principal.get("AWS") or principal.get("*")
            if aws == "*" or principal.get("*"):
                public = True
        elif principal == "*":
            public = True
        if public and (any(a in ("*", "*:*") for a in actions) or
                       any(r == "*" for r in resources)):
            return True
    return False


# ---------------------------------------------------------------- AWS ----- #
def _check_aws(resource: dict, f: list):
    rtype = resource.get("type", "")
    name = resource.get("name", "?")
    if rtype == "iam_user":
        if resource.get("mfa_active") is False:
            _add(f, "CIS-AWS-1.5", "MEDIUM", "aws", rtype, name,
                 "1.5 Ensure IAM users have MFA enabled", "IAM user has no MFA device")
        for key in resource.get("access_keys", []) or []:
            if str(key.get("status", "")).lower() == "active" and key.get("age_days", 0) > 90:
                _add(f, "CIS-AWS-1.14", "LOW", "aws", rtype, name,
                     "1.14 Rotate access keys every 90 days",
                     f"active access key is {key.get('age_days')} days old")
    elif rtype in ("iam_role", "iam_policy"):
        if _policy_allows_admin(_as_policy(resource.get("policy"))):
            _add(f, "CIS-AWS-1.16", "HIGH", "aws", rtype, name,
                 "1.16 Restrict wildcard IAM policies",
                 "policy grants * actions/* resources to a public principal")
    elif rtype == "s3_bucket":
        acl = (resource.get("acl") or "").lower()
        pab = resource.get("public_access_block") or {}
        block_all = all(pab.get(k) is True for k in
                        ("block_public_acls", "ignore_public_acls",
                         "block_public_policy", "restrict_public_buckets"))
        if "public-read" in acl or "public-read-write" in acl or "authenticated" in acl:
            _add(f, "CIS-AWS-2.1", "CRITICAL", "aws", rtype, name,
                 "2.1 Block public S3 ACLs", f"bucket ACL is {acl}")
        if not block_all:
            _add(f, "CIS-AWS-2.1", "HIGH", "aws", rtype, name,
                 "2.1 Enable S3 Block Public Access", "public access block not fully enabled")
        if not resource.get("encryption"):
            _add(f, "CIS-AWS-2.1.1", "HIGH", "aws", rtype, name,
                 "2.1.1 Enable S3 default encryption", "no default encryption configured")
        if resource.get("versioning") is False:
            _add(f, "CIS-AWS-2.1.2", "LOW", "aws", rtype, name,
                 "2.1.2 Enable MFA delete/versioning", "bucket versioning disabled")
        if not resource.get("logging"):
            _add(f, "CIS-AWS-2.6", "LOW", "aws", rtype, name,
                 "2.6 Enable S3 access logging", "server access logging not configured")
    elif rtype == "security_group":
        for rule in resource.get("ingress", []) or []:
            cidr = str(rule.get("cidr", ""))
            if cidr not in WORLD_CIDRS:
                continue
            lo = int(rule.get("from_port", -1))
            hi = int(rule.get("to_port", lo))
            if lo == 0 or (lo <= 22 <= hi):
                _add(f, "CIS-AWS-5.2", "CRITICAL", "aws", rtype, name,
                     "5.2 Restrict SSH (22) from the internet",
                     f"ingress allows {cidr} to ports {lo}-{hi} (covers 22)")
            elif lo <= 3389 <= hi:
                _add(f, "CIS-AWS-5.1", "CRITICAL", "aws", rtype, name,
                     "5.1 Restrict RDP (3389) from the internet",
                     f"ingress allows {cidr} to ports {lo}-{hi} (covers 3389)")


# --------------------------------------------------------------- Azure ---- #
def _check_azure(resource: dict, f: list):
    rtype = resource.get("type", "")
    name = resource.get("name", "?")
    if rtype == "storage_account":
        if resource.get("https_traffic_only") is False or resource.get("enable_https_traffic_only") is False:
            _add(f, "CIS-AZ-3.1", "HIGH", "azure", rtype, name,
                 "3.1 Require secure transfer (HTTPS)", "storage allows HTTP traffic")
        if resource.get("min_tls_version", "TLS1_0") in ("TLS1_0", "TLS1_1", "1.0", "1.1"):
            _add(f, "CIS-AZ-3.1.1", "MEDIUM", "azure", rtype, name,
                 "3.1.1 Enforce minimum TLS 1.2", f"minTLS={resource.get('min_tls_version')}")
        if not resource.get("blob_encryption") and resource.get("encryption") is False:
            _add(f, "CIS-AZ-3.2", "HIGH", "azure", rtype, name,
                 "3.2 Enable storage encryption", "storage encryption disabled")
    elif rtype == "nsg":
        for rule in resource.get("security_rules", []) or []:
            if str(rule.get("source_address_prefix", "")) in WORLD_CIDRS and \
               str(rule.get("destination_port_range", "")) in ("22", "*", "3389") and \
               str(rule.get("access", "")).lower() == "allow":
                _add(f, "CIS-AZ-6.1", "HIGH", "azure", rtype, name,
                     "6.1 Restrict RDP/SSH from internet",
                     f"rule {rule.get('name','?')} allows {rule.get('source_address_prefix')} -> {rule.get('destination_port_range')}")
    elif rtype == "role_assignment":
        if str(resource.get("role", "")).lower() in ("owner", "contributor") and \
           str(resource.get("principal", "")).lower() in ("*", "everyone", "allusers"):
            _add(f, "CIS-AZ-1.23", "HIGH", "azure", rtype, name,
                 "1.23 Avoid broad Owner/Contributor grants", "privileged role assigned to a wildcard principal")


# ----------------------------------------------------------------- GCP ---- #
def _check_gcp(resource: dict, f: list):
    rtype = resource.get("type", "")
    name = resource.get("name", "?")
    if rtype == "bucket":
        if resource.get("iam_configuration", {}).get("public_access_prevention") in ("inherited", None) and \
           not resource.get("uniform_bucket_level_access"):
            _add(f, "CIS-GCP-2.1", "HIGH", "gcp", rtype, name,
                 "2.1 Prevent public bucket access",
                 "uniform bucket-level access / public-access prevention not enforced")
        if not resource.get("encryption"):
            _add(f, "CIS-GCP-2.10", "MEDIUM", "gcp", rtype, name,
                 "2.10 Enable bucket encryption", "no CMEK/default encryption reported")
    elif rtype == "firewall":
        for rule in resource.get("allowed", []) or []:
            ports = [str(p) for p in (rule.get("ports") or [])]
            src = resource.get("source_ranges") or []
            if any(s in WORLD_CIDRS for s in src) and any(p in ("22", "3389", "0-65535") for p in ports):
                _add(f, "CIS-GCP-3.6", "HIGH", "gcp", rtype, name,
                     "3.6 Restrict SSH/RDP from 0.0.0.0/0",
                     f"firewall allows world to ports {ports}")
    elif rtype == "iam_binding":
        if resource.get("role", "").endswith(("owner", "editor")) and \
           ("allUsers" in (resource.get("members") or []) or "allAuthenticatedUsers" in (resource.get("members") or [])):
            _add(f, "CIS-GCP-1.12", "CRITICAL", "gcp", rtype, name,
                 "1.12 No primitive roles for allUsers",
                 f"{resource.get('role')} granted to public members")


_PROVIDER_FN = {"aws": _check_aws, "azure": _check_azure, "gcp": _check_gcp}


def evaluate(resources: Iterable[dict]) -> dict[str, Any]:
    findings: list[PostureFinding] = []
    counts = {"aws": 0, "azure": 0, "gcp": 0, "unknown": 0}
    for resource in resources:
        provider = (resource.get("provider") or "").lower()
        fn = _PROVIDER_FN.get(provider)
        counts[provider if provider in _PROVIDER_FN else "unknown"] += 1
        if fn:
            fn(resource, findings)
    findings.sort(key=lambda x: -SEV.get(x.severity, 0))
    by_sev: dict[str, int] = {}
    for x in findings:
        by_sev[x.severity] = by_sev.get(x.severity, 0) + 1
    return {"resources_scanned": sum(counts.values()), "by_provider": counts,
            "total_findings": len(findings), "by_severity": by_sev,
            "findings": [x.to_dict() for x in findings]}
