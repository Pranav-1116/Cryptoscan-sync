"""Deterministic tests for the DevSecOps engines (features 13-20). No network:
HTTP/producer calls are injected fakes; all matching is offline."""

from __future__ import annotations

import json



# ---- 13. Container CVE + Dockerfile -------------------------------------- #
from devsecops.container_scan import (
    match_packages, scan_dockerfile, scan_image, version_compare,
)

FEED = [
    {"cve_id": "CVE-2024-0001", "severity": "CRITICAL",
     "affected": [{"ecosystem": "debian", "package": "openssl",
                   "ranges": [{"introduced": "0", "fixed": "3.0.11"}]}]},
    {"cve_id": "CVE-2024-0002", "severity": "HIGH",
     "affected": [{"ecosystem": "pypi", "package": "requests",
                   "ranges": [{"introduced": "2.20.0", "fixed": "2.32.0"}]}]},
    {"cve_id": "CVE-2024-0003", "severity": "MEDIUM",
     "affected": [{"ecosystem": "debian", "package": "libfoo",
                   "ranges": [{"introduced": "1.0", "last_affected": "1.5"}]}]},
]


def test_version_ordering():
    assert version_compare("3.0.10", "3.0.11") < 0
    assert version_compare("3.0.12", "3.0.11") > 0
    assert version_compare("2.32.0", "2.32.0") == 0


def test_cve_matching_fixed_ranges():
    pkgs = [
        {"name": "openssl", "version": "3.0.9", "ecosystem": "debian"},   # vuln
        {"name": "openssl", "version": "3.0.11", "ecosystem": "debian"},  # fixed
        {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},   # vuln
        {"name": "libfoo", "version": "1.5", "ecosystem": "debian"},      # last_affected incl
        {"name": "safe", "version": "9.9", "ecosystem": "debian"},        # no CVE
    ]
    matches = match_packages(pkgs, FEED)
    ids = {(m.package, m.cve_id) for m in matches}
    assert ("openssl", "CVE-2024-0001") in ids
    assert ("requests", "CVE-2024-0002") in ids
    assert ("libfoo", "CVE-2024-0003") in ids
    # fixed openssl 3.0.11 not matched
    assert not any(m.package == "openssl" and m.version == "3.0.11" for m in matches)
    # sorted worst-first
    assert matches[0].severity == "CRITICAL"


def test_dockerfile_rules():
    df = """FROM ubuntu
ENV API_KEY=hardcoded-secret-123456
RUN apt-get update && apt-get install -y curl
ADD https://example.com/file.tar /tmp/
CMD ["python"]
"""
    codes = {f.code for f in scan_dockerfile(df)}
    assert {"DK-LATEST", "DK-SECRET-IN-ENV", "DK-ADD-REMOTE", "DK-NO-USER", "DK-PKG-CACHE"} <= codes


def test_dockerfile_good_image_clean():
    df = """FROM python:3.11.9@sha256:abcdef1234567890
USER 1000
RUN pip install --no-cache-dir requests==2.32.0
COPY . /app
"""
    findings = scan_dockerfile(df)
    codes = {f.code for f in findings}
    assert "DK-LATEST" not in codes and "DK-ROOT-USER" not in codes and "DK-NO-USER" not in codes


def test_scan_image_driver():
    r = scan_image(packages=[{"name": "openssl", "version": "3.0.9", "ecosystem": "debian"}],
                   feed=FEED, dockerfile="FROM ubuntu:latest\nRUN apt-get update\n")
    assert r["vulnerabilities"] >= 1 and r["worst_severity"] == "CRITICAL"
    assert any(f["code"] == "DK-LATEST" for f in r["dockerfile_findings"])


# ---- 14. Kubernetes misconfig -------------------------------------------- #
from devsecops.k8s_rules import scan_manifests

BAD_K8S = """
apiVersion: v1
kind: Pod
metadata: {name: bad-pod}
spec:
  hostPID: true
  volumes:
    - name: host
      hostPath: {path: /}
  containers:
    - name: app
      image: nginx
      securityContext:
        privileged: true
        capabilities: {add: ["SYS_ADMIN"]}
      ports:
        - containerPort: 80
          hostPort: 8080
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: wildcard}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
"""


def test_k8s_flags_privileged_hostpath_rbac():
    r = scan_manifests(BAD_K8S)
    codes = {f["code"] for f in r["findings"]}
    assert "K8S-PRIVILEGED" in codes
    assert "K8S-HOSTPID" in codes
    assert "K8S-HOSTPATH" in codes
    assert "K8S-CAP-ALL" in codes
    assert "K8S-RBAC-WILDCARD" in codes
    assert "K8S-HOSTPORT" in codes
    assert "K8S-LATEST-IMAGE" in codes
    assert "K8S-NO-LIMITS" in codes


def test_k8s_hardened_manifest_clean():
    good = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: good}
spec:
  template:
    spec:
      serviceAccountName: app-sa
      securityContext: {runAsNonRoot: true}
      containers:
        - name: app
          image: nginx:1.27.1
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: ["ALL"]}
          resources:
            requests: {cpu: "100m", memory: "128Mi"}
            limits: {cpu: "500m", memory: "512Mi"}
"""
    r = scan_manifests(good)
    codes = {f["code"] for f in r["findings"]}
    assert "K8S-PRIVILEGED" not in codes
    assert "K8S-RBAC-WILDCARD" not in codes
    assert "K8S-NO-LIMITS" not in codes
    assert "K8S-RUN-AS-ROOT" not in codes


# ---- 15. Cloud CIS posture ------------------------------------------------ #
from devsecops.cloud_posture import evaluate


def test_aws_s3_public_and_unencrypted():
    res = evaluate([
        {"provider": "aws", "type": "s3_bucket", "name": "open-bucket",
         "acl": "public-read", "public_access_block": {}, "encryption": None,
         "versioning": False, "logging": None},
        {"provider": "aws", "type": "s3_bucket", "name": "secure-bucket",
         "acl": "private",
         "public_access_block": {"block_public_acls": True, "ignore_public_acls": True,
                                 "block_public_policy": True, "restrict_public_buckets": True},
         "encryption": {"algorithm": "AES256"}, "versioning": True, "logging": True},
    ])
    rules = {f["rule_id"] for f in res["findings"]}
    assert "CIS-AWS-2.1" in rules and "CIS-AWS-2.1.1" in rules
    # secure bucket has no findings
    assert all(f["resource"] != "secure-bucket" for f in res["findings"])


def test_aws_sg_ssh_open():
    res = evaluate([{"provider": "aws", "type": "security_group", "name": "sg-open",
                     "ingress": [{"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22, "protocol": "tcp"}]}])
    assert any(f["rule_id"] == "CIS-AWS-5.2" for f in res["findings"])


def test_aws_iam_mfa_and_wildcard():
    res = evaluate([
        {"provider": "aws", "type": "iam_user", "name": "alice", "mfa_active": False},
        {"provider": "aws", "type": "iam_policy", "name": "wild",
         "policy": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*",
                                   "Principal": {"AWS": "*"}}]}},
    ])
    rules = {f["rule_id"] for f in res["findings"]}
    assert "CIS-AWS-1.5" in rules and "CIS-AWS-1.16" in rules


def test_azure_gcp_findings():
    res = evaluate([
        {"provider": "azure", "type": "storage_account", "name": "st",
         "https_traffic_only": False, "min_tls_version": "TLS1_0", "encryption": False},
        {"provider": "gcp", "type": "iam_binding", "name": "b", "role": "roles/owner",
         "members": ["allUsers"]},
    ])
    rules = {f["rule_id"] for f in res["findings"]}
    assert "CIS-AZ-3.1" in rules and "CIS-AZ-3.1.1" in rules
    assert "CIS-GCP-1.12" in rules


def test_secure_resources_no_findings():
    res = evaluate([
        {"provider": "aws", "type": "s3_bucket", "name": "ok", "acl": "private",
         "public_access_block": {"block_public_acls": True, "ignore_public_acls": True,
                                 "block_public_policy": True, "restrict_public_buckets": True},
         "encryption": {"a": 1}, "versioning": True, "logging": True},
        {"provider": "aws", "type": "security_group", "name": "tight",
         "ingress": [{"cidr": "10.0.0.0/8", "from_port": 443, "to_port": 443}]},
    ])
    assert res["total_findings"] == 0


# ---- 16. SBOM CycloneDX/SPDX + pinning ------------------------------------ #
from devsecops.sbom import (
    check_pinning, dependency_graph, export_cyclonedx, export_spdx,
    import_cyclonedx, import_sbom, import_spdx,
)

CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "components": [
        {"type": "library", "bom-ref": "pkg:pypi/requests@2.32.0", "name": "requests",
         "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0",
         "licenses": [{"license": {"id": "Apache-2.0"}}],
         "hashes": [{"alg": "SHA-256", "content": "abc"}]},
        {"type": "library", "bom-ref": "pkg:pypi/certifi@2024.2.2", "name": "certifi",
         "version": "2024.2.2", "purl": "pkg:pypi/certifi@2024.2.2"},
    ],
    "dependencies": [{"ref": "pkg:pypi/requests@2.32.0",
                      "dependsOn": ["pkg:pypi/certifi@2024.2.2"]}],
}


def test_sbom_cyclonedx_roundtrip():
    comps = import_cyclonedx(CDX)
    assert len(comps) == 2
    req = next(c for c in comps if c["name"] == "requests")
    assert req["version"] == "2.32.0" and req["license"] == "Apache-2.0"
    assert req["depends_on"] == ["pkg:pypi/certifi@2024.2.2"]
    out = export_cyclonedx(comps)
    assert out["bomFormat"] == "CycloneDX" and len(out["components"]) == 2
    # re-import export stays consistent
    re = import_sbom(out)
    assert len(re) == 2


def test_sbom_spdx_import_export():
    spdx = {"spdxVersion": "SPDX-2.3",
            "packages": [
                {"SPDXID": "SPDXRef-Package-1", "name": "log4j-core", "versionInfo": "2.17.1",
                 "licenseConcluded": "Apache-2.0", "supplier": "Organization: Apache",
                 "externalRefs": [{"referenceType": "purl",
                                   "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"}]},
            ],
            "relationships": []}
    comps = import_spdx(spdx)
    assert comps[0]["name"] == "log4j-core" and comps[0]["version"] == "2.17.1"
    out = export_spdx(comps)
    assert out["spdxVersion"] == "SPDX-2.3" and out["packages"][0]["name"] == "log4j-core"


def test_pinning_check_flags_ranges_and_missing():
    comps = import_cyclonedx(CDX)
    comps += [
        {"name": "leftpad", "version": "^1.2.0", "ecosystem": "npm", "purl": "pkg:npm/leftpad@1.2.0", "depends_on": []},
        {"name": "base", "version": None, "ecosystem": "docker", "purl": "pkg:docker/nginx", "depends_on": []},
    ]
    r = check_pinning(comps)
    codes = {f["code"] for f in r["findings"]}
    assert "PIN-MISSING" in codes and "PIN-RANGE" in codes and "PIN-NO-DIGEST" in codes
    # requests + certifi are exact-pinned; leftpad is a range; docker has no version
    assert r["pinned"] == 2 and r["unpinned"] == 2


def test_dependency_graph_and_cycle():
    comps = [
        {"name": "a", "purl": "pkg:pypi/a@1", "depends_on": ["pkg:pypi/b@1"]},
        {"name": "b", "purl": "pkg:pypi/b@1", "depends_on": ["pkg:pypi/a@1"]},
    ]
    g = dependency_graph(comps)
    assert g["has_cycle"] is True and g["edge_count"] == 2


# ---- 17-20. Connectors ---------------------------------------------------- #
from devsecops.connectors import (
    DeliveryLedger, dedup_key, elastic_bulk, jira_issue, kafka_stream,
    rabbit_stream, servicenow_ticket, slack_message, splunk_hec, teams_adaptive_card,
    HttpResult,
)


class FakeHttp:
    def __init__(self, status=201, body=None):
        self.calls = []
        self.status = status
        self.body = body or {}

    def __call__(self, url, *, content, headers, timeout=10):
        text = content.decode()
        try:
            body = json.loads(text)
        except json.JSONDecodeError:
            body = [json.loads(line) for line in text.splitlines() if line.strip()]
        self.calls.append({"url": url, "body": body, "headers": headers})
        return HttpResult(ok=200 <= self.status < 300, status=self.status,
                          body=json.dumps(self.body))


FINDING = {"finding_id": "F-1", "title": "Critical: public S3 bucket",
           "severity": "critical", "asset": "open-bucket", "detail": "acl=public-read"}


def test_dedup_key_stable():
    assert dedup_key("a", "F-1") == dedup_key("a", "F-1")
    assert dedup_key("a", "F-1") != dedup_key("b", "F-1")


def test_servicenow_and_jira_tickets():
    h = FakeHttp(201, {"result": {"sys_id": "abc123"}})
    r = servicenow_ticket(FINDING, instance="dev123.service-now.com", auth="xx", post=h)
    assert r["ok"] and r["ticket_id"] == "abc123"
    assert h.calls[0]["body"]["correlation_id"] == r["dedup_key"]
    assert "incident" in h.calls[0]["url"]
    h2 = FakeHttp(201, {"key": "SEC-42"})
    j = jira_issue(FINDING, base_url="https://j.co", auth="xx", project="SEC", post=h2)
    assert j["ok"] and j["ticket_id"] == "SEC-42"
    assert j["dedup_key"] in h2.calls[0]["body"]["fields"]["labels"]


def test_splunk_hec_and_elastic_bulk():
    h = FakeHttp(200)
    s = splunk_hec([FINDING, FINDING], hec_url="https://hec:8088", token="tok", post=h)
    assert s["ok"] and s["events_sent"] == 2
    assert h.calls[0]["headers"]["Authorization"] == "Splunk tok"
    assert "/services/collector" in h.calls[0]["url"]
    h2 = FakeHttp(200)
    e = elastic_bulk([FINDING], base_url="https://es:9200", index="findings", auth="key", post=h2)
    assert e["ok"] and e["events_sent"] == 1
    assert "application/x-ndjson" in h2.calls[0]["headers"]["Content-Type"]
    h2.calls[0]["body"] if isinstance(h2.calls[0]["body"], str) else None
    # bulk = 2 NDJSON lines per event (action + doc)
    assert h2.calls[0]["url"].endswith("/findings/_bulk")


def test_kafka_and_rabbit_stream():
    produced = []
    def fake_producer(topic, value, headers):
        produced.append((topic, value, headers))
    k = kafka_stream([FINDING, FINDING], topic="findings", bootstrap="k:9092", producer=fake_producer)
    assert k["ok"] and k["events_sent"] == 2 and produced[0][0] == "findings"
    published = []
    def fake_pub(ex, rk, body, props):
        published.append((ex, rk, props))
    r = rabbit_stream([FINDING], exchange="sec", routing_key="findings.critical", publisher=fake_pub)
    assert r["ok"] and r["events_sent"] == 1 and published[0][0] == "sec"


def test_slack_and_teams_cards_have_actions():
    h = FakeHttp(200)
    s = slack_message(FINDING, webhook_url="https://hooks.slack/x", post=h)
    assert s["ok"]
    actions = h.calls[0]["body"]["attachments"][0]["blocks"][-1]["elements"]
    values = [json.loads(a["value"])["action"] for a in actions]
    assert "ack" in values and "assign" in values
    h2 = FakeHttp(200)
    t = teams_adaptive_card(FINDING, webhook_url="https://teams/x", post=h2)
    assert t["ok"]
    acts = h2.calls[0]["body"]["attachments"][0]["content"]["actions"]
    assert {a["data"]["action"] for a in acts} >= {"ack", "assign"}


def test_delivery_ledger_dedups():
    led = DeliveryLedger()
    k = dedup_key("slack", "F-1")
    assert led.should_deliver("slack-target", k) is True
    assert led.should_deliver("slack-target", k) is False  # same target + key
    assert led.should_deliver("teams-target", k) is True   # different target
