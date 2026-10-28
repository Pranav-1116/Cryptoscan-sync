"""Live AWS discovery plane (spec 67 §4, §21; spec 93 §13).

Spec 67 listed "live cloud collectors" as open, and cloud TLS correlation only
accepted metadata the caller supplied. This is the read-only collector: it calls
the provider's own APIs with SigV4-signed requests formed in this process, and
turns the **configured** TLS/encryption properties of managed services into estate
assets and evidence.

What it reads (read-only, six bounded calls):

* ``ELBv2 DescribeLoadBalancers/DescribeListeners`` — the listener's SSL policy and
  the certificates attached to it;
* ``ACM ListCertificates/DescribeCertificate`` — key algorithm, signature
  algorithm, expiry, and whether the certificate is in use;
* ``RDS DescribeDBInstances`` — storage encryption, its KMS key, the CA the
  instance trusts;
* ``KMS ListKeys/DescribeKey`` — key spec and usage. This is *capability*: a key
  exists and could encrypt AES-256. It does not say an application used it, so
  every KMS fact is ``CONFIGURED`` at the KMS layer and never "in use";
* ``API Gateway GetDomainNames`` — the endpoint's minimum TLS security policy.

What it refuses to do:

* read data planes, objects, secrets, key material or anything that would expose
  customer data — only the metadata above is requested;
* upgrade "the load balancer offers TLS 1.3" into "this application negotiated
  TLS 1.3": that is a network observation, a different plane, a different evidence
  type;
* treat ``AccessDenied`` as "no resources". A refused call becomes ``blocked[]``
  and the plane reports ``PARTIAL`` with the resource named (§16, §32);
* invent credentials. Without an access key the plane raises
  :class:`PlaneNotConfigured`, which the estate job reports ``NOT_ATTEMPTED``.

Credentials: ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, optional
``AWS_SESSION_TOKEN`` (so an instance/task role's temporary credentials work),
``AWS_REGION``/``AWS_DEFAULT_REGION``, and ``AWS_ENDPOINT_OVERRIDE`` for a private
endpoint or a test double.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from api.estate_planes import PlaneNotConfigured
from api.security.aws_sigv4 import sigv4_headers
from shared_models.estate_graph import make_evidence, normalize_asset

SCHEMA = "cryptoscan.estate-cloud/1"
PLANE = "CLOUD"

#: one read-only call per resource family, each naming the exact IAM action it runs
CALLS: dict[str, str] = {
    "load_balancers": "elasticloadbalancing:DescribeLoadBalancers",
    "listeners": "elasticloadbalancing:DescribeListeners",
    "acm": "acm:ListCertificates",
    "databases": "rds:DescribeDBInstances",
    "kms": "kms:ListKeys",
    "api_gateways": "apigateway:GetDomainNames",
}

#: SSL policies whose *name* states the minimum protocol version they allow. A
#: policy name that is not listed is reported ``UNKNOWN`` rather than guessed.
SSL_POLICY_FLOORS: dict[str, str] = {
    "ELBSecurityPolicy-TLS13-1-2-2021-06": "TLSv1.2",
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06": "TLSv1.2",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06": "TLSv1.2",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06": "TLSv1.2",
    "ELBSecurityPolicy-TLS13-1-0-2021-06": "TLSv1.0",
    "ELBSecurityPolicy-TLS-1-2-2017-01": "TLSv1.2",
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06": "TLSv1.2",
    "ELBSecurityPolicy-TLS-1-1-2017-01": "TLSv1.1",
    "ELBSecurityPolicy-2016-08": "TLSv1.0",
    "ELBSecurityPolicy-FS-1-2-Res-2020-10": "TLSv1.2",
    "ELBSecurityPolicy-FS-1-2-2019-08": "TLSv1.2",
}

Transport = Callable[[str, str, Mapping[str, str], "bytes | None", float], tuple[int, bytes]]


class CloudReadError(RuntimeError):
    """The API answered, but not with data we can use."""


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def cloud_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve AWS credentials, or raise :class:`PlaneNotConfigured`."""
    env = dict(os.environ if environ is None else environ)
    access_key = str(env.get("AWS_ACCESS_KEY_ID") or "").strip()
    secret_key = str(env.get("AWS_SECRET_ACCESS_KEY") or "").strip()
    if not access_key or not secret_key:
        raise PlaneNotConfigured(
            "no AWS credentials are available to this process (AWS_ACCESS_KEY_ID / "
            "AWS_SECRET_ACCESS_KEY, or the instance/task role that supplies them)"
        )
    region = str(env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "").strip() or "us-east-1"
    return {
        "access_key": access_key,
        "secret_key": secret_key,
        "session_token": str(env.get("AWS_SESSION_TOKEN") or "").strip() or None,
        "region": region,
        "endpoint": str(env.get("AWS_ENDPOINT_OVERRIDE") or "").rstrip("/") or None,
        "source": "ENVIRONMENT",
    }


def _default_transport(method: str, url: str, headers: Mapping[str, str], body: "bytes | None",
                       timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method.upper())
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read() or b""


# --------------------------------------------------------------------------- #
# request plumbing (SigV4 + the AWS protocols)
# --------------------------------------------------------------------------- #
def _base_url(config: Mapping[str, Any], service: str) -> str:
    if config.get("endpoint"):
        return str(config["endpoint"])
    return f"https://{service}.{config['region']}.amazonaws.com"


def _send(config: Mapping[str, Any], service: str, *, method: str, path: str, query: str,
          body: bytes | None, headers: Mapping[str, str], transport: Transport, timeout: float,
          label: str) -> tuple[int, bytes]:
    url = _base_url(config, service) + path + (f"?{query}" if query else "")
    extras = dict(headers)
    if body:
        extras.setdefault("content-type", "application/x-www-form-urlencoded")
    signed = sigv4_headers(
        method=method,
        url=url,
        body=body or b"",
        region=str(config["region"]),
        access_key=str(config["access_key"]),
        secret_key=str(config["secret_key"]),
        session_token=config.get("session_token"),
        extra_headers=extras,
        service=service,
    )
    request_headers = dict(signed)
    request_headers["Host"] = signed["host"]
    for key, value in headers.items():
        request_headers[key] = value
    status, payload = transport(method, url, request_headers, body, timeout)
    if status == 403:
        raise PermissionError(label)
    if status >= 300:
        raise CloudReadError(f"{label}: HTTP {status} {payload[:200].decode('utf-8', 'replace')}")
    return status, payload


def _query_call(config: Mapping[str, Any], service: str, action: str, version: str,
                params: Mapping[str, Any] | None, transport: Transport, timeout: float,
                label: str | None = None) -> ElementTree.Element:
    """AWS query protocol (ELBv2, RDS): ``GET /?Action=…&Version=…``."""
    from urllib.parse import urlencode

    items: list[tuple[str, str]] = [("Action", action), ("Version", version)]
    for key, value in (params or {}).items():
        items.append((str(key), str(value)))
    _, payload = _send(config, service, method="GET", path="/", query=urlencode(items), body=None,
                       headers={}, transport=transport, timeout=timeout,
                       label=label or f"{service}:{action}")
    try:
        return ElementTree.fromstring(payload)
    except ElementTree.ParseError as exc:
        raise CloudReadError(f"{label or action}: unparseable XML") from exc


def _json_call(config: Mapping[str, Any], service: str, target: str, payload: Mapping[str, Any] | None,
               transport: Transport, timeout: float, label: str | None = None) -> dict[str, Any]:
    """AWS JSON protocol (ACM, KMS): ``POST /`` with ``X-Amz-Target``."""
    body = json.dumps(dict(payload or {})).encode("utf-8")
    headers = {"content-type": "application/x-amz-json-1.1", "x-amz-target": target}
    _, raw = _send(config, service, method="POST", path="/", query="", body=body, headers=headers,
                   transport=transport, timeout=timeout, label=label or target)
    try:
        return json.loads(raw or b"{}")
    except ValueError as exc:
        raise CloudReadError(f"{label or target}: unparseable JSON") from exc


def _rest_get(config: Mapping[str, Any], service: str, path: str, transport: Transport,
              timeout: float, label: str | None = None) -> dict[str, Any]:
    """AWS REST-JSON (API Gateway): plain ``GET`` returning JSON."""
    _, raw = _send(config, service, method="GET", path=path, query="", body=None, headers={},
                   transport=transport, timeout=timeout, label=label or f"{service}:{path}")
    try:
        return json.loads(raw or b"{}")
    except ValueError as exc:
        raise CloudReadError(f"{label or path}: unparseable JSON") from exc


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _members(element: ElementTree.Element, container: str, item: str = "member") -> list[ElementTree.Element]:
    for node in element.iter():
        if _localname(node.tag) == container:
            return [child for child in list(node) if _localname(child.tag) == item]
    return []


def _text(element: ElementTree.Element | None, name: str) -> str | None:
    if element is None:
        return None
    for node in element.iter():
        if _localname(node.tag) == name and node.text:
            return node.text.strip()
    return None


def _flag(element: ElementTree.Element | None, name: str) -> bool | None:
    value = _text(element, name)
    if value is None:
        return None
    return value.lower() == "true"


def _days_until(value: Any, now: datetime) -> int | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - now).days


# --------------------------------------------------------------------------- #
# collector
# --------------------------------------------------------------------------- #
def collect_cloud(
    _db: Any = None,
    *,
    transport: Transport | None = None,
    config: Mapping[str, Any] | None = None,
    timeout: float = 20.0,
    max_items: int = 100,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Enumerate managed-service TLS/encryption configuration into estate evidence."""
    resolved = dict(config) if config else cloud_config()
    resolved.setdefault("source", "INJECTED")
    sender = transport or _default_transport
    stated_now = now or datetime.now(timezone.utc)

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    blocked: list[str] = []
    limitations: list[str] = [
        "every fact here is CONFIGURED: a listener policy or a KMS key spec is a declaration of what "
        "the service allows, not a handshake this scan performed",
        "data planes, objects, secrets and key material are never requested",
        "ELB SSL policies map to their declared minimum TLS version; the real cipher order and maximum "
        "version are only visible by observing a handshake",
    ]
    seen: set[str] = set()
    #: one entry per resource family that answered; a family that answered *and*
    #: was partly refused still counts as answered and the refusal is named in
    #: ``blocked`` — the count is "families we could ask", not "objects we liked"
    answered: set[str] = set()

    def add_asset(kind: str, name: str, identity: Mapping[str, Any],
                  attributes: Mapping[str, Any] | None = None) -> str:
        asset = normalize_asset(kind, name, identity=dict(identity), source="aws",
                                attributes=dict(attributes or {}))
        if asset["asset_id"] not in seen:
            seen.add(asset["asset_id"])
            assets.append(asset)
        return asset["asset_id"]

    def link(subject: str, predicate: str, obj: str, evidence_ids: list[str],
             attributes: Mapping[str, Any] | None = None) -> None:
        relationships.append({
            "subject": subject,
            "predicate": predicate,
            "object": obj,
            "basis": "DEPLOYMENT_CONFIG",
            "evidence_ids": evidence_ids,
            "attributes": {"claim": "CONFIGURED", "observed": False, **dict(attributes or {})},
        })

    def blocked_call(label: str, exc: Exception) -> None:
        blocked.append(f"{label}: {exc}")
        limitations.append(f"{label}: {exc} — this resource family is NOT_OBSERVED, not empty")

    # ---- load balancers, listeners, certificates -------------------------- #
    lb_ids: dict[str, str] = {}
    try:
        document = _query_call(resolved, "elasticloadbalancing", "DescribeLoadBalancers",
                               "2015-12-01", None, sender, timeout, label=CALLS["load_balancers"])
        answered.add("load_balancers")
        for node in _members(document, "LoadBalancers", "member")[:max_items]:
            arn = _text(node, "LoadBalancerArn")
            name = _text(node, "LoadBalancerName") or arn or "load-balancer"
            if not arn:
                continue
            asset_id = add_asset("LOAD_BALANCER", name,
                                 {"name": name, "management_address": _text(node, "DNSName")},
                                 {"provider": "AWS", "arn": arn, "type": _text(node, "Type"),
                                  "scheme": _text(node, "Scheme"), "region": resolved["region"]})
            lb_ids[arn] = asset_id
            evidence.append(make_evidence(
                source="aws", evidence_type="CONFIGURED", target=asset_id, layer="NETWORK_TRANSPORT",
                collector="aws:elasticloadbalancing:DescribeLoadBalancers",
                facts={"lb_type": _text(node, "Type"), "scheme": _text(node, "Scheme"),
                       "dns_name": _text(node, "DNSName"), "state": _text(node, "State")},
            ))

        for arn, asset_id in lb_ids.items():
            try:
                listeners = _query_call(
                    resolved, "elasticloadbalancing", "DescribeListeners", "2015-12-01",
                    {"LoadBalancerArn": arn}, sender, timeout, label=CALLS["listeners"])
                answered.add("listeners")
            except PermissionError as exc:
                blocked_call(CALLS["listeners"], exc)
                continue
            except CloudReadError as exc:
                blocked_call(CALLS["listeners"], exc)
                continue
            for listener in _members(listeners, "Listeners", "member")[:max_items]:
                protocol = (_text(listener, "Protocol") or "").upper()
                port = _text(listener, "Port")
                policy = _text(listener, "SslPolicy")
                plaintext = protocol in {"HTTP", "TCP", "UDP"}
                tls_terminating = protocol in {"HTTPS", "TLS"}
                certificate_arns = [item for item in
                                    (_text(member, "CertificateArn")
                                     for member in _members(listener, "Certificates", "member")) if item]
                record = make_evidence(
                    source="aws", evidence_type="CONFIGURED", target=asset_id, layer="NETWORK_TRANSPORT",
                    collector="aws:elasticloadbalancing:DescribeListeners",
                    facts={
                        "listener_protocol": protocol,
                        "port": int(port) if port and port.isdigit() else port,
                        "ssl_policy": policy,
                        # only a TLS listener declares a protocol floor; an HTTP
                        # listener has none, and "" is not an answer
                        "minimum_tls_version_declared": (
                            SSL_POLICY_FLOORS.get(str(policy or ""), "UNKNOWN") if tls_terminating else None
                        ),
                        "certificate_arns": certificate_arns,
                        "plaintext_listener": plaintext,
                        "claim": "CONFIGURED — the listener allows this; nothing here shows what a client "
                                 "negotiated",
                    },
                )
                evidence.append(record)
                for certificate_arn in certificate_arns:
                    certificate_id = add_asset("CERTIFICATE", certificate_arn,
                                               {"fingerprint_sha256": None, "serial_number": None,
                                                "subject": certificate_arn},
                                               {"provider": "AWS", "arn": certificate_arn})
                    link(asset_id, "uses", certificate_id, [record["evidence_id"]],
                         {"meaning": "this listener is configured with this certificate"})

        try:
            listed = _json_call(resolved, "acm", "CertificateManager.ListCertificates", {},
                                sender, timeout, label=CALLS["acm"])
            answered.add("acm")
        except PermissionError as exc:
            listed = {}
            blocked_call(CALLS["acm"], exc)
        except CloudReadError as exc:
            listed = {}
            blocked_call(CALLS["acm"], exc)
        for summary in list(listed.get("CertificateSummaryList") or [])[:max_items]:
            arn = str(summary.get("CertificateArn") or "")
            if not arn:
                continue
            try:
                described = _json_call(resolved, "acm", "CertificateManager.DescribeCertificate",
                                       {"CertificateArn": arn}, sender, timeout,
                                       label="acm:DescribeCertificate").get("Certificate") or {}
            except PermissionError as exc:
                described = {}
                blocked_call(f"acm:DescribeCertificate({arn})", exc)
            except CloudReadError as exc:
                described = {}
                blocked_call(f"acm:DescribeCertificate({arn})", exc)
            domain = str(described.get("DomainName") or summary.get("DomainName") or arn)
            certificate_id = add_asset(
                "CERTIFICATE", domain,
                {"fingerprint_sha256": described.get("Serial"), "serial_number": described.get("Serial"),
                 "subject": domain},
                {"provider": "AWS", "arn": arn, "issuer": described.get("Issuer"),
                 "type": described.get("Type"), "status": described.get("Status"),
                 "in_use_by": list(described.get("InUseBy") or [])},
            )
            evidence.append(make_evidence(
                source="aws", evidence_type="CONFIGURED", target=certificate_id, layer="NETWORK_TRANSPORT",
                collector="aws:acm:DescribeCertificate",
                facts={
                    "public_key_algorithm": described.get("KeyAlgorithm"),
                    "signature_algorithm": described.get("SignatureAlgorithm"),
                    "not_after": str(described.get("NotAfter") or "") or None,
                    "days_until_expiry": _days_until(described.get("NotAfter"), stated_now),
                    "domain": domain,
                    "renewal_eligibility": described.get("RenewalEligibility"),
                    "in_use": bool(described.get("InUseBy")),
                    "claim": "CONFIGURED — this certificate exists and is attached to what the API reports",
                },
            ))
    except PermissionError as exc:
        blocked_call(CALLS["load_balancers"], exc)
    except CloudReadError as exc:
        blocked_call(CALLS["load_balancers"], exc)

    # ---- RDS -------------------------------------------------------------- #
    try:
        document = _query_call(resolved, "rds", "DescribeDBInstances", "2014-10-31", None, sender, timeout,
                               label=CALLS["databases"])
        answered.add("databases")
        for instance in _members(document, "DBInstances", "DBInstance")[:max_items]:
            identifier = _text(instance, "DBInstanceIdentifier") or "database"
            engine = _text(instance, "Engine")
            endpoint = next((node for node in instance.iter() if _localname(node.tag) == "Endpoint"), None)
            host = _text(endpoint, "Address")
            port = _text(endpoint, "Port")
            asset_id = add_asset("DATABASE", identifier,
                                 {"host": host or identifier, "port": port, "engine": engine},
                                 {"provider": "AWS", "instance_class": _text(instance, "DBInstanceClass"),
                                  "multi_az": _flag(instance, "MultiAZ"),
                                  "publicly_accessible": _flag(instance, "PubliclyAccessible")})
            key_id = _text(instance, "KmsKeyId")
            record = make_evidence(
                source="aws", evidence_type="CONFIGURED", target=asset_id, layer="STORAGE",
                collector="aws:rds:DescribeDBInstances",
                facts={
                    "engine": engine,
                    "engine_version": _text(instance, "EngineVersion"),
                    "storage_encrypted": _flag(instance, "StorageEncrypted"),
                    "kms_key_configured": key_id,
                    "ca_certificate": _text(instance, "CACertificateIdentifier"),
                    "publicly_accessible": _flag(instance, "PubliclyAccessible"),
                    "claim": "CONFIGURED — storage encryption is on or off by configuration; the algorithm "
                             "the engine actually uses is not visible from the control plane",
                },
            )
            evidence.append(record)
            if key_id:
                key_asset = add_asset("KMS_KEY", key_id, {"provider": "AWS", "key_id": key_id},
                                      {"provider": "AWS", "key_id": key_id, "discovered_via": "rds"})
                link(asset_id, "uses", key_asset, [record["evidence_id"]],
                     {"meaning": "the instance is configured to use this key"})
    except PermissionError as exc:
        blocked_call(CALLS["databases"], exc)
    except CloudReadError as exc:
        blocked_call(CALLS["databases"], exc)

    # ---- KMS (capability, not usage) -------------------------------------- #
    try:
        listed = _json_call(resolved, "kms", "TrentService.ListKeys", {}, sender, timeout, label=CALLS["kms"])
        answered.add("kms")
        for key in list(listed.get("Keys") or [])[:max_items]:
            key_id = str(key.get("KeyId") or "")
            if not key_id:
                continue
            try:
                described = _json_call(resolved, "kms", "TrentService.DescribeKey", {"KeyId": key_id},
                                       sender, timeout, label="kms:DescribeKey").get("KeyMetadata") or {}
            except PermissionError as exc:
                described = {}
                blocked_call(f"kms:DescribeKey({key_id})", exc)
            except CloudReadError as exc:
                described = {}
                blocked_call(f"kms:DescribeKey({key_id})", exc)
            asset_id = add_asset("KMS_KEY", key_id, {"provider": "AWS", "key_id": key_id},
                                 {"provider": "AWS", "key_manager": described.get("KeyManager"),
                                  "origin": described.get("Origin"), "state": described.get("KeyState")})
            evidence.append(make_evidence(
                source="aws", evidence_type="CONFIGURED", target=asset_id, layer="KMS",
                collector="aws:kms:DescribeKey",
                facts={
                    "key_spec": described.get("KeySpec"),
                    "key_usage": described.get("KeyUsage"),
                    "supported_algorithms_hint": _kms_algorithms(described.get("KeySpec")),
                    "usage_state": "SUPPORTED",
                    "claim": "CAPABILITY — this key can perform this crypto; no evidence here says an "
                             "application used it",
                },
            ))
    except PermissionError as exc:
        blocked_call(CALLS["kms"], exc)
    except CloudReadError as exc:
        blocked_call(CALLS["kms"], exc)

    # ---- API Gateway custom domains --------------------------------------- #
    try:
        payload = _rest_get(resolved, "apigateway", "/domainnames", sender, timeout,
                            label=CALLS["api_gateways"])
        answered.add("api_gateways")
        for item in list(payload.get("items") or [])[:max_items]:
            name = str(item.get("domainName") or "")
            if not name:
                continue
            endpoint_type = str((item.get("endpointConfiguration") or {}).get("types") or "UNKNOWN")
            asset_id = add_asset("API_GATEWAY", name,
                                 {"name": name, "management_address": item.get("regionalHostedZoneId")},
                                 {"provider": "AWS", "endpoint_type": endpoint_type,
                                  "security_policy": item.get("securityPolicy")})
            evidence.append(make_evidence(
                source="aws", evidence_type="CONFIGURED", target=asset_id, layer="NETWORK_TRANSPORT",
                collector="aws:apigateway:GetDomainNames",
                facts={
                    "security_policy": item.get("securityPolicy"),
                    "minimum_tls_version_declared": _apigw_floor(item.get("securityPolicy")),
                    "endpoint_type": endpoint_type,
                    "claim": "CONFIGURED — the domain's minimum TLS policy, not an observed handshake",
                },
            ))
    except PermissionError as exc:
        blocked_call(CALLS["api_gateways"], exc)
    except CloudReadError as exc:
        blocked_call(CALLS["api_gateways"], exc)

    return {
        "schema": SCHEMA,
        "plane": PLANE,
        "provider": "AWS",
        "region": resolved.get("region"),
        "credential_source": resolved.get("source"),
        "expected": len(CALLS),
        "collected": len(answered),
        "answered": sorted(answered),
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "blocked": blocked,
        "note": (
            "managed-service configuration only: nothing here is a negotiated parameter or an application's own "
            "cryptography"
        ),
        "limitations": limitations,
    }


def _kms_algorithms(key_spec: Any) -> list[str]:
    """Algorithms a key spec can perform — a capability list, never a usage claim."""
    spec = str(key_spec or "").upper()
    if spec == "SYMMETRIC_DEFAULT":
        return ["AES-256-GCM"]
    if spec.startswith("AES_"):
        return [f"AES-{spec.replace('AES_', '')}-GCM"]
    if spec.startswith("RSA_"):
        bits = spec.replace("RSA_", "")
        return [f"RSA-{bits}-OAEP", f"RSA-{bits}-PSS"]
    if spec.startswith("ECC_"):
        return [f"ECDSA-{spec.replace('ECC_', '')}"]
    return []


def _apigw_floor(policy: Any) -> str:
    value = str(policy or "").upper()
    if value == "TLS_1_2":
        return "TLSv1.2"
    if value == "TLS_1_3":
        return "TLSv1.3"
    if value == "TLS_1_0":
        return "TLSv1.0"
    return "UNKNOWN"
