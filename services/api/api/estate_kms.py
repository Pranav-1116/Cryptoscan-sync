"""KMS *usage* observation from the provider's own audit trail (spec 67 §21, spec 93 §13).

"A KMS key supports AES-256" is capability. The question a bank actually asks is
"who encrypted with it, and when", and the only honest source for that is the
provider's audit log: CloudTrail records the ``Encrypt``, ``Decrypt``,
``GenerateDataKey``, ``Sign`` and ``Verify`` calls that really happened, with the
principal that made them.

So this plane reads CloudTrail ``LookupEvents`` filtered to ``kms.amazonaws.com``
and emits, per key:

* ``AUDIT_OBSERVED`` evidence at the KMS layer with the operation counts, the
  principals, and the first/last time the key was used — this is *use*, not
  capability, and it is the strongest evidence the estate can carry short of
  instrumenting the calling process;
* a ``uses`` edge from each calling principal to the key, on the
  ``RUNTIME_OBSERVATION`` basis (an observed call at runtime, recorded by the
  provider), never on a guess from a key policy;
* for a key that was **not** observed in the window: no evidence of use at all,
  reported as ``NOT_OBSERVED_IN_WINDOW`` with the window stated. Not observing a
  call is not proof that none happened, and the record says exactly that.

Refusals and limits:

* ``AccessDenied`` on CloudTrail ⇒ ``blocked`` + ``PARTIAL``: we were not allowed
  to look at the trail, so usage is unknown, not zero;
* an audit trail only holds the retention window (90 days by default) — the
  window used is reported, and a key last used before it is ``NOT_OBSERVED``;
* the event cap (``max_events``) is reported when reached, so a truncated read is
  never presented as a complete one.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from api.estate_planes import PlaneNotConfigured  # re-exported: the plane's marker
from api.security.aws_http import AwsHttpError, default_transport, send_signed
from shared_models.estate_graph import make_evidence, normalize_asset

__all__ = ["PLANE", "SCHEMA", "PlaneNotConfigured", "collect_kms_usage", "kms_config"]

SCHEMA = "cryptoscan.estate-kms-usage/1"
PLANE = "KMS"
SERVICE = "cloudtrail"
TARGET_PREFIX = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"

#: KMS API calls that mean the key was *used* for crypto. CreateKey/Tag/Describe
#: are deliberately absent: administration is not use.
USAGE_OPERATIONS = frozenset({
    "encrypt", "decrypt", "reencrypt", "generatedatakey", "generatedatakeywithoutplaintext",
    "generatedatakeypair", "generatedatakeypairwithoutplaintext", "sign", "verify",
    "generateMac", "verifymac", "generaterandom", "deriveSharedSecret",
})

Transport = Callable[[str, str, Mapping[str, str], "bytes | None", float], tuple[int, bytes]]


class KmsReadError(AwsHttpError):
    """The audit trail answered, but not with data we can use."""


def kms_config(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """AWS credentials for the audit read (the same shape the cloud plane uses)."""
    from api.estate_cloud import cloud_config

    config = cloud_config(environ)
    config["source"] = config.get("source") or "ENVIRONMENT"
    return config


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _events_call(
    config: Mapping[str, Any],
    *,
    start: datetime,
    end: datetime,
    max_results: int,
    next_token: str | None,
    transport: Transport,
    timeout: float,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "LookupAttributes": [{"AttributeKey": "EventSource", "AttributeValue": "kms.amazonaws.com"}],
        "StartTime": int(start.timestamp()),
        "EndTime": int(end.timestamp()),
        "MaxResults": int(max_results),
    }
    if next_token:
        payload["NextToken"] = next_token
    body = json.dumps(payload).encode("utf-8")
    raw = send_signed(
        config,
        SERVICE,
        method="POST",
        path="/",
        query="",
        body=body,
        headers={
            "content-type": "application/x-amz-json-1.1",
            # confirmed against botocore's cloudtrail model (targetPrefix)
            "x-amz-target": f"{TARGET_PREFIX}.LookupEvents",
        },
        transport=transport,
        timeout=timeout,
        label="cloudtrail:LookupEvents",
    )
    try:
        return json.loads(raw or b"{}")
    except ValueError as exc:
        raise KmsReadError("cloudtrail:LookupEvents: unparseable JSON") from exc


def _principal(event: Mapping[str, Any], detail: Mapping[str, Any]) -> str:
    """Who made the call: the CloudTrail detail first, the summary fields second."""
    identity = detail.get("userIdentity") or {}
    arn = identity.get("arn") or identity.get("principalId")
    if arn:
        return str(arn)
    session = identity.get("sessionContext") or {}
    issuer = (session.get("sessionIssuer") or {}).get("arn")
    if issuer:
        return str(issuer)
    return str(event.get("Username") or event.get("AccessKeyId") or "UNKNOWN")


def _key_id(detail: Mapping[str, Any]) -> str | None:
    params = detail.get("requestParameters") or {}
    for field in ("keyId", "keyArn", "resourceArn"):
        value = params.get(field)
        if value:
            return str(value)
    for resource in detail.get("resources") or []:
        if str(resource.get("type") or resource.get("ResourceType") or "").upper() == "AWS::KMS::KEY":
            name = resource.get("ARN") or resource.get("ResourceName") or resource.get("name")
            if name:
                return str(name)
    return None


def collect_kms_usage(
    _db: Any = None,
    *,
    transport: Transport | None = None,
    config: Mapping[str, Any] | None = None,
    timeout: float = 20.0,
    window_hours: int = 24,
    max_events: int = 1000,
    page_size: int = 50,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Read key *usage* from CloudTrail for the last ``window_hours``."""
    resolved = dict(config) if config else kms_config()
    resolved.setdefault("source", "INJECTED")
    sender = transport or default_transport
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(hours=max(1, int(window_hours)))

    assets: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    blocked: list[str] = []
    limitations: list[str] = [
        f"usage is read from CloudTrail for {_iso(start)} … {_iso(end)}; a key whose last call is older than "
        f"the trail's retention is NOT_OBSERVED here, not unused",
        "administration calls (CreateKey, DescribeKey, PutKeyPolicy) are not usage and are excluded",
    ]
    answered: set[str] = set()
    usage: dict[str, dict[str, Any]] = {}
    tokens: set[str] = set()
    episodes = 0
    truncated = False

    seen_events = 0
    token: str | None = None
    while True:
        try:
            page = _events_call(resolved, start=start, end=end, max_results=page_size,
                                next_token=token, transport=sender, timeout=timeout)
            answered.add("cloudtrail")
        except PermissionError as exc:
            blocked.append(f"cloudtrail:LookupEvents: {exc}")
            limitations.append(
                "cloudtrail:LookupEvents was denied — KMS usage is NOT_OBSERVED, not zero; the key set is "
                "capability only"
            )
            break
        except (KmsReadError, AwsHttpError) as exc:
            blocked.append(str(exc))
            limitations.append(f"cloudtrail:LookupEvents: {exc} — KMS usage is NOT_OBSERVED")
            break

        events = page.get("Events") or []
        for event in events:
            seen_events += 1
            raw_detail = event.get("CloudTrailEvent")
            detail: Mapping[str, Any] = {}
            if isinstance(raw_detail, str) and raw_detail.strip():
                try:
                    detail = json.loads(raw_detail)
                except ValueError:
                    detail = {}
            operation = str(detail.get("eventName") or event.get("EventName") or "").strip()
            if operation.lower() not in {item.lower() for item in USAGE_OPERATIONS}:
                continue
            key_id = _key_id(detail) or next(
                (str(resource.get("ResourceName") or resource.get("name"))
                 for resource in (event.get("Resources") or [])
                 if str(resource.get("ResourceType") or resource.get("type") or "").upper() == "AWS::KMS::KEY"),
                None,
            )
            if not key_id:
                continue
            moment = str(detail.get("eventTime") or event.get("EventTime") or "")
            principal = _principal(event, detail)
            bucket = usage.setdefault(key_id, {"operations": {}, "principals": {}, "first": None,
                                               "last": None, "events": 0})
            bucket["operations"][operation] = bucket["operations"].get(operation, 0) + 1
            bucket["principals"][principal] = bucket["principals"].get(principal, 0) + 1
            bucket["events"] += 1
            if moment:
                bucket["first"] = min(filter(None, [bucket["first"], moment]))
                bucket["last"] = max(filter(None, [bucket["last"], moment]))
            if str(detail.get("sourceIPAddress") or event.get("SourceIPAddress") or ""):
                bucket.setdefault("source_ips", set()).add(
                    str(detail.get("sourceIPAddress") or event.get("SourceIPAddress")))

        token = page.get("NextToken")
        if not events or not token or token in tokens or seen_events >= max_events:
            truncated = bool(token) and seen_events >= max_events
            break
        tokens.add(token)
        episodes += 1
        if episodes > 100:  # a pathological trail must not become an infinite loop
            limitations.append("event pagination stopped after 100 pages — the window is PARTIAL")
            break

    if truncated:
        limitations.append(
            f"the {max_events}-event cap was reached — usage beyond it was NOT read; this window is PARTIAL"
        )
    if not usage and "cloudtrail" in answered:
        limitations.append(
            "no KMS usage event was recorded in the window — that is (NOT_OBSERVED_IN_WINDOW), not proof the "
            "keys are unused"
        )

    def add_asset(kind: str, name: str, identity: Mapping[str, Any],
                  attributes: Mapping[str, Any] | None = None) -> str:
        asset = normalize_asset(kind, name, identity=dict(identity), source="aws",
                                attributes=dict(attributes or {}))
        assets.append(asset)
        return asset["asset_id"]

    for key_id, bucket in sorted(usage.items()):
        short = key_id.rsplit("/", 1)[-1]
        key_asset = add_asset("KMS_KEY", key_id, {"provider": "AWS", "key_id": key_id},
                              {"provider": "AWS", "discovered_via": "cloudtrail"})
        principal_ids: dict[str, str] = {}
        for principal in sorted(bucket["principals"]):
            principal_ids[principal] = add_asset(
                "SERVICE", principal, {"name": principal},
                {"principal": principal, "provider": "AWS", "discovered_via": "cloudtrail"},
            )
        record = make_evidence(
            source="aws",
            evidence_type="AUDIT_OBSERVED",
            target=key_asset,
            layer="KMS",
            collector="aws:cloudtrail:LookupEvents",
            facts={
                "usage_state": "OBSERVED",
                "key_id": key_id,
                "key_short_id": short,
                "operations": dict(sorted(bucket["operations"].items())),
                "call_count": bucket["events"],
                "principals": dict(sorted(bucket["principals"].items())),
                "source_ips": sorted(bucket.get("source_ips") or []),
                "first_observed": bucket["first"],
                "last_observed": bucket["last"],
                "window": {"start": _iso(start), "end": _iso(end), "hours": int(window_hours)},
                "claim": (
                    "AUDIT_OBSERVED — the provider recorded these calls to this key in this window; this is "
                    "use, not capability"
                ),
            },
        )
        evidence.append(record)
        for principal, asset_id in principal_ids.items():
            relationships.append({
                "subject": asset_id,
                "predicate": "uses",
                "object": key_asset,
                "basis": "RUNTIME_OBSERVATION",
                "evidence_ids": [record["evidence_id"]],
                "attributes": {
                    "claim": "OBSERVED",
                    "observed": True,
                    "calls": bucket["principals"][principal],
                    "operations": sorted(bucket["operations"]),
                    "note": "an audit-log record of a call this principal made to this key",
                },
            })

    return {
        "schema": SCHEMA,
        "plane": PLANE,
        "provider": "AWS",
        "region": resolved.get("region"),
        "credential_source": resolved.get("source"),
        "window": {"start": _iso(start), "end": _iso(end), "hours": int(window_hours)},
        "expected": 1,
        "collected": len(answered),
        "answered": sorted(answered),
        "assets": assets,
        "evidence": evidence,
        "relationships": relationships,
        "blocked": blocked,
        "usage_observed": len(usage),
        "events_examined": seen_events,
        "note": (
            "KMS usage from the provider audit trail: which key, which principal, how many calls, over the "
            "stated window"
        ),
        "limitations": limitations,
    }
