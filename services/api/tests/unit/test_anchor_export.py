"""External anchor export: SigV4 correctness, write-once sinks, honest failures (spec 67 §31).

The point of these tests is that "external" is a claim about a *confirmed write to
somebody else's storage*, so the checks are: the signature is the one AWS documents,
the sink is never overwritten, and an unconfirmed or unconfigured export never
reports ``external: true``.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from api.security import anchor_export

RECEIPT = {
    "anchor_id": "anc_0123456789abcdef",
    "projection_id": "proj_abc",
    "tenant_id": "bank-a",
    "boms": {"SBOM": {"digest": "sha256:aa"}},
    "signature": "deadbeef",
}


# --------------------------------------------------------------------------- #
# SigV4 against the published AWS test vector
# --------------------------------------------------------------------------- #
def test_sigv4_matches_the_documented_aws_example():
    from datetime import datetime, timezone

    headers = anchor_export.sigv4_headers(
        method="GET",
        url="https://examplebucket.s3.amazonaws.com/test.txt",
        body=b"",
        region="us-east-1",
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        extra_headers={"range": "bytes=0-9"},
        now=datetime(2013, 5, 24, tzinfo=timezone.utc),
    )
    assert headers["authorization"] == (
        "AWS4-HMAC-SHA256 "
        "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    )


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def test_no_sink_configured_is_an_error_not_a_pretend_anchor():
    with pytest.raises(anchor_export.AnchorExportError) as caught:
        anchor_export.sink_config({})
    assert caught.value.code == "anchor_export_not_configured"
    assert "not external" in caught.value.reason
    assert anchor_export.sink_status({})["configured"] is False


def test_s3_config_never_leaks_the_secret_in_status():
    status = anchor_export.sink_status({
        "ANCHOR_EXPORT_S3_BUCKET": "bank-evidence",
        "ANCHOR_EXPORT_S3_ACCESS_KEY": "AKIAEXAMPLE",
        "ANCHOR_EXPORT_S3_SECRET_KEY": "super-secret",
        "ANCHOR_EXPORT_S3_REGION": "eu-west-1",
    })
    assert status["configured"] is True and status["sink"] == "S3"
    assert "super-secret" not in json.dumps(status)
    assert status["detail"]["bucket"] == "bank-evidence"


# --------------------------------------------------------------------------- #
# S3 sink
# --------------------------------------------------------------------------- #
def _s3_config(**overrides):
    config = {
        "sink": anchor_export.SINK_S3,
        "bucket": "bank-evidence",
        "region": "eu-west-1",
        "endpoint": "https://s3.eu-west-1.amazonaws.com",
        "access_key": "AKIAEXAMPLE",
        "secret_key": "secret",
        "session_token": None,
        "prefix": "cryptoscan/anchors",
        "object_lock": True,
        "retention_days": 30,
    }
    config.update(overrides)
    return config


def test_s3_export_puts_the_receipt_under_object_lock():
    calls: list[dict] = []

    def transport(url, method, headers, body, timeout):
        calls.append({"url": url, "method": method, "headers": dict(headers), "body": body})
        return 200, b"", {"ETag": '"abc123"', "x-amz-version-id": "v7"}

    result = anchor_export.export_receipt(RECEIPT, config=_s3_config(), transport=transport)

    assert len(calls) == 1
    call = calls[0]
    assert call["method"] == "PUT"
    assert call["url"].endswith("/bank-evidence/cryptoscan/anchors/anc_0123456789abcdef.json")
    assert call["headers"]["If-None-Match"] == "*"
    assert call["headers"]["x-amz-object-lock-mode"] == "COMPLIANCE"
    assert call["headers"]["x-amz-object-lock-retain-until-date"]
    assert call["headers"]["authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert json.loads(call["body"])["anchor_id"] == RECEIPT["anchor_id"]

    assert result["external"] is True
    assert result["sink"] == "S3"
    assert result["object_version"] == "v7"
    assert result["content_sha256"] == hashlib.sha256(call["body"]).hexdigest()
    assert "does not prove the facts" in result["boundary"]


def test_s3_refusal_is_reported_as_already_exported():
    result = anchor_export.AnchorExportError
    with pytest.raises(result) as caught:
        anchor_export.export_receipt(
            RECEIPT, config=_s3_config(), transport=lambda *a: (412, b"<Error/>", {}))
    assert caught.value.code == "already_exported"
    assert "never overwrites" in caught.value.reason


def test_s3_server_error_does_not_claim_external():
    with pytest.raises(anchor_export.AnchorExportError) as caught:
        anchor_export.export_receipt(
            RECEIPT, config=_s3_config(), transport=lambda *a: (500, b"boom", {}))
    assert caught.value.code == "anchor_export_failed"
    assert "HTTP 500" in caught.value.reason


# --------------------------------------------------------------------------- #
# filesystem sink (append-only)
# --------------------------------------------------------------------------- #
def test_filesystem_sink_writes_once_and_refuses_a_second_write(tmp_path):
    config = {"sink": anchor_export.SINK_FILESYSTEM, "directory": str(tmp_path)}
    first = anchor_export.export_receipt(RECEIPT, config=config)
    assert first["external"] is True
    assert first["location"].startswith("file://")
    assert (tmp_path / f"{RECEIPT['anchor_id']}.json").exists()

    with pytest.raises(anchor_export.AnchorExportError) as caught:
        anchor_export.export_receipt(RECEIPT, config=config)
    assert caught.value.code == "already_exported"
    # the original receipt is untouched
    stored = json.loads((tmp_path / f"{RECEIPT['anchor_id']}.json").read_text())
    assert stored["projection_id"] == RECEIPT["projection_id"]


# --------------------------------------------------------------------------- #
# webhook sink (HMAC-signed)
# --------------------------------------------------------------------------- #
def test_webhook_body_is_signed_with_the_shared_key():
    seen: dict = {}

    def transport(url, method, headers, body, timeout):
        seen.update({"url": url, "method": method, "headers": dict(headers), "body": body})
        return 202, b'{"ok":true}', {"X-Request-Id": "req-9"}

    result = anchor_export.export_receipt(
        RECEIPT, config={"sink": anchor_export.SINK_WEBHOOK, "url": "https://siem.bank/anchor",
                         "key": "shared"}, transport=transport)

    expected = hmac.new(b"shared", seen["body"], hashlib.sha256).hexdigest()
    assert seen["headers"]["X-CryptoScan-Signature"] == f"sha256={expected}"
    assert seen["headers"]["X-CryptoScan-Anchor-Id"] == RECEIPT["anchor_id"]
    assert result["receiver_reference"] == "req-9"
    assert result["external"] is True


def test_webhook_rejection_is_a_failure():
    with pytest.raises(anchor_export.AnchorExportError) as caught:
        anchor_export.export_receipt(
            RECEIPT, config={"sink": anchor_export.SINK_WEBHOOK, "url": "https://siem.bank/anchor",
                             "key": "shared"},
            transport=lambda *a: (401, b"denied", {}))
    assert caught.value.code == "anchor_export_failed"
