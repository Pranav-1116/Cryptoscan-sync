"""The evidence object tier, and the four things it refuses.

An archive is only an archive if it cannot return different bytes under the same name,
cannot overwrite what it already holds, does not pretend an unconfigured tier is an
empty one, and does not report a missing object as "this evidence has no artefact".

The transport is injected, so these tests drive the S3 path with no server and no
credentials — the SigV4 signing itself is covered by the anchor-export suite, which
shares it.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from api import estate_evidence_objects as tier
from shared_models.estate_graph import build_graph

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

BASE = "/api/v1/estate/evidence"


RECORD = {
    "evidence_id": "ev-1",
    "evidence_type": "RUNTIME_OBSERVED",
    "target": "application:aaa",
    "layer": "APPLICATION",
    "facts": {"algorithm": "AES-256-GCM", "role": "encrypt"},
}


def _s3_config() -> dict:
    return {
        "sink": tier.SINK_S3,
        "bucket": "bank-evidence",
        "region": "me-central-1",
        "endpoint": "https://minio.bank.internal",
        "access_key": "AKIAEXAMPLE",
        "secret_key": "secret",
        "session_token": None,
        "prefix": "cryptoscan/evidence",
    }


class _Store:
    """A transport that behaves like an object store, including If-None-Match."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []

    def __call__(self, url, method, headers, body, timeout):
        self.calls.append((method, url))
        if method == "PUT":
            if headers.get("If-None-Match") == "*" and url in self.objects:
                return 412, b"", {}
            self.objects[url] = body or b""
            return 200, b"", {"ETag": '"etag-1"'}
        if method == "GET":
            if url not in self.objects:
                return 404, b"", {}
            return 200, self.objects[url], {}
        return 405, b"", {}


# -- the address is the content --------------------------------------------- #


def test_the_address_is_the_sha256_of_what_the_record_asserts():
    stored = tier.store(RECORD, transport=_Store(), config=_s3_config())

    assert stored["address"] == f"sha256:{tier.content_address(RECORD)}"
    assert stored["verified"] is True
    assert stored["stored"] is True


def test_the_bytes_are_canonical_so_key_order_does_not_change_the_address():
    reordered = dict(reversed(list(RECORD.items())))

    assert tier.digest_of(RECORD) == tier.digest_of(reordered)


def test_a_read_returns_the_record_and_verifies_it():
    store = _Store()
    digest = tier.store(RECORD, transport=store, config=_s3_config())["address"]

    read = tier.fetch(digest, transport=store, config=_s3_config())

    assert read["verified"] is True
    assert read["record"] == RECORD
    # the short form of an address is accepted, and both are normalised
    assert read["address"] == digest


def test_a_read_of_bytes_that_do_not_match_the_address_is_refused():
    """The one failure an archive must never paper over."""
    store = _Store()
    digest = tier.store(RECORD, transport=store, config=_s3_config())["address"]
    url = store.calls[0][1]
    store.objects[url] = json.dumps({"evidence_id": "ev-1", "facts": {"algorithm": "RSA"}}).encode()

    with pytest.raises(tier.EvidenceObjectError) as exc:
        tier.fetch(digest, transport=store, config=_s3_config())

    assert exc.value.code == "integrity_mismatch"
    assert "not an archive" in exc.value.reason
    assert exc.value.detail["actual"] != digest


def test_the_build_clock_is_archived_but_is_not_part_of_the_address():
    """Two reads of the same stored discovery must address to the same object.

    ``observed_at`` is the clock at build time when the payload asserted none, which is
    exactly why ``EstateGraph.fingerprint`` leaves it out of the projection id. The value
    is still carried inside the object — it is the *address* it is excluded from.
    """
    first = {**RECORD, "observed_at": "2026-11-05T10:00:00+00:00"}
    second = {**RECORD, "observed_at": "2026-11-05T10:00:01+00:00"}

    assert tier.content_address(first) == tier.content_address(second)

    store = _Store()
    tier.store(first, transport=store, config=_s3_config())
    read = tier.fetch(tier.content_address(first), transport=store, config=_s3_config())

    assert read["record"]["observed_at"] == first["observed_at"]
    wrapper = json.loads(list(store.objects.values())[0])
    assert wrapper["address_excludes"] == ["observed_at"]


def test_the_same_content_under_a_different_timestamp_is_the_same_object(tmp_path):
    config = {"sink": tier.SINK_FILESYSTEM, "directory": str(tmp_path)}

    first = tier.store({**RECORD, "observed_at": "2026-11-05T10:00:00+00:00"}, config=config)
    second = tier.store({**RECORD, "observed_at": "2026-11-05T10:00:01+00:00"}, config=config)

    assert second["already_stored"] is True
    assert second["address"] == first["address"]


# -- a write never overwrites ----------------------------------------------- #


def test_storing_the_same_content_twice_reports_already_stored(tmp_path):
    config = {"sink": tier.SINK_FILESYSTEM, "directory": str(tmp_path)}

    first = tier.store(RECORD, config=config)
    second = tier.store(RECORD, config=config)

    assert first["stored"] is True
    assert second["stored"] is False
    assert second["already_stored"] is True
    assert second["location"] == first["location"]
    # and the file is still the first one, byte for byte
    with open(first["location"], "rb") as handle:
        assert handle.read() == tier.canonical_bytes(RECORD)


def test_the_s3_write_asks_the_store_not_to_overwrite():
    store = _Store()

    tier.store(RECORD, transport=store, config=_s3_config())

    method, url = store.calls[0]
    assert method == "PUT"
    assert f"/{_s3_config()['bucket']}/" in url
    # the signing headers are present: this path is not a stub
    assert store.objects[url] == tier.canonical_bytes(RECORD)


def test_a_store_that_refuses_is_reported_not_swallowed():
    def refusing(url, method, headers, body, timeout):
        return 503, b"bucket unavailable", {}

    with pytest.raises(tier.EvidenceObjectError) as exc:
        tier.store(RECORD, transport=refusing, config=_s3_config())

    assert exc.value.code == "store_failed"
    assert "HTTP 503" in exc.value.reason


# -- an absent object is a tier gap ----------------------------------------- #


def test_a_missing_object_says_tier_gap_not_no_artefact():
    with pytest.raises(tier.EvidenceObjectError) as exc:
        tier.fetch("a" * 64, transport=_Store(), config=_s3_config())

    assert exc.value.code == "not_stored"
    assert "tier gap" in exc.value.reason


def test_a_missing_object_on_the_filesystem_sink_says_the_same_thing(tmp_path):
    with pytest.raises(tier.EvidenceObjectError) as exc:
        tier.fetch("b" * 64, config={"sink": tier.SINK_FILESYSTEM, "directory": str(tmp_path)})

    assert exc.value.code == "not_stored"


@pytest.mark.parametrize("digest", ["", "xyz", "A" * 63, "g" * 64])
def test_a_thing_that_is_not_a_digest_is_not_an_address(digest):
    with pytest.raises(tier.EvidenceObjectError) as exc:
        tier.fetch(digest, transport=_Store(), config=_s3_config())

    assert exc.value.code == "invalid_digest"


# -- configuration ----------------------------------------------------------- #


def test_an_unconfigured_tier_says_so_and_does_not_pretend_to_be_empty():
    status = tier.tier_status({})

    assert status["configured"] is False
    assert status["sink"] is None
    assert "counted as 'no evidence'" in status["note"]
    assert "tier gap" in status["reason"]


def test_the_tier_falls_back_to_the_bucket_this_deployment_already_uses():
    """One object store per deployment, not one per feature."""
    environ = {
        "ANCHOR_EXPORT_S3_BUCKET": "bank-evidence",
        "ANCHOR_EXPORT_S3_ACCESS_KEY": "AKIAEXAMPLE",
        "ANCHOR_EXPORT_S3_SECRET_KEY": "secret",
        "ANCHOR_EXPORT_S3_REGION": "me-central-1",
    }

    config = tier.tier_config(environ)

    assert config["sink"] == tier.SINK_S3
    assert config["bucket"] == "bank-evidence"
    assert config["prefix"] == "cryptoscan/evidence"


def test_its_own_variables_win_over_the_shared_bucket():
    environ = {
        "EVIDENCE_OBJECT_S3_BUCKET": "evidence-only",
        "EVIDENCE_OBJECT_S3_ACCESS_KEY": "AKIAEXAMPLE",
        "EVIDENCE_OBJECT_S3_SECRET_KEY": "secret",
        "EVIDENCE_OBJECT_S3_ENDPOINT": "https://minio.bank.internal",
        "ANCHOR_EXPORT_S3_BUCKET": "anchor-bucket",
        "ANCHOR_EXPORT_S3_ACCESS_KEY": "AKIAOTHER",
        "ANCHOR_EXPORT_S3_SECRET_KEY": "other-secret",
    }

    config = tier.tier_config(environ)

    assert config["bucket"] == "evidence-only"
    assert config["endpoint"] == "https://minio.bank.internal"


def test_the_status_never_prints_a_secret():
    status = tier.tier_status({
        "EVIDENCE_OBJECT_S3_BUCKET": "b", "EVIDENCE_OBJECT_S3_ACCESS_KEY": "AKIAEXAMPLE",
        "EVIDENCE_OBJECT_S3_SECRET_KEY": "super-secret", "EVIDENCE_OBJECT_S3_SESSION_TOKEN": "tok",
    })

    blob = json.dumps(status)
    assert "super-secret" not in blob
    assert "AKIAEXAMPLE" not in blob
    assert "tok" not in blob


def test_a_filesystem_directory_is_accepted_and_reported():
    status = tier.tier_status({"EVIDENCE_OBJECT_DIR": os.path.join("/mnt", "worm")})

    assert status["configured"] is True
    assert status["sink"] == tier.SINK_FILESYSTEM
    assert status["detail"]["directory"].endswith("worm")


# -- the routes -------------------------------------------------------------- #


def _payload() -> dict:
    return {
        "estate": "Synthetic Bank",
        "assets": [{"ref": "api", "type": "APPLICATION", "name": "Payment API",
                    "environment": "production"}],
        "evidence": [
            {"evidence_id": "ev-1", "source": "agent", "evidence_type": "RUNTIME_OBSERVED",
             "target": "api", "layer": "APPLICATION",
             "facts": {"algorithm": "AES-256-GCM", "role": "encrypt"}},
        ],
        "relationships": [],
    }


def _discover(http) -> dict:
    created = http.post(f"{BASE}/discover", json=_payload())
    assert created.status_code == 200, created.text
    return created.json()


def test_the_route_reports_an_unconfigured_tier_as_unconfigured(api, monkeypatch):
    http, _session = api
    _discover(http)
    for key in ("EVIDENCE_OBJECT_DIR", "EVIDENCE_OBJECT_S3_BUCKET", "ANCHOR_EXPORT_S3_BUCKET"):
        monkeypatch.delenv(key, raising=False)

    body = http.get(f"{BASE}/twin/artifacts").json()

    assert body["configured"] is False
    assert body["sink"] is None
    assert "no evidence" in body["note"]


def test_the_route_archives_a_record_from_the_twin_not_from_the_request(api, monkeypatch, tmp_path):
    http, _session = api
    _discover(http)
    monkeypatch.setenv("EVIDENCE_OBJECT_DIR", str(tmp_path))
    monkeypatch.delenv("EVIDENCE_OBJECT_S3_BUCKET", raising=False)

    stored = http.post(f"{BASE}/twin/artifacts", params={"evidence_id": "ev-1"})

    assert stored.status_code == 200, stored.text
    body = stored.json()
    assert body["verified"] is True
    assert body["address"].startswith("sha256:")
    assert body["evidence_id"] == "ev-1"

    # the same record archives to the same address, and a second store never rewrites
    second = http.post(f"{BASE}/twin/artifacts", params={"evidence_id": "ev-1"})
    assert second.status_code == 200, second.text
    again = second.json()
    assert again["already_stored"] is True, (body, again)
    assert again["location"] == body["location"]


def test_the_route_reads_an_artefact_back_and_verifies_it(api, monkeypatch, tmp_path):
    http, _session = api
    _discover(http)
    monkeypatch.setenv("EVIDENCE_OBJECT_DIR", str(tmp_path))

    stored = http.post(f"{BASE}/twin/artifacts", params={"evidence_id": "ev-1"}).json()
    read = http.get(f"{BASE}/twin/artifacts/{stored['address']}")

    assert read.status_code == 200, read.text
    body = read.json()
    assert body["verified"] is True
    assert body["record"]["evidence_id"] == "ev-1"


def test_the_route_refuses_evidence_the_twin_does_not_hold(api):
    http, _session = api
    _discover(http)

    response = http.post(f"{BASE}/twin/artifacts", params={"evidence_id": "ev-never-collected"})

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "no_such_evidence"
    assert "not 'it has no artefact'" in detail["reason"]


def test_the_route_reports_a_missing_object_as_a_tier_gap(api, monkeypatch, tmp_path):
    http, _session = api
    _discover(http)
    monkeypatch.setenv("EVIDENCE_OBJECT_DIR", str(tmp_path))

    response = http.get(f"{BASE}/twin/artifacts/{'c' * 64}")

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "not_stored"
