"""Guide 182 — live drivers, evidence store, facades, observation windows, resolvers.

Guide 181 proved the *shape* of the layer (a vendor adapter, a normalised row, a proof per
claim). This file proves the things that only appear once the layer is pointed at a real
estate:

* a read that fails is a state, never an exception and never an empty success;
* a hash-chained store can tell a deleted record from an edited one;
* a facade cannot re-read a device and cannot invent a relation the model does not have;
* an observation is compared with a limit using the limiter's own arithmetic, and refused when
  the two windows are not the same interval;
* a correlation is not allowed to describe 09:14 with a 06:00 inventory.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import json

import pytest

from cbom import security_controls as sc
from cbom import techbom
from cbom.security_controls import drivers, store, transport


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def test_transport_allows_reads_only():
    """A layer that integrates cannot write; the allow-list is where that is enforced."""
    http = sc.HttpTransport(base_url="https://fw",
                            credential=sc.Credential("t", source="test"))
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(sc.ControlRefused) as refused:
            http.request(verb, "/api/v2/cmdb/firewall/policy")
        assert refused.value.code == "NOT_READ_ONLY"


def test_transport_refuses_plaintext():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.HttpTransport(base_url="http://fw")
    assert refused.value.code == "TLS_REQUIRED"


def test_transport_refuses_unverified_tls():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.HttpTransport(base_url="https://fw", verify=False)
    assert refused.value.code == "TLS_VERIFICATION_REQUIRED"


def test_unreachable_is_a_state_not_an_exception():
    result = sc.RecordedTransport({}).get("/api/v2/monitor")
    assert result.state in {"UNREACHABLE", "BAD_RESPONSE"}
    assert not result.ok
    assert result.reason


def test_unreadable_success_response_is_bad_response_not_an_empty_success():
    class Response:
        status_code = 200
        headers = {}

        def json(self):
            raise ValueError("test-only invalid JSON")

        @property
        def text(self):
            raise OSError("test-only unreadable body")

    class Client:
        def request(self, *args, **kwargs):
            return Response()

        def close(self):
            pass

    device = sc.HttpTransport(base_url="https://device.bank.invalid", max_retries=0,
                              _client_factory=Client)
    result = device.get("/api/status")
    assert result.state == "BAD_RESPONSE"
    assert result.ok is False
    assert "unreadable" in result.reason


def test_recorded_transport_reports_a_missing_route():
    result = sc.RecordedTransport({}).get("/x")
    assert result.state == "BAD_RESPONSE"
    assert result.status == 404


def test_link_header_parses_next_page():
    result = transport.TransportResult(url="/api", state="OK", status=200, body={},
                                       link='<https://fw/api?page=2>; rel="next"')
    assert transport._next_link(result, "link") == "https://fw/api?page=2"
    assert transport._next_link(transport.TransportResult(url="/api", state="OK", body={}),
                                "link") is None


# --------------------------------------------------------------------------- #
# drivers
# --------------------------------------------------------------------------- #

def test_every_read_control_has_a_driver():
    dialect = set(drivers.DRIVERS)
    assert {key.split(".")[0] for key in dialect} >= {"firewall", "ids", "ips",
                                                     "load_balancer", "api_gateway", "siem"}
    assert {"firewall.fortigate", "ids.suricata"} <= dialect


def test_an_unknown_dialect_gets_a_refusal_not_a_guess():
    with pytest.raises(sc.ControlRefused) as refused:
        drivers.driver_for("firewall.cisco-asa", sc.RecordedTransport({}))
    assert refused.value.code == "NO_LIVE_DRIVER"


def test_live_snapshot_carries_the_read_it_did():
    """One unreachable device is a read that failed, not an empty success."""
    snapshot = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({}),
                                system="FW-EDGE-01")
    assert snapshot["read"]["state"] in {"UNREACHABLE", "PARTIAL_READ", "BAD_RESPONSE",
                                        "REFUSED"}
    assert snapshot["read"]["driver"]
    assert snapshot["transport"]["read_only"] is True


def test_credential_never_prints_its_secret():
    credential = sc.Credential("super-secret", source="env")
    assert "super-secret" not in repr(credential)
    assert "super-secret" not in str(credential)
    assert "super-secret" not in f"{credential}"
    assert credential.reveal() == "super-secret"
    assert credential.fingerprint().startswith("sha256:")


# --------------------------------------------------------------------------- #
# evidence store
# --------------------------------------------------------------------------- #

def snapshot_body(name: str = "FW-EDGE-01") -> dict:
    return {"control": "FIREWALL", "vendor": "Fortinet",
            "assets": [{"kind": "FIREWALL", "name": name, "version": "7.4.3"}],
            "captured_at": "2026-11-04T03:00:00Z", "read_at": "2026-11-04T03:00:01Z"}


def test_store_is_idempotent_by_content(tmp_path):
    book = sc.EvidenceStore(tmp_path, "bank-a")
    first = book.append(snapshot_body())
    second = book.append(snapshot_body())
    assert first["digest"] == second["digest"]
    assert second["duplicate"] is True
    assert len(book.records()) == 1


def test_store_volatile_fields_do_not_change_the_digest():
    """A snapshot that says the same thing is the same evidence, whenever it was read."""
    one = store.content_digest({**snapshot_body(), "retrieved_at": "2026-11-04T03:00:01Z"})
    two = store.content_digest({**snapshot_body(), "retrieved_at": "2026-11-05T09:00:00Z"})
    assert one == two
    changed = store.content_digest({**snapshot_body(),
                                    "assets": [{"kind": "FIREWALL", "name": "FW-EDGE-01",
                                                "version": "9.9.9"}]})
    assert changed != one


def test_store_detects_an_edited_body(tmp_path):
    book = sc.EvidenceStore(tmp_path, "bank-a")
    record = book.append(snapshot_body())
    path = book.body_path(record["digest"])
    path.write_text(path.read_text().replace('"7.4.3"', '"9.9.9"'))
    report = book.verify()
    assert report["verified"] is False
    assert "BODY_ALTERED" in json.dumps(report)


def test_store_detects_a_deleted_record(tmp_path):
    book = sc.EvidenceStore(tmp_path, "bank-a")
    book.append(snapshot_body())
    book.append({**snapshot_body(), "assets": [{"kind": "FIREWALL", "name": "FW-EDGE-02"}]})
    index = book.index_path
    lines = index.read_text().splitlines()
    index.write_text(lines[1] + "\n")  # the second record survives, its predecessor does not
    report = book.verify()
    assert report["verified"] is False
    assert "SEQUENCE_GAP" in json.dumps(report) or "CHAIN_BROKEN" in json.dumps(report)


def test_retention_leaves_a_tombstone_not_a_gap(tmp_path):
    book = sc.EvidenceStore(tmp_path, "bank-a")
    old_body = {"control": "FIREWALL", "vendor": "Fortinet",
                "assets": [{"kind": "FIREWALL", "name": "FW-EDGE-00", "version": "6.0.0"}]}
    book.append(old_body, captured_at="2020-01-01T00:00:00+00:00")
    book.append(snapshot_body())
    result = book.retain(max_age_days=30, keep_last=1)
    assert len(result["removed"]) == 1
    assert book.tombstone_path.exists()
    assert len(book.records()) == 2  # the index is never rewritten


def test_store_refuses_a_path_outside_its_root(tmp_path):
    with pytest.raises(sc.ControlRefused) as refused:
        sc.EvidenceStore(tmp_path, "../escape")
    assert refused.value.code == "TENANT_NOT_A_SLUG"


def test_store_diff_names_the_change(tmp_path):
    book = sc.EvidenceStore(tmp_path, "bank-a")
    book.append(snapshot_body())
    book.append({**snapshot_body(), "assets": [
        {"kind": "FIREWALL", "name": "FW-EDGE-01", "version": "7.4.4"}]})
    diff = book.diff()
    assert diff["comparable"] is True
    assert diff["changes"], diff


# --------------------------------------------------------------------------- #
# facades
# --------------------------------------------------------------------------- #

def test_the_four_facade_controls_are_implemented_and_declare_their_delegates():
    catalogue = sc.controls()
    for control in ("HSM", "KMS", "PKI", "NETWORK"):
        entry = catalogue[control]
        assert entry["implemented"] is True, control
        assert entry["facade"] is True
        assert entry["delegates_to"], control
    assert not catalogue["FIREWALL"].get("facade")


def test_a_facade_has_no_vendor_dialect():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.spec_for("HSM", "thales")
    assert refused.value.code == "FACADE_HAS_NO_VENDOR"


def test_hsm_facade_refuses_key_material():
    feed = {"hsms": [{"asset_id": "HSM-PAY-01", "model": "Luna A790",
                      "pinned_secret": "0x" + "a" * 64, "password": "hunter2"}]}
    snap = sc.collector("HSM", "existing-collectors", feed).snapshot()
    text = str(snap)
    assert "hunter2" not in text
    assert "0x" + "a" * 64 not in text


def test_kms_facade_holds_key_relationship_with_evidence():
    feed = {"keys": [{"provider": "AWS", "key_ref": "k-1", "algorithm": "AES", "size": 256,
                      "usage": "ENCRYPT_DECRYPT", "status": "enabled"}]}
    snap = sc.collector("KMS", "existing-collectors", feed).snapshot()
    claim = next(row for row in snap["relationships"] if row["relation"] == "HOLDS_KEY")
    assert claim["evidence_ids"]


def test_pki_facade_uses_the_models_own_relations():
    """A leaf is ISSUED_BY an authority; an authority is SIGNED_BY the one above it."""
    feed = {"certificates": [
        {"ref": "leaf", "fingerprint": "sha256:" + "a" * 64, "subject": "CN=pay.example",
         "issuer": "CN=Root", "authority_key_id": "KI-ROOT",
         "public_key_algorithm": "RSA", "key_size": 2048, "not_after": "2027-01-01"},
        {"ref": "CA-1", "fingerprint": "sha256:" + "b" * 64, "subject": "CN=Root",
         "issuer": "CN=Root", "key_id": "KI-ROOT", "is_ca": True, "self_signed": True},
        {"ref": "inter", "fingerprint": "sha256:" + "c" * 64, "subject": "CN=Issuing",
         "issuer": "CN=Root", "authority_key_id": "KI-ROOT", "key_id": "KI-INT",
         "is_ca": True, "not_after": "2028-01-01"}], "anchors": ["CA-1"]}
    snap = sc.collector("PKI", "existing-collectors", feed).snapshot()
    relations = {(row["from"], row["relation"], row["to"]) for row in snap["relationships"]}
    assert ("leaf", "ISSUED_BY", "CA-1") in relations
    assert ("inter", "SIGNED_BY", "CA-1") in relations
    assert all(row["relation"] in techbom.RELATIONS for row in snap["relationships"])


def test_pki_facade_refuses_a_certificate_it_cannot_name():
    feed = {"certificates": [{"subject": "CN=anonymous"}]}
    snap = sc.collector("PKI", "existing-collectors", feed).snapshot()
    assert snap["assets"] == []
    assert any(row["code"] == "CERTIFICATE_REFUSED" for row in snap["refusals"])


def test_network_facade_drops_everything_that_is_not_a_handshake():
    feed = {"endpoints": [{"host": "10.20.3.4", "port": 443, "tls_version": "TLS1.2"}],
            "events": [{"kind": "ALERT", "src": "10.20.3.4", "alert": "handshake_failure",
                        "raw_body": "GET /pay HTTP/1.1\r\nCookie: sess=abc",
                        "authorization": "Basic eA=="}]}
    snap = sc.collector("NETWORK", "existing-collectors", feed).snapshot()
    text = str(snap)
    assert "sess=abc" not in text
    assert "Basic eA==" not in text
    assert snap["events"][0]["metadata"] == {"kind": "ALERT", "src": "10.20.3.4",
                                            "alert": "handshake_failure"}
    dropped = {row["field"] for row in snap["redactions"]}
    assert {"raw_body", "authorization"} <= dropped


# --------------------------------------------------------------------------- #
# rate limits: the window is part of the answer
# --------------------------------------------------------------------------- #

def _limiter(mode: str = "FIXED", limit: int = 100, window: int = 60):
    from cbom.security_controls import registry

    feed = {"sections": {
        "limits": [{"name": "rl-public", "enabled": True, "limit": limit,
                    "window_seconds": window, "window_mode": mode}],
        "mappings": [{"policy": "rl-public", "api": "PAYMENTS-API"}],
    }}
    return registry.PACKAGES["RATE_LIMIT"].collector("Kong", feed)


def test_fixed_and_sliding_windows_permit_different_traffic():
    """The boundary is the whole difference, and it is why the model has to be read."""
    fixed = sc.WindowModel(mode="FIXED", limit=100, window_seconds=60)
    aligned = sc.WindowModel(mode="FIXED", limit=100, window_seconds=60)
    sliding = sc.WindowModel(mode="SLIDING", limit=100, window_seconds=60)
    assert sliding.expected(60)[0] == 100            # N in any rolling window, ever
    assert aligned.expected(60, aligned=True)[0] == 100   # one closed counter window
    assert fixed.expected(60)[0] == 200              # a boundary burst is legal
    assert fixed.expected(120)[0] == 300
    assert sliding.expected(120)[0] == 200
    assert "boundary burst" in fixed.expected(60)[1]


def test_an_unknown_window_model_is_refused_not_guessed():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.WindowModel(mode="SOMETIMES", limit=10)
    assert refused.value.code == "UNKNOWN_WINDOW_MODE"


def test_a_breach_needs_an_observation_with_evidence():
    audit = sc.audit_limits(_limiter(), traffic=[
        {"api": "PAYMENTS-API", "requests": 900, "window_seconds": 60}])
    assert audit["summary"]["OVER_LIMIT"] == 0
    assert any(row["code"] == "OBSERVATION_WITHOUT_EVIDENCE" for row in audit["refusals"])


def test_traffic_without_a_policy_is_not_configured_not_unknown():
    source = sc.CounterAPI(
        sc.RecordedTransport({"/metrics": {"routes": [
            {"api": "PAYMENTS-API", "requests": 10, "window_seconds": 60},
            {"api": "UNPROTECTED", "requests": 9000, "window_seconds": 60}]}}),
        "/metrics")
    audit = sc.audit_limits(_limiter(), source=source)
    states = {(row["api"], row["state"]) for row in audit["findings"]}
    assert ("UNPROTECTED", "NOT_CONFIGURED") in states
    assert ("PAYMENTS-API", "WITHIN_LIMIT") in states


def test_a_mismatched_window_is_incomparable_not_a_breach():
    source = sc.CounterAPI(
        sc.RecordedTransport({"/metrics": {"routes": [
            {"api": "PAYMENTS-API", "requests": 400, "window_seconds": 60,
             "window_mode": "SLIDING"}]}}),
        "/metrics")
    audit = sc.audit_limits(_limiter("FIXED"), source=source)
    assert audit["summary"]["INCOMPARABLE_WINDOW"] == 1
    assert audit["summary"]["OVER_LIMIT"] == 0


def test_an_unavailable_source_is_reported_not_silently_empty():
    source = sc.CounterAPI(sc.RecordedTransport({}), "/metrics")
    audit = sc.audit_limits(_limiter(), source=source)
    assert any(row["code"] == "OBSERVATION_SOURCE_UNAVAILABLE" for row in audit["refusals"])
    assert audit["sources"][0]["state"] != "OK"


def test_the_report_says_what_was_not_measured():
    source = sc.CounterAPI(
        sc.RecordedTransport({"/metrics": {"routes": [
            {"api": "PAYMENTS-API", "requests": 10, "window_seconds": 60}]}}),
        "/metrics", routes=("PAYMENTS-API",))
    report = sc.observation_report(sc.audit_limits(_limiter(), source=source))
    assert report["measured"] == 1
    assert "not a limit that held" in report["statement"]


# --------------------------------------------------------------------------- #
# resolvers: an inventory is a statement about a moment
# --------------------------------------------------------------------------- #

NOW = datetime(2026, 11, 4, 9, 14, tzinfo=timezone.utc)


def _iso(minutes: int) -> str:
    return (NOW - timedelta(minutes=minutes)).isoformat()


def _estate(library_minutes: int = 5) -> sc.StaticResolver:
    return sc.StaticResolver(rows={
        "hosts": [{"ip": "10.20.3.4", "host": "APP-PAY-01", "captured_at": _iso(5)}],
        "processes": [{"host": "APP-PAY-01", "process": "java:payments",
                       "captured_at": _iso(5)}],
        "apis": [{"process": "java:payments", "api": "PAYMENTS-API",
                  "captured_at": _iso(5)}],
        "libraries": [{"api": "PAYMENTS-API", "library": "OpenSSL 3.0.13",
                       "captured_at": _iso(library_minutes)}],
        "keys": [{"library": "OpenSSL 3.0.13", "hsm": "HSM-PAY-01",
                  "captured_at": _iso(5)}],
    })


def test_window_classification():
    window = sc.Window(event_at=NOW, max_age_seconds=3600)
    assert window.classify(_iso(5)) == "IN_WINDOW"
    assert window.classify(_iso(180)) == "STALE"
    assert window.classify((NOW + timedelta(hours=2)).isoformat()) == "AFTER_EVENT"
    assert window.classify(None) == "UNKNOWN_TIME"


def test_a_fresh_inventory_resolves_the_whole_path():
    result = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.20.3.4"},
                                         _estate(), window=sc.Window(event_at=NOW))
    assert result["answerable"] is True
    assert result["trustworthy"] is True
    assert [hop["to"] for hop in result["path"]][-1] == "HSM-PAY-01"


def test_a_stale_hop_is_named_and_not_counted():
    result = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.20.3.4"},
                                         _estate(library_minutes=600),
                                         window=sc.Window(event_at=NOW,
                                                          max_age_seconds=3600))
    assert result["inventory"]["stale"]
    assert any(row["code"] == "STALE_EVIDENCE" for row in result["unresolved"])
    assert result["trustworthy"] is False


def test_strict_mode_drops_the_stale_hop_instead_of_using_it():
    result = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.20.3.4"},
                                         _estate(library_minutes=600),
                                         window=sc.Window(event_at=NOW,
                                                          max_age_seconds=3600),
                                         strict=True)
    assert "OpenSSL 3.0.13" not in str(result["path"])
    # the path stops where the evidence stops, and is not extended by the stale hop
    assert [hop["to"] for hop in result["path"]][-1] == "PAYMENTS-API"
    assert result["trustworthy"] is False


def test_an_empty_inventory_is_an_unresolved_path_not_a_pass():
    result = sc.correlate_from_inventory({"id": "EVT-1", "src": "10.99.99.99"},
                                         sc.StaticResolver(rows={}),
                                         window=sc.Window(event_at=NOW))
    assert result["answerable"] is False
    assert result["inventory"]["source"] == "empty"


def test_an_event_without_a_source_is_refused():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.correlate_from_inventory({"id": "EVT-1"}, sc.StaticResolver(rows={}))
    assert refused.value.code == "NO_SOURCE_ADDRESS"
