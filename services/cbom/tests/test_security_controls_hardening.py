"""Guide 183 — the guarantees, hardened: redaction precision, enforcement, versions, coverage.

Guide 181's guarantees were structural ("no prohibited value survives a cycle") and guide 182's
were about honesty under failure. Both were true statements. Neither was *precise*, and this
file is about the difference between a guarantee that reads well and one that holds under
numbers:

* **a redaction rule that redacts everything is a broken rule.** The card-number shape matched
  any 13-19 digit run — epoch milliseconds, object ids, byte counts. A corpus of legitimate
  numeric fields holds the guard to its precision, and an allowlist makes the trade reviewable.
* **"read-only" has to be enforced where bytes leave.** The transport allow-list is tested with
  a client that records whether it was ever called: a `POST` must not reach it at all.
* **an evidence id has to survive a version change in both directions** — stable when the fact
  is unchanged, moved when the *text* changed but the identity did not, and readable after the
  digest rule itself changes.
* **failure has a taxonomy, and every surface reports it.** Three of seven sections is
  `PARTIAL_READ`, not "no findings"; an un-written dialect is `UNSUPPORTED_DIALECT`, not an
  empty list.
* **scale is a correctness problem.** Only changed sections are collected, coverage is
  per-device, and a snapshot has a memory ceiling that is recorded when it is hit.
"""

from __future__ import annotations

import json

import pytest

from cbom import security_controls as sc


# --------------------------------------------------------------------------- #
# 7 — the redaction guard, held to its precision
# --------------------------------------------------------------------------- #

#: Values that are not secrets and must survive a collection cycle untouched. Every entry is
#: something a real device reports: a timestamp in three resolutions, an object id, a serial,
#: an inode, a byte count, a port range, a checksum-shaped number.
LEGITIMATE_NUMERIC_FIELDS: dict[str, str] = {
    "epoch_ms": "1735689600000",
    "epoch_micros": "1735689600000123",
    "epoch_seconds": "1735689600",
    "object_id": "1099511627776",
    "serial": "1234567890123456",
    "inode": "8392018475629",
    "bytes": "7812345678901",
    "uptime_ms": "86400000",
    "mtu": "9000",
    "vlan": "4094",
    "policyid": "1234567890123",
    "sensor_id": "9192837465561",
    "window_seconds": "60",
    "port_range": "8080-8443",
    "trace_id_int": "2026110409140000001",
    "created_at": "2026-11-04T09:14:00Z",
    "duration_ms": "1735689600000",
    "count": "8912345678901",
    "size": "4294967296",
    "build_number": "20261104123",
}


def test_the_guard_does_not_redact_the_evidence_it_needs():
    clean, redactions = sc.scrub(dict(LEGITIMATE_NUMERIC_FIELDS))
    redacted = {key for key, value in clean.items() if value == sc.REDACTED}
    assert redacted == set(), f"false positives: {sorted(redacted)}"
    assert redactions == []


def test_a_real_card_number_is_still_caught():
    """Precision must not have cost the rule its purpose."""
    clean, redactions = sc.scrub({
        "summary": "4111 1111 1111 1111",        # Visa
        "note": "5500 0000 0000 0004",           # Mastercard
        "trace": "378282246310005",              # Amex, 15 digits
        "detail": "6011 0009 9013 9424",         # Discover
    })
    assert {key for key, value in clean.items() if value == sc.REDACTED} == {
        "summary", "note", "trace", "detail"}
    assert {row["reason"] for row in redactions} == {"CARD_NUMBER"}


def test_a_luhn_valid_number_in_no_issuer_range_is_not_a_card():
    """Both checks matter: Luhn alone has a one-in-ten false-positive rate."""
    clean, _ = sc.scrub({"reference": "1234567812345670"})
    assert clean["reference"] == "1234567812345670"


def test_an_allowlisted_field_does_not_excuse_real_secrets():
    """The allowlist relaxes the *numeric shape*, never the field rules or the other shapes."""
    clean, redactions = sc.scrub({
        "timestamp": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
        "serial": "AKIAIOSFODNN7EXAMPLE",
        "version": "Bearer abcdef1234567890abcdef",
        "count": "x",
        "pan": "4111111111111111",           # field name still refused
    })
    reasons = {row["reason"] for row in redactions}
    assert clean["timestamp"] == sc.REDACTED
    assert clean["serial"] == sc.REDACTED
    assert clean["version"] == sc.REDACTED
    assert clean["pan"] == sc.REDACTED
    assert reasons == {"PEM_PRIVATE_KEY", "AWS_ACCESS_KEY", "BEARER_TOKEN",
                       "PROHIBITED_FIELD"}


def test_the_allowlist_is_reported_so_the_trade_is_reviewable():
    allowlist = sc.redaction_allowlist()
    assert "timestamp" in allowlist["numeric_fields"]
    assert "CARD_NUMBER" not in allowlist["never_allowed"]
    assert "PEM_PRIVATE_KEY" in allowlist["never_allowed"]
    assert "Luhn" in allowlist["card_rule"]


def test_the_corpus_survives_a_full_collection_cycle():
    """The same corpus, through a collector, with nothing redacted on the way through."""
    feed = {"system": "FW-EDGE-01",
            "assets": [{"kind": "FIREWALL", "name": "FW-EDGE-01",
                        "version": "7.4.3", "serial_number": "1234567890123456"}],
            "sections": {"rules": [{"name": "allow-pay", "policyid": "1234567890123",
                                    "timestamp": "1735689600000", "bytes": "7812345678901",
                                    "action": "accept"}]},
            "health": {"collected_at": "2026-11-04T09:14:00Z"}}
    snapshot = sc.collector("FIREWALL", "fortigate", feed).snapshot()
    assert snapshot["redactions"] == []
    assert "1234567890123456" in json.dumps(snapshot)


# --------------------------------------------------------------------------- #
# 8 — read-only, enforced where bytes leave
# --------------------------------------------------------------------------- #

class CountingClient:
    """An HTTP client that records every request it is asked to make."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **_kwargs):
        self.calls.append((method.upper(), url))

        class _Response:
            status_code = 200
            headers: dict[str, str] = {}
            text = "{}"

            def json(self):
                return {}

        return _Response()

    def close(self) -> None:
        return None


def test_a_write_never_reaches_the_http_client():
    """The refusal has to happen above the socket, or it is a preference rather than a lock."""
    client = CountingClient()
    http = sc.HttpTransport(base_url="https://fw.example.bank",
                            credential=sc.Credential("t", source="test"),
                            _client_factory=lambda: client)
    for verb in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(sc.ControlRefused) as refused:
            http.request(verb, "/api/v2/cmdb/firewall/policy")
        assert refused.value.code == "NOT_READ_ONLY"
    assert client.calls == []


def test_get_and_head_do_reach_the_client():
    client = CountingClient()
    http = sc.HttpTransport(base_url="https://fw.example.bank",
                            credential=sc.Credential("t", source="test"),
                            _client_factory=lambda: client)
    http.request("GET", "/api/v2/monitor/system/status")
    http.request("head", "/api/v2/monitor/license")
    assert [method for method, _ in client.calls] == ["GET", "HEAD"]


def test_the_allowlist_is_the_whole_method_set():
    assert sc.transport.READ_METHODS == frozenset({"GET", "HEAD"})


def test_a_recorded_transport_refuses_a_write_too():
    with pytest.raises(sc.ControlRefused):
        sc.RecordedTransport({}).request("POST", "/x")


def test_a_spec_that_declares_a_write_is_refused_at_registration():
    with pytest.raises(sc.ControlRefused):
        sc.AdapterSpec(key="firewall.bad", control="FIREWALL", vendor="Bad",
                       product="Bad", operations=("API_POST",))


# --------------------------------------------------------------------------- #
# 9 — evidence ids: stable, versioned, and readable after a scheme change
# --------------------------------------------------------------------------- #

def test_an_unchanged_rule_keeps_its_evidence_id():
    book = sc.EvidenceBook("FIREWALL", "Fortinet", "FW-EDGE-01")
    rule = {"name": "allow-payments", "action": "accept", "version": "42"}
    assert book.id_for("RULE", "allow-payments", rule) == \
        book.id_for("RULE", "allow-payments", rule)


def test_a_rule_whose_text_changed_moves_its_evidence_id():
    """The identity is the same; the revision is not. The id has to move."""
    book = sc.EvidenceBook("FIREWALL", "Fortinet", "FW-EDGE-01")
    before = {"name": "allow-payments", "action": "accept", "version": "42",
              "src": "10.0.0.0/8"}
    after = dict(before, version="43", src="10.1.0.0/16")
    assert book.id_for("RULE", "allow-payments", before) != \
        book.id_for("RULE", "allow-payments", after)


def test_the_config_version_is_what_moves_it_event_alone():
    """Same text, bumped revision — the device says the rule changed, so the id agrees."""
    book = sc.EvidenceBook("FIREWALL", "Fortinet", "FW-EDGE-01")
    text = {"name": "allow-payments", "action": "accept", "src": "10.0.0.0/8"}
    assert book.id_for("RULE", "allow-payments", {**text, "version": "42"}) != \
        book.id_for("RULE", "allow-payments", {**text, "version": "43"})


def test_the_version_field_names_are_discovered_not_assumed():
    found = sc.config_version({"etag": "abc", "last_modified": "2026-11-04T09:00:00Z",
                               "name": "rule", "action": "accept"})
    assert set(found) == {"etag", "lastmodified"}
    assert sc.config_version({"name": "rule"}) == {}


def test_every_id_carries_its_scheme():
    book = sc.EvidenceBook("WAF", "F5", "WAF-01")
    evidence_id = book.id_for("VIRTUAL_SERVER", "vs-pay")
    assert evidence_id.startswith(f"EVID-{sc.EVIDENCE_SCHEME}-WAF-")
    assert sc.evidence_scheme(evidence_id) == sc.EVIDENCE_SCHEME


def test_a_legacy_id_is_recognised_rather_than_misread():
    assert sc.evidence_scheme("EVID-FIREWALL-0123456789ab") == sc.LEGACY_SCHEME
    assert sc.evidence_scheme("EVID-v1-FIREWALL-0123456789ab") == "v1"
    assert sc.evidence_scheme("KMS-EVID-001") == "UNKNOWN"


def test_a_citation_can_be_re_verified_six_months_later():
    book = sc.EvidenceBook("FIREWALL", "Fortinet", "FW-EDGE-01")
    rule = {"name": "allow-payments", "version": "42"}
    evidence_id = book.id_for("RULE", "allow-payments", rule)
    assert book.verify(evidence_id, "RULE", "allow-payments", rule)["matches"] is True
    changed = book.verify(evidence_id, "RULE", "allow-payments", {**rule, "version": "43"})
    assert changed["matches"] is False
    assert "the fact hashes differently now" in changed["reason"]


def test_verification_does_not_mint_evidence():
    book = sc.EvidenceBook("FIREWALL", "Fortinet", "FW-EDGE-01")
    rule = {"name": "allow-payments"}
    evidence_id = book.id_for("RULE", "allow-payments", rule)
    before = len(book.as_list())
    book.verify(evidence_id, "RULE", "allow-payments", rule)
    assert len(book.as_list()) == before


def test_an_observation_id_uses_the_same_scheme():
    audit = sc.audit_limits(
        sc.registry.PACKAGES["RATE_LIMIT"].collector("Kong", {"sections": {
            "limits": [{"name": "rl", "limit": 100, "window_seconds": 60}],
            "mappings": [{"policy": "rl", "api": "PAYMENTS-API"}]}}),
        traffic=[{"api": "PAYMENTS-API", "requests": 10, "window_seconds": 60,
                  "evidence_id": "EVID-v1-OBS-0123456789ab", "aligned": True}])
    assert audit["findings"][0]["evidence_ids"][1].startswith("EVID-v1-")


# --------------------------------------------------------------------------- #
# 10 — the taxonomy, on every surface
# --------------------------------------------------------------------------- #

def test_the_taxonomy_names_every_state_and_what_it_means():
    for state in sc.CONTROL_STATES:
        described = sc.describe(state)
        assert described["meaning"] and described["operator_action"]
        assert described["group"] in {"COLLECTED", "FAILED", "ABSENT", "CHOSEN"}
    with pytest.raises(sc.ControlRefused):
        sc.describe("PROBABLY_FINE")


def test_three_of_seven_sections_is_a_partial_read_not_nothing():
    transport_ = sc.RecordedTransport({
        "/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "allow-pay"}]},
    })
    snapshot = sc.live_snapshot("FIREWALL", "fortigate", transport_, system="FW-EDGE-01")
    read = snapshot["read"]
    assert read["state"] == "PARTIAL_READ"
    assert read["coverage"]["sections_read"] == 1
    assert read["coverage"]["sections_declared"] == 5
    assert set(read["coverage"]["failed"]) == {"zones", "interfaces", "vpn", "tls_inspection"}
    assert read["coverage"]["complete"] is False


def test_health_reports_the_taxonomy_and_the_read():
    collector = sc.collector("FIREWALL", "fortigate", {
        "system": "FW-EDGE-01",
        "health": {"state": "AUTH_FAILED",
                   "coverage": {"sections_read": 0, "sections_declared": 5},
                   "failed_sections": ["rules"]}})
    health = collector.health()
    assert health["state"] == "AUTH_FAILED"
    assert health["taxonomy"]["group"] == "FAILED"
    assert health["taxonomy"]["operator_action"].startswith("rotate")
    assert health["read"]["coverage"]["sections_declared"] == 5


def test_an_unreachable_device_is_unreachable_in_health():
    health = sc.collector("SIEM", "splunk", {"health": {"reachable": False}}).health()
    assert health["state"] == "UNREACHABLE"
    assert health["taxonomy"]["retryable"] is True


def test_a_dialect_nobody_wrote_is_unsupported_not_empty():
    """The dialect row exists; the driver does not. That is a gap, and it has a name."""
    assert "firewall.cisco-asa" not in sc.DRIVERS
    with pytest.raises(sc.ControlRefused) as refused:
        sc.drivers.driver_for("firewall.cisco-asa", sc.RecordedTransport({}))
    assert refused.value.code == "NO_LIVE_DRIVER"
    described = sc.describe("UNSUPPORTED_DIALECT")
    assert described["group"] == "ABSENT"
    assert described["collected"] is False
    assert "no driver exists" in described["meaning"]


def test_the_projection_summary_carries_coverage_not_just_counts():
    collectors = [
        sc.collector("FIREWALL", "fortigate", {"system": "FW-01"}),
        sc.collector("SIEM", "splunk", {"health": {"reachable": False}}),
    ]
    coverage = sc.project(collectors)["summary"]["coverage"]
    assert coverage["counts"]["UNREACHABLE"] == 1
    assert coverage["collected"] == 1
    assert coverage["complete"] is False
    assert "could not be read" in coverage["statement"]
    assert coverage["per_control"][0]["group"] in {"COLLECTED", "FAILED"}


def test_an_empty_collection_says_so_instead_of_reporting_success():
    coverage = sc.project([])["summary"]["coverage"]
    assert coverage["nothing_asked"] is True
    assert "did not happen" in coverage["statement"]


def test_coverage_regression_is_its_own_finding():
    before = sc.summarise([{"control": "FIREWALL", "state": "OK"}])
    after = sc.summarise([{"control": "FIREWALL", "state": "AUTH_FAILED"}])
    diff = sc.for_diff(before, after)
    assert diff["regressed"] is True
    assert diff["degraded"] == [{"control": "FIREWALL", "was": "OK", "now": "AUTH_FAILED"}]


# --------------------------------------------------------------------------- #
# 11 — scale: incremental, per-device, bounded
# --------------------------------------------------------------------------- #

def test_an_unchanged_section_is_not_re_read():
    routes = {"/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "a"}]},
              "/api/v2/cmdb/system/zone": {"results": [{"name": "payments"}]}}
    first = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(routes),
                             system="FW-01")
    previous = {"sections": first["configuration"]["sections"], "health": first["health"]}
    second = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(routes),
                              system="FW-01", previous=previous, incremental=True)
    assert second["read"]["incremental"] is True
    assert second["read"]["unchanged_sections"] == ["rules", "zones"]
    # the snapshot is still complete: the unchanged rows are merged back from the previous read
    assert second["read"]["merged_sections"] == ["rules", "zones"]
    assert second["read"]["coverage"]["sections_read"] == 2


def test_a_changed_section_is_read_again():
    first_routes = {"/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "a"}]},
                    "/api/v2/cmdb/system/zone": {"results": [{"name": "payments"}]}}
    first = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(first_routes),
                             system="FW-01")
    previous = {"sections": first["configuration"]["sections"], "health": first["health"]}
    changed = {**first_routes,
               "/api/v2/cmdb/firewall/policy": {"results": [{"policyid": 1, "name": "b"}]}}
    second = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport(changed),
                              system="FW-01", previous=previous, incremental=True)
    assert second["read"]["unchanged_sections"] == ["zones"]
    assert "rules" in second["configuration"]["sections"]


def test_the_section_cache_holds_digests_not_rows():
    cache = sc.drivers.SectionCache()
    rows = [{"name": "a", "policyid": 1}]
    assert cache.changed("rules", rows) is True
    cache.record("rules", rows)
    assert cache.changed("rules", rows) is False
    assert len(json.dumps(cache.as_dict())) < 200


def test_coverage_is_per_device_not_per_estate():
    one = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({
        "/api/v2/cmdb/firewall/policy": {"results": [{"x": 1}]}}), system="FW-01")
    two = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({}), system="FW-02")
    assert one["read"]["coverage"]["sections_read"] == 1
    assert two["read"]["coverage"]["sections_read"] == 0
    assert one["read"]["coverage"]["state"] != two["read"]["coverage"]["state"]


def test_a_section_larger_than_the_cap_is_truncated_and_says_so():
    big = {"results": [{"policyid": index, "name": f"rule-{index}"} for index in range(40)]}
    snapshot = sc.live_snapshot("FIREWALL", "fortigate",
                                sc.RecordedTransport({"/api/v2/cmdb/firewall/policy": big}),
                                system="FW-01", max_rows=10)
    truncated = snapshot["read"]["truncated"]["rules"]
    assert truncated["rows_read"] == 40
    assert truncated["rows_kept"] == 10
    assert truncated["rows_dropped"] == 30
    assert "clean audit of a rule nobody could see" in truncated["reason"]


def test_the_snapshot_ceiling_is_reported_before_it_is_hit():
    snapshot = sc.live_snapshot("FIREWALL", "fortigate", sc.RecordedTransport({}),
                                system="FW-01")
    limits = snapshot["read"]["limits"]
    assert limits["max_rows_per_section"] > 0
    assert limits["max_snapshot_bytes"] > 0
    assert limits["bytes_remaining"] <= limits["max_snapshot_bytes"]
