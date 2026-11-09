"""Tier-2 runtime observation acceptance tests (approved — §3).

PROVENANCE: trace fixtures are RECONSTRUCTED from the documented
capture format of tools/runtime_capture/crypto_trace.bt — NOT
captured from a live host (no root, no bpftrace in the sandbox).
The collector program and capture driver are REAL code for an
authorised host; synthetic fixtures stay labelled synthetic.

Discipline proven here: metadata events only (secrets/keys/payloads
REFUSED with reasons), unknown categories never guessed, dedup never
silent, event loss recorded never guessed, runtime_usage_confirmed
raised ONLY by runtime events and never overwriting static rows,
OS-CRYPTO-017 semantics (loss = observability gap; no session is
never 'healthy'; zero events is never 'no crypto activity').
"""

from __future__ import annotations

from pathlib import Path

from os_intelligence.rules import evaluate
from os_intelligence.runtime import (EVENT_FIELDS,
                                     PROHIBITED_FIELD_MARKERS,
                                     ingest_events, parse_trace_text)

FIXTURES = Path(__file__).parent / "fixtures"


def _session(lost: bool = False):
    name = "runtime-trace-lost.txt" if lost else \
        "runtime-trace-sample.txt"
    return parse_trace_text((FIXTURES / name).read_text(),
                            session_id="rt-1", host_id="h1",
                            evidence_source="runtime collector")


class TestProvenance:
    def test_fixtures_labelled_synthetic(self):
        for name in ("runtime-trace-sample.txt",
                     "runtime-trace-lost.txt"):
            text = (FIXTURES / name).read_text()
            assert "RECONSTRUCTED" in text
            assert "NOT captured from a live" in text


class TestBoundedFilter:
    def test_events_carry_only_allowlisted_fields(self):
        session = _session()
        for ev in session.events:
            assert set(ev.as_dict().keys()) == set(EVENT_FIELDS)

    def test_prohibited_fields_are_refused_with_reasons(self):
        session = ingest_events("s", "h", [
            {"timestamp": "1", "algorithm_identifier": "aes",
             "plaintext": "hunter2", "private_key": "PEM...",
             "session_token": "abc", "key_material": "x"},
        ])
        assert session.events, "the metadata fields survive"
        assert session.events[0].as_dict().get("plaintext") is None
        blob = str(session.as_dict())
        assert "hunter2" not in blob and "PEM" not in blob
        reasons = " ".join(r["reason"] for r in session.refusals)
        assert "NEVER collects" in reasons
        assert len(session.refusals) >= 3
        for marker in ("plaintext", "private_key", "token"):
            assert marker in reasons.lower()

    def test_non_allowlisted_fields_refused(self):
        session = ingest_events("s", "h", [
            {"timestamp": "1", "favorite_color": "blue"}])
        assert "outside the allowlist" in session.refusals[0]["reason"]

    def test_prohibited_marker_list_covers_the_spec(self):
        for marker in ("plaintext", "private_key", "password",
                       "token", "secret", "decrypted"):
            assert marker in PROHIBITED_FIELD_MARKERS


class TestNormalizer:
    def test_unknown_category_is_unclassified_never_guessed(self):
        session = _session()
        categories = {e.operation_category for e in session.events}
        assert "unclassified" in categories
        assert "quantum_maybe" not in categories
        assert any("never guessed" in r["reason"]
                   for r in session.refusals)

    def test_duplicates_collapse_with_note_never_silent(self):
        session = _session()
        rsa = [e for e in session.events
               if e.algorithm_identifier == "rsa"]
        assert len(rsa) == 1, "the duplicated rsa event collapsed"
        assert any("deduplication" in n for n in session.notes)

    def test_malformed_events_refused_never_fabricated(self):
        session = ingest_events("s", "h", ["not-a-mapping", {}])
        assert session.events == []
        assert len(session.refusals) >= 2
        assert all(r["reason"] for r in session.refusals)


class TestUsageConfirmations:
    def test_confirmation_raised_only_by_runtime_events(self):
        session = _session()
        confirmations = session.usage_confirmations()
        by_algo = {c["algorithm"]: c for c in confirmations}
        assert "cbc(aes)" in by_algo
        c = by_algo["cbc(aes)"]
        assert c["runtime_usage_confirmed"] is True
        assert c["evidence_class"] == "observed"
        assert c["confirmed_by_events"]
        assert "never overwritten" in c["note"]
        assert "co-location" in c["note"]

    def test_confirmation_scoped_to_observed_process(self):
        session = _session()
        c = [x for x in session.usage_confirmations()
             if x["algorithm"] == "cbc(aes)"][0]
        assert any("pid=4242" in p for p in c["observed_processes"])
        assert any("sha256:aaaa1111" in p for p in
                   c["observed_processes"])

    def test_no_events_means_no_confirmations_ever(self):
        session = ingest_events("s", "h", [])
        assert session.usage_confirmations() == []

    def test_unclassified_category_confirms_nothing(self):
        session = _session()
        confirmed = {c["algorithm"]
                     for c in session.usage_confirmations()}
        assert "kyber" not in confirmed, \
            "an unclassified event never raises usage"


class TestLossAccounting:
    def test_lost_events_recorded_never_guessed(self):
        session = _session(lost=True)
        report = session.loss_report()
        assert report["events_lost"] == 7
        assert report["events_accepted"] == 1
        assert "recorded, never guessed" in report["note"]

    def test_sample_session_loss_accounting(self):
        report = _session().loss_report()
        assert report["events_lost"] == 0
        # 4 accepted: cbc(aes), sha256, rsa (deduped), and the
        # unclassified event — accepted with its category honestly
        # unclassified, never dropped
        assert report["events_accepted"] == 4


class TestRule017:
    def _rule(self, session):
        inv = {"host_id": "h", "coverage":
               {"sources_collected": []}}
        kw = {} if session is None else {"runtime_session": session}
        return [r for r in evaluate(inv, **kw).results
                if r.rule_id == "OS-CRYPTO-017"][0]

    def test_no_session_is_never_healthy(self):
        rule = self._rule(None)
        assert rule.status == "not_evaluable"
        assert "never reported as 'healthy'" in rule.evaluation_note

    def test_event_loss_is_an_observability_gap(self):
        rule = self._rule(_session(lost=True))
        assert rule.status == "evaluated"
        f = rule.findings[0]
        assert f["details"]["events_lost"] == 7
        assert f["details"]["events_accepted"] == 1
        assert "observability gap" in f["details"]["risk"]
        assert "NEVER 'unused'" in f["details"]["risk"]
        assert "recorded, never guessed" in str(f["limitations"])

    def test_zero_loss_never_absent(self):
        rule = self._rule(_session())
        assert rule.status == "evaluated"
        assert rule.findings == []
        assert "never 'absent'" in rule.evaluation_note
        assert "per-session, not continuous" in rule.evaluation_note

    def test_zero_event_session_is_unknown_not_no_activity(self):
        empty = ingest_events("s", "h", [])
        rule = self._rule(empty)
        assert "UNKNOWN" in rule.evaluation_note
        assert "never 'no cryptographic activity'" in \
            rule.evaluation_note
