"""Certificate metadata acceptance tests (OS-CRYPTO-008's source, §7).

REAL corpus: certificates-openssl-real.txt is captured output of
`openssl x509` against the ACTUAL local host CA bundle (ISRG Root X1,
ACCVRAIZ1) — genuine certificate metadata. The certutil fixture is
RECONSTRUCTED from the documented `certutil -store` format and
labelled synthetic.

Discipline: public certificate metadata only — private keys are NEVER
collected, exported, displayed or stored. Unparseable validity dates
are UNKNOWN — never 'not expired' (§2.1).
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from os_intelligence.certificates import (build_certificates,
                                          parse_certutil_store,
                                          parse_openssl_x509)
from os_intelligence.collector import collect_linux
from os_intelligence.rules import _parse_cert_date, evaluate

FIXTURES = Path(__file__).parent / "fixtures"
REAL = FIXTURES / "certificates-openssl-real.txt"
CERTUTIL = FIXTURES / "certificates-certutil-reconstructed.txt"


class TestRealCorpus:
    def test_real_host_certificates_parse(self):
        records = parse_openssl_x509(REAL.read_text())
        subjects = {r.subject for r in records}
        assert any("ISRG Root X1" in s for s in subjects), \
            "the REAL local corpus must parse"
        isrg = [r for r in records if "ISRG Root X1" in r.subject][0]
        assert isrg.thumbprint_sha256.startswith("96BCEC")
        assert isrg.public_key_bits == 4096
        assert isrg.evidence_class == "observed"
        assert "private key material is NEVER collected" in str(
            isrg.limitations)

    def test_dates_are_honest(self):
        records = parse_openssl_x509(REAL.read_text())
        for r in records:
            assert r.not_after
            assert _parse_cert_date(r.not_after) is not None
        assert _parse_cert_date("not-a-date") is None, \
            "unparseable dates are UNKNOWN, never guessed"

    def test_collector_wires_certificate_metadata(self):
        import os
        import shutil
        import tempfile
        root = tempfile.mkdtemp()
        try:
            os.makedirs(f"{root}/proc")
            os.makedirs(f"{root}/etc/ssl")
            shutil.copy(FIXTURES / "host-linux-sample.txt",
                        f"{root}/proc/version")
            shutil.copy(REAL, f"{root}/etc/ssl/cert-metadata")
            inv = collect_linux("h", source_root=root,
                                collect_hardware_trust=False).as_dict()
        finally:
            shutil.rmtree(root)
        assert len(inv["certificates"]) == 2
        assert "certificate_metadata" in \
            inv["coverage"]["sources_collected"]

    def test_missing_cert_source_is_unavailable_never_all_valid(self):
        inv = collect_linux("h", source_root=str(FIXTURES / "empty-root"),
                            collect_hardware_trust=False).as_dict()
        assert inv["certificates"] == []
        unavailable = [u for u in inv["coverage"]["sources_unavailable"]
                       if u["source"] == "certificate_metadata"]
        assert unavailable


class TestCertutilFormat:
    def test_certutil_blocks_parse(self):
        records = parse_certutil_store(CERTUTIL.read_text())
        assert len(records) == 2
        legacy = records[0]
        assert legacy.subject == "CN=legacy.example.internal"
        assert legacy.public_key_bits == 2048
        # private-key FLAG is metadata only — never any key content
        flags = [l for l in legacy.limitations if "presence flag" in l]
        assert flags, "the presence flag is recorded as metadata (§7)"
        assert all("NEVER collected" in f for f in flags)


class TestRule008:
    def _cert(self, not_after: str, subject: str = "CN=x") -> dict:
        return {"subject": subject, "issuer": "CN=ca",
                "not_before": "", "not_after": not_after,
                "thumbprint_sha256": "AB", "public_key_algorithm": "",
                "public_key_bits": None, "evidence_class": "observed",
                "evidence_source": "test", "limitations": []}

    def _rule(self, certs, as_of: date):
        inv = {"host_id": "h", "certificates": certs,
               "coverage": {"sources_collected": ["certificate_metadata"]}}
        return [r for r in evaluate(inv, as_of=as_of).results
                if r.rule_id == "OS-CRYPTO-008"][0]

    def test_expired_fires(self):
        rule = self._rule([self._cert("Jun  4 11:04:38 2020 GMT")],
                          as_of=date(2026, 10, 16))
        assert rule.status == "evaluated"
        f = rule.findings[0]
        assert f["details"]["state"] == "expired"
        assert f["details"]["days_remaining"] < 0
        # os-risk/1.0: without a registered business mapping 'high' is
        # UNREACHABLE — the computed severity is honestly capped and
        # the derivation records the reason (§9)
        assert f["severity_label"] == "medium"
        derivation = str(f.get("risk_derivation", f))
        assert "business" in derivation.lower() or \
            f["risk_model_version"] == "os-risk/1.0"
        assert "never inferred" in str(f["limitations"])

    def test_near_expiration_window_is_30_days(self):
        rule = self._rule(
            [self._cert("Nov 10 11:04:38 2026 GMT")],
            as_of=date(2026, 10, 16))
        assert rule.findings[0]["details"]["state"] == "near_expiration"
        assert rule.findings[0]["details"]["days_remaining"] == 25

    def test_not_detected_is_never_absent(self):
        rule = self._rule([self._cert("Jun  4 11:04:38 2035 GMT")],
                          as_of=date(2026, 10, 16))
        assert rule.status == "evaluated"
        assert rule.findings == []
        assert "never 'absent'" in rule.evaluation_note

    def test_undated_certs_are_unknown_never_not_expired(self):
        rule = self._rule([self._cert("someday-ish")],
                          as_of=date(2026, 10, 16))
        assert rule.status == "not_evaluable"
        assert "UNKNOWN, never 'not expired'" in rule.evaluation_note

    def test_no_certs_never_all_valid(self):
        rule = self._rule([], as_of=date(2026, 10, 16))
        assert rule.status == "not_evaluable"
        assert "never 'all valid'" in rule.evaluation_note

    def test_certutil_locale_dates_parse(self):
        assert _parse_cert_date("4/1/2026 12:00 AM") == date(2026, 4, 1)

    def test_real_corpus_is_fine_at_fixed_date(self):
        certs = build_certificates(
            "certificate_metadata", REAL.read_text())
        rule = self._rule(certs, as_of=date(2026, 10, 16))
        assert rule.status == "evaluated"
        assert rule.findings == [], \
            "the real host roots are far from expiration in 2026"
