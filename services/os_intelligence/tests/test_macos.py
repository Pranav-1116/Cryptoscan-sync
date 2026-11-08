"""macOS adapter acceptance tests
(docs/os-kernel-intelligence/01_PRODUCT_SPEC.md §15 step 9).

PROVENANCE: fixtures RECONSTRUCTED from documented Apple output
formats (fixtures/macos/README.md) — NOT captured from a live macOS
host. Passing these tests is NOT macOS fleet qualification (§12).
Collection boundary: command outputs only — protected storage files
and keychain databases are never scraped.
"""

from __future__ import annotations

from pathlib import Path

from os_intelligence.macos import (collect_macos, parse_csrutil,
                                  parse_fdesetup, parse_kmutil,
                                  parse_spctl, parse_sw_vers,
                                  parse_uname)
from os_intelligence.rules import evaluate

MAC = Path(__file__).parent / "fixtures" / "macos"


def _read(name: str) -> str:
    return (MAC / name).read_text()


def _captured() -> dict:
    return {
        "sw_vers": _read("sw_vers.txt"),
        "uname": _read("uname.txt"),
        "csrutil": _read("csrutil.txt"),
        "spctl": _read("spctl.txt"),
        "fdesetup": _read("fdesetup.txt"),
        "kmutil": _read("kmutil.txt"),
    }


class TestProvenance:
    def test_fixture_provenance_is_labelled(self):
        readme = (MAC / "README.md").read_text()
        assert "RECONSTRUCTED" in readme
        assert "NOT captured from a live macOS host" in readme
        assert "never scraped" in readme

    def test_identity_carries_platform_and_boundary_notes(self):
        inv = collect_macos("mac-host", _captured())
        identity = inv["identity"]
        assert identity["platform"] == "macos"
        assert identity["environment_development_only"] is True
        assert any("never scraped" in n for n in identity["notes"])
        assert any("never guessed" in n for n in identity["notes"]) or \
            identity["kernel_release"] != "unknown"
        assert "never proof of runtime use" in inv["note"] or \
            "never proof of runtime use" in inv["note"]


class TestIdentity:
    def test_sw_vers_and_uname(self):
        fields = parse_sw_vers(_read("sw_vers.txt"))
        assert fields["os_pretty_name"] == "macOS"
        assert fields["os_version_id"] == "14.6.1"
        assert fields["build"] == "23G93"
        uname = parse_uname(_read("uname.txt"))
        assert uname["kernel_release"] == "23.6.0"
        assert uname["machine"] == "arm64"

    def test_missing_identity_never_guessed(self):
        inv = collect_macos("mac-host", {})
        assert inv["identity"]["kernel_release"] == "unknown"
        assert any("unknown, never guessed" in n
                   for n in inv["identity"]["notes"])


class TestStorageAndTrust:
    def test_filevault_on_is_established_metadata(self):
        fact, _ = parse_fdesetup(_read("fdesetup.txt"))
        assert fact.metadata["conversion_status"] == "Fully Encrypted"
        assert "no recovery key or password is collected" in fact.notes[0]

    def test_filevault_off_is_state_never_verdict(self):
        fact, _ = parse_fdesetup("FileVault is Off.")
        assert fact.metadata["conversion_status"] == "Fully Decrypted"
        assert "never a security verdict" in fact.notes[0]

    def test_fdesetup_error_is_unknown_never_guessed(self):
        fact, _ = parse_fdesetup("fdesetup: unexpected error")
        assert fact is None
        inv = collect_macos("mac-host", {"fdesetup": "garbage output"})
        storage = inv["storage"][0]
        assert storage["metadata"]["conversion_status"] == "unknown"
        assert "never guessed" in storage["notes"][0]

    def test_sip_state_is_configuration_never_trust_verdict(self):
        fact = parse_csrutil(_read("csrutil.txt"))
        assert fact.state == "enabled"
        assert "never a trust verdict" in fact.notes[0]

    def test_sip_unparseable_is_unavailable_never_disabled(self):
        fact = parse_csrutil("csrutil: command not found")
        assert fact.state == "unavailable"
        assert "NEVER as 'disabled'" in fact.notes[0]

    def test_gatekeeper_state(self):
        assert parse_spctl(_read("spctl.txt")).state == "enabled"
        unknown = parse_spctl("spctl: unrecognized option")
        assert unknown.state == "unavailable"

    def test_denied_sources_record_unavailable_facts(self):
        inv = collect_macos("mac-host", {
            "csrutil": {"error": "permission_denied"},
            "spctl": {"error": "permission_denied"}})
        subjects = {t["subject"]: t for t in inv["hardware_trust"]}
        assert subjects["sip"]["state"] == "unavailable"
        assert subjects["gatekeeper"]["state"] == "unavailable"
        for t in inv["hardware_trust"]:
            assert t["evidence_class"] == "unknown"
            assert any("NEVER as 'disabled'" in n for n in t["notes"])


class TestModulesAndCoverage:
    def test_kext_rows_parse_with_fail_safe(self):
        modules = parse_kmutil(_read("kmutil.txt"))
        assert {m.name for m in modules} == {
            "com.apple.iokit.IOHIDFamily", "com.apple.kec.corecrypto"}
        assert any("version: 13.0" in n for m in modules for n in m.notes)
        assert parse_kmutil("garbage without identifiers\n") == [], \
            "rows without identifiers are never fabricated"

    def test_crypto_inventory_unavailable_never_no_providers(self):
        inv = collect_macos("mac-host", _captured())
        assert inv["crypto_api"] == []
        cov = inv["coverage"]["sources_unavailable"]
        entry = [u for u in cov
                 if u["source"] == "crypto_provider_inventory"][0]
        assert "NEVER as 'no providers'" in entry["reason"]

    def test_missing_sources_recorded_never_zeros(self):
        inv = collect_macos("mac-host", {})
        cov = inv["coverage"]
        assert cov["sources_unavailable"]
        for entry in cov["sources_unavailable"]:
            assert entry["reason"]


class TestSharedCanonicalModel:
    def test_macos_inventory_feeds_the_shared_rules(self):
        """§15 step 4: one canonical model across Linux, Windows and
        macOS — with platform honesty in every rule."""
        inv = collect_macos("mac-host", _captured())
        report = evaluate(inv)
        by_id = {r.rule_id: r for r in report.results}
        assert len(report.results) == 18
        for rule_id in ("OS-CRYPTO-002", "OS-CRYPTO-014",
                        "OS-CRYPTO-016"):
            assert by_id[rule_id].status == "not_evaluable"
            assert "Linux-specific" in by_id[rule_id].evaluation_note
        # 007 recognizes FileVault On as an established layer
        rule007 = by_id["OS-CRYPTO-007"]
        assert rule007.status == "evaluated"
        assert rule007.findings == [], \
            "FileVault On is an ESTABLISHED encryption layer"
        # 009: trust subjects exist but no TPM — never 'no hardware trust'
        rule009 = by_id["OS-CRYPTO-009"]
        assert rule009.status == "not_evaluable"
        assert "never 'no hardware trust'" in rule009.evaluation_note
        assert "sip" in rule009.evaluation_note
        # 010: no secure_boot subject — SIP is a distinct claim
        rule010 = by_id["OS-CRYPTO-010"]
        assert rule010.status == "not_evaluable"
        assert "distinct claims" in rule010.evaluation_note
        assert "never reported as 'disabled'" in rule010.evaluation_note
        # every finding keeps the decisive field
        for r in report.results:
            for f in r.findings:
                assert f["runtime_usage_confirmed"] is False

    def test_010_secure_boot_fires_from_windows_facts(self):
        """OS-CRYPTO-010 evaluates the Windows-collected Secure Boot
        state: a disabled state is a detection, never a defect verdict."""
        inv = {
            "host_id": "h",
            "hardware_trust": [
                {"subject": "secure_boot", "state": "disabled",
                 "evidence_class": "observed", "metadata": {},
                 "notes": []}],
            "coverage": {"sources_collected": ["confirm_secureboot"]},
        }
        rule = [r for r in evaluate(inv).results
                if r.rule_id == "OS-CRYPTO-010"][0]
        assert rule.status == "evaluated"
        f = rule.findings[0]
        assert f["details"]["state"] == "disabled"
        assert "not a defect verdict" in str(f["limitations"])
        assert f["severity_label"] in ("medium", "high")
